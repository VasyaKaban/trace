#include "Trace.h"
#include <netinet/ip.h>
#include <netdb.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include "Socket.h"
#include "Host.h"
#include "ICMPEchoRequest.h"
#include "ICMPResponse.h"
#include "Sample.h"

constexpr inline std::size_t PacketDataSize = 8;
using ICMPEchoRequestType = ICMPEchoRequest<PacketDataSize>;
using ICMPResponseType = ICMPResponse<PacketDataSize>;

TraceResult Trace(const std::string &host_name, int hops, int samples, timeval timeout, std::ostream &out)
{
	auto host_opt = Host::ResolveHost(host_name,
									  AF_INET,
									  SOCK_RAW,
									  IPPROTO_ICMP,
									  AI_CANONNAME);

	if(!host_opt)
		return TraceResult::UnresolvedHost;

	Host &host = *host_opt;
	out<<"Goal host name: "<<host.name<<"\tip: "<<host.GetStringAddress()<<std::endl;

	Socket sender;
	int sender_open_res = sender.Open(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sender_open_res != 0)
	{
		out<<strerror(sender_open_res)<<std::endl;
		return TraceResult::Errno;
	}

	Socket receiver;
	int receiver_open_res = receiver.Open(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(receiver_open_res != 0)
	{
		out<<strerror(errno)<<std::endl;
		return TraceResult::Errno;
	}

	sockaddr_in local;
	std::memset(&local, 0, sizeof(local));
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(33499);
	local.sin_family = AF_INET;
	int bind_res = receiver.Bind(reinterpret_cast<const sockaddr *>(&local), sizeof(local));
	if(bind_res != 0)
	{
		out<<strerror(errno)<<std::endl;
		return TraceResult::Errno;
	}

	int target_hops = 1;
	int recv_timeout_res = receiver.SetReceiveTimeout(timeout);
	if(recv_timeout_res < 0)
	{
		out<<strerror(errno)<<std::endl;
		return TraceResult::Errno;
	}

	sockaddr recv_addr;
	socklen_t recv_addr_len;

	std::uint64_t request_data = 0;
	ICMPResponseType response;

	icmphdr hdr;
	hdr.type = ICMP_ECHO;
	hdr.code = 0;
	hdr.un.echo.id = htons(12345);
	hdr.un.echo.sequence = htons(12345);
	ICMPEchoRequestType request(hdr, 2028);

	std::vector<Sample> result_samples;
	result_samples.resize(samples);

	while(target_hops <= hops)
	{
		int ttl_set_res = sender.SetTTL(target_hops);
		if(ttl_set_res < 0)
		{
			out<<strerror(errno)<<std::endl;
			return TraceResult::Errno;
		}

		int i = 0;
		std::fill_n(result_samples.begin(), samples, Sample{});
		for(; i < samples; i++)
		{
			request.header.un.echo.sequence = htons((ntohs(request.header.un.echo.sequence) + 1));
			request.RecalculateChecksum();

			int send_res = sender.SentTo(&request,
										 sizeof(request),
										 0,
										 &host.address,
										 host.address_len);

			if(send_res < 0)
			{
				out<<strerror(errno)<<std::endl;
				return TraceResult::Errno;
			}

			auto read_time_start  = std::chrono::system_clock::now();

			int read_res = receiver.RecvFrom(&response,
											 sizeof(response),
											 0,
											 &recv_addr,
											 &recv_addr_len);

			if(read_res < 0)
				continue;

			auto read_delta =
				std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() -
																	  read_time_start);

			//if(!header.SamePacket(packet))
			//	continue;

			if(!(response.SameType(ICMP_TIME_EXCEEDED) || response.SameType(ICMP_ECHOREPLY)))
				continue;

			result_samples[i] = Sample(&recv_addr, recv_addr_len, read_delta);
		}

		out<<"Hop: "<<target_hops<<"\t";

		char *ip = nullptr;
		std::optional<HostName> remote_host_opt;
		for(const auto &sample_result : result_samples)
		{
			if(sample_result.address.sa_family == AF_UNSPEC)
				continue;

			if(ip == nullptr)
				ip = inet_ntoa(reinterpret_cast<const sockaddr_in *>(&sample_result.address)->sin_addr);

			auto host_name_opt = HostName::ResolveAddress(&sample_result.address, sample_result.address_len);
			if(!remote_host_opt && host_name_opt)
				remote_host_opt = host_name_opt;
		}

		if(ip)
			out<<"ip: "<<ip<<"\t";
		else
			out<<"ip: UNRESOLVED_IP\t";

		if(remote_host_opt)
		{
			if(!remote_host_opt->IsHostEmpty())
				out<<"host: "<<remote_host_opt->host<<"\t";
			else
				out<<"host: UNRESOLVED_HOST\t";

			if(!remote_host_opt->IsServerEmpty())
				out<<"server: "<<remote_host_opt->server<<"\t";
			else
				out<<"server: UNRESOLVED_SERVER\t";
		}
		else
			out<<"host: UNRESOLVED_HOST\tserver: UNRESOLVED_SERVER\t";

		out<<"time: ";
		for(const auto &sample_result : result_samples)
		{
			if(sample_result.read_time != std::chrono::milliseconds(0))
				out<<sample_result.read_time<<" ";
			else
				out<<"* ";
		}
		out<<std::endl;

		if(host.IsSame(&recv_addr, recv_addr_len))
			break;

		target_hops++;
	}

	return TraceResult::Success;
}
