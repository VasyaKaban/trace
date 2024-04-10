#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <algorithm>
#include <optional>
#include <utility>
#include <cassert>

template<std::size_t N>
struct ICMPPacket
{
	icmphdr header;
	std::byte data[N];

	ICMPPacket() = default;

	template<typename T>
	ICMPPacket(const icmphdr &_header, const T *ptr, std::size_t size) noexcept
	{
		header = _header;
		std::size_t copy_size = std::min(size, N);
		std::memcpy(data, ptr, copy_size);
		RecalculateChecksum();
	}

	template<typename T>
	ICMPPacket(const icmphdr &_header, const T &_data) noexcept
	{
		header = _header;
		std::size_t copy_size = std::min(sizeof(T), N);
		std::memcpy(data, reinterpret_cast<const void *>(&_data), copy_size);
		RecalculateChecksum();
	}

	template<typename T>
	ICMPPacket & operator=(const T &_data) noexcept
	{
		std::size_t copy_size = std::min(sizeof(T), N);
		std::memcpy(data, reinterpret_cast<const void *>(&_data), copy_size);
		RecalculateChecksum();
		return *this;
	}

	static ushort checksum(void *b, int len)
	{
		ushort *buf = reinterpret_cast<ushort *>(b);
		uint sum=0;
		ushort result;

		for (sum = 0; len > 1; len -= 2) {
			sum += *buf++;
		}
		if (len == 1) {
			sum += *(unsigned char*)buf;
		}
		sum = (sum >> 16) + (sum & 0xFFFF);
		sum += (sum >> 16);
		result = ~sum;
		return result;
	}

	void RecalculateChecksum() noexcept
	{
		header.checksum = 0;
		assert(sizeof(ICMPPacket) % 2 == 0);
		std::uint64_t sum = 0;
		const std::uint16_t *repr = std::launder(reinterpret_cast<const std::uint16_t *>(this));
		for(std::size_t i = 0; i < sizeof(ICMPPacket) / 2; i++)
		{
			std::uint16_t target_sum = *(repr + i);
			sum += target_sum;
			std::uint64_t carry = sum >> 16;
			sum = (sum & 0xFFFF) + carry;
		}

		auto csum = checksum(this, sizeof(*this));
		header.checksum = ~sum;
		//header.checksum = htons((~sum) & 0xFFFF);

	}

	bool IsSameEcho(const ICMPPacket &packet) const noexcept
	{
		return
			header.type == packet.header.type &&
			header.code == packet.header.code &&
			header.checksum == packet.header.checksum &&
			header.un.echo.id == packet.header.un.echo.id &&
			header.un.echo.sequence == packet.header.un.echo.sequence;
	}
};

struct Host
{
	sockaddr address;
	std::string name;
	socklen_t address_len;

	Host(const sockaddr &_address, const char *_name, socklen_t _address_len) noexcept
		: address(_address),
		  name(_name),
		  address_len(_address_len) {}

	static std::optional<Host>
	ResolveHost(const char *host,
				int hint_family,
				int hint_socktype,
				int hint_proto,
				int hint_flags) noexcept
	{
		addrinfo *addrinfo_result;
		addrinfo hints;
		std::memset(&hints, '\0', sizeof(addrinfo));
		hints.ai_family = hint_family;
		hints.ai_socktype = hint_socktype;
		hints.ai_protocol = hint_proto;
		hints.ai_flags = hint_flags;
		int error = getaddrinfo(host, nullptr, &hints, &addrinfo_result);
		if(error != 0)
			return {};

		if(addrinfo_result == nullptr)
			return {};

		Host out_host(*addrinfo_result->ai_addr,
					  (addrinfo_result->ai_canonname ? addrinfo_result->ai_canonname : ""),
					  addrinfo_result->ai_addrlen);

		freeaddrinfo(addrinfo_result);
		return out_host;
	}

	struct HostName
	{
		constexpr static std::size_t HOST_NAME_SIZE = 128;
		constexpr static std::size_t SERVER_NAME_SIZE = HOST_NAME_SIZE;
		char host[HOST_NAME_SIZE];
		char server[SERVER_NAME_SIZE];

		constexpr HostName() noexcept
		{
			std::fill_n(host, HOST_NAME_SIZE, '\0');
			std::fill_n(server, SERVER_NAME_SIZE,'\0');
		}

		constexpr bool IsHostEmpty() const noexcept
		{
			return host[0] == '\0';
		}

		constexpr bool IsServerEmpty() const noexcept
		{
			return server[0] == '\0';
		}
	};

	static std::optional<HostName> ResolveAddress(const sockaddr *addr, socklen_t len) noexcept
	{
		HostName host_name;
		int res = getnameinfo(addr,
							  len,
							  host_name.host,
							  HostName::HOST_NAME_SIZE,
							  host_name.server,
							  HostName::SERVER_NAME_SIZE,
							  0);

		if(res != 0)
			return {};

		return host_name;
	}

	static const char * GetStringAddress(const sockaddr &addr)
	{
		return inet_ntoa(reinterpret_cast<const sockaddr_in *>(&addr)->sin_addr);
	}

	const char * GetStringAddress() const
	{
		return GetStringAddress(address);
	}

	bool IsSame(const sockaddr *addr, socklen_t addr_len) const noexcept
	{
		if(address_len == addr_len)
			return std::memcmp(&address, addr, addr_len) == 0;

		return false;
	}
};

void ExitOnBadCondition(bool true_cond)
{
	if(true_cond)
		return;

	if(errno != 0)
		std::cerr<<"Error: "<<strerror(errno)<<std::endl;
	else
		std::cerr<<"Unresolved error!"<<std::endl;
	exit(errno);
}

class Socket
{
public:
	Socket() = default;

	~Socket()
	{
		Close();
	}

	Socket(const Socket &) = delete;
	Socket(Socket &&s) noexcept : sock(std::exchange(s.sock, 0)) {}
	Socket & operator=(const Socket &) = delete;
	Socket & operator=(Socket &&s) noexcept
	{
		Close();

		sock = std::exchange(s.sock, 0);

		return *this;
	}

	int Open(int family, int type, int proto) noexcept
	{
		Close();

		int _sock = socket(family, type, proto);
		if(_sock < 0)
			return errno;

		sock = _sock;
		return 0;
	}

	void Close() noexcept
	{
		if(sock != 0)
		{
			close(sock);
			sock = 0;
		}
	}

	int SetReceiveTimeout(const timeval &t) noexcept
	{
		return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
	}

	int SetSendTimeout(const timeval &t) noexcept
	{
		return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
	}

	int SetIpHeaderIncludance() noexcept
	{
		int val = 1;
		return setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));
	}

	int SetTTL(int ttl) noexcept
	{
		return setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	}

	int Bind(const sockaddr *addr, socklen_t len) noexcept
	{
		return bind(sock, addr, len);
	}

	int GetFD() const noexcept
	{
		return sock;
	}


private:
	int sock;
};

constexpr std::size_t PacketDataSize = 8;

using ICMPPacketType = ICMPPacket<PacketDataSize>;

struct icmp_echo_reply
{
	std::uint16_t id;
	std::uint16_t seq;

	std::byte data[PacketDataSize];
};

struct icmp_ttl_with_options
{
	std::byte unused[4];
	ip ip_header;
	std::byte options[4];
	std::byte data[8];
};

struct icmp_ttl_without_options
{
	std::byte unused[4];
	ip ip_header;
	std::byte data[8];
};

struct icmp_responses
{
	std::uint8_t type;
	std::uint8_t code;
	std::uint16_t checksum;

	union
	{
		icmp_echo_reply echo_reply;
		icmp_ttl_with_options ttl_with_options;
		icmp_ttl_without_options ttl_without_options;
	} responses;
};

/*struct header_with_options
{
	std::byte options[4];
	icmp_responses icmp;
};*/

struct HEADER
{
	ip ip_header;

	union
	{
		union
		{
			std::byte options[4];
			icmp_responses icmp;
		} header_with_opts;

		icmp_responses icmp;
	} data;


	/*std::uint32_t ip_header_top_options;

	std::uint8_t type;
	std::uint8_t code;
	std::uint16_t checksum;

	std::uint16_t id;
	std::uint16_t seq;
	//std::uint32_t unused;

	ip ip_header_post;
	std::uint32_t ip_header_post_options;

	std::uint64_t data;*/
};

int main(int argc, char **argv)
{
	const int tries_per_hop = 3;
	auto host_opt = Host::ResolveHost("www.google.com",
									  AF_INET,
									  SOCK_RAW,
									  IPPROTO_ICMP,
									  AI_CANONNAME);


	ExitOnBadCondition(host_opt.has_value());
	Host &host = *host_opt;
	std::cout<<"Goal host name: "<<host.name<<"\tip: "<<host.GetStringAddress()<<std::endl;

	Socket sender;
	int sender_open_res = sender.Open(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sender_open_res != 0)
	{
		std::cout<<strerror(sender_open_res)<<std::endl;
		return sender_open_res;
	}

	Socket receiver;
	int receiver_open_res = receiver.Open(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(receiver_open_res != 0)
	{
		std::cout<<strerror(errno)<<std::endl;
		return errno;
	}

	sockaddr_in local;
	std::memset(&local, 0, sizeof(local));
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(33499);
	local.sin_family = AF_INET;
	int bind_res = receiver.Bind(reinterpret_cast<const sockaddr *>(&local), sizeof(local));
	if(bind_res != 0)
	{
		std::cout<<strerror(errno)<<std::endl;
		return errno;
	}

	int max_hops = 128;
	int target_hops = 1;

	timeval timeout{.tv_sec = 1, .tv_usec = 0};
	int recv_timeout_res = receiver.SetReceiveTimeout(timeout);
	if(recv_timeout_res < 0)
	{
		std::cout<<strerror(errno)<<std::endl;
		return EXIT_FAILURE;
	}

	/*int ip_hdr_res = receiver.SetIpHeaderIncludance();
	if(ip_hdr_res < 0)
	{
		std::cout<<strerror(errno)<<std::endl;
		return EXIT_FAILURE;
	}*/

	icmphdr h;

	ICMPPacketType response;
	sockaddr recv_addr;
	socklen_t recv_addr_len;

	std::uint64_t request_data = 0;
	HEADER header;

	icmphdr hdr;
	hdr.type = ICMP_ECHO;
	hdr.code = 0;
	hdr.un.echo.id = htons(12345);
	hdr.un.echo.sequence = htons(12345);
	ICMPPacketType packet(hdr, 2028);

	while(target_hops <= max_hops)
	{
		int ttl_set_res = sender.SetTTL(target_hops);
		if(ttl_set_res < 0)
		{
			std::cout<<strerror(errno)<<std::endl;
			return EXIT_FAILURE;
		}

		std::string recognized_ip;
		int i = 0;
		for(; i < tries_per_hop; i++)
		{
			packet.header.un.echo.sequence = htons((ntohs(packet.header.un.echo.sequence) + 1));
			packet.RecalculateChecksum();
			//request_data++;

			int send_res = sendto(sender.GetFD(),
								  &packet,
								  sizeof(packet),
								  0,
								  &host.address,
								  host.address_len);
			if(send_res < 0)
			{
				std::cout<<strerror(errno)<<std::endl;
				return EXIT_FAILURE;
			}

			int read_res = recvfrom(receiver.GetFD(),
									&header,
									sizeof(header),
									0,
									&recv_addr,
									&recv_addr_len);

			if(read_res < 0)
			{
				std::cout<<strerror(errno)<<std::endl;
				continue;
			}




			if(header.ip_header.ip_hl > 5)//with options
			{
				std::cout<<"Header with options!"<<std::endl;
				if(header.data.header_with_opts.icmp.type == ICMP_ECHOREPLY)
				{
					std::cout<<"ICMP_ECHOREPLY!"<<std::endl;
					std::cout<<"Id: "<<ntohs(header.data.header_with_opts.icmp.responses.echo_reply.id)<<std::endl;
					std::cout<<"Seq: "<<ntohs(header.data.header_with_opts.icmp.responses.echo_reply.seq)<<std::endl;
				}
				else if(header.data.header_with_opts.icmp.type == ICMP_TIME_EXCEEDED)
				{
					std::cout<<"ICMP_TIME_EXCEEDED!"<<std::endl;
				}
				else
				{
					std::cout<<"ICMP_UNDEFINED!"<<std::endl;
				}
			}
			else
			{
				std::cout<<"Header without options!"<<std::endl;
				if(header.data.icmp.type == ICMP_ECHOREPLY)
				{
					std::cout<<"ICMP_ECHOREPLY!"<<std::endl;
					std::cout<<"Id: "<<header.data.icmp.responses.echo_reply.id<<std::endl;
					std::cout<<"Seq: "<<header.data.icmp.responses.echo_reply.seq<<std::endl;
					std::cout<<"Data: "<<*reinterpret_cast<std::uint64_t*>(header.data.icmp.responses.echo_reply.data)<<std::endl;
				}
				else if(header.data.icmp.type == ICMP_TIME_EXCEEDED)
				{
					std::cout<<"ICMP_TIME_EXCEEDED!"<<std::endl;
					bool same = !std::memcmp(header.data.icmp.responses.ttl_without_options.data,
											 &packet.header,
											 64);
					std::cout<<std::boolalpha<<same<<std::endl;
				}
				else
				{
					std::cout<<"ICMP_UNDEFINED!"<<std::endl;
				}
			}

			char *ip = inet_ntoa(reinterpret_cast<sockaddr_in *>(&recv_addr)->sin_addr);
			recognized_ip = ip;
			break;
		}

		std::cout<<"Hop: "<<target_hops<<"\t";

		if(i == 3)
			std::cout<<"* * *"<<std::endl;
		else
		{
			if(!recognized_ip.empty())
				std::cout<<"ip: "<<recognized_ip<<"\t";
			else
				std::cout<<"ip: UNRESOLVED_IP\t";

			auto host_name_opt = Host::ResolveAddress(&recv_addr, recv_addr_len);
			if(host_name_opt)
			{
				if(!host_name_opt->IsHostEmpty())
					std::cout<<"host: "<<host_name_opt->host<<"\t";
				else
					std::cout<<"host: UNRESOLVED_HOST\t";

				if(!host_name_opt->IsServerEmpty())
					std::cout<<"server: "<<host_name_opt->server<<"\t";
				else
					std::cout<<"server: UNRESOLVED_SERVER\t";
			}
			else
				std::cout<<"host: UNRESOLVED_HOST\tserver: UNRESOLVED_SERVER\t";

			if(i != 0)
			{
				for(int j = 0; j < i; j++)
					std::cout<<"* ";
			}
		}

		std::cout<<std::endl;

		/*if(recognized_ip.empty())
			std::cout<<"Hop: "<<target_hops<<"\t* * *"<<std::endl;
		else
		{
			std::cout<<"Hop: "<<target_hops<<"\t";
			auto host_name_opt = Host::ResolveAddress(&recv_addr, recv_addr_len);
			if(host_name_opt)
				std::cout<<"host: "<<host_name_opt->host<<"\tserver: "<<host_name_opt->server<<"\t";

			std::cout<<recognized_ip;
			if(i != 0)
			{
				std::cout<<"\t";
				for(int j = 0; j < i; j++)
					std::cout<<" *";
			}

			std::cout<<std::endl;
		}*/

		//if(header.type == ICMP_EXC_TTL)//???
		//	break;

		if(host.IsSame(&recv_addr, recv_addr_len))
			break;

		target_hops++;
	}
}
