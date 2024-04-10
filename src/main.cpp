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
#include <chrono>

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

	/*static ushort checksum(void *b, int len)
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
	}*/

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
				int hint_flags)
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

	static std::optional<Host>
	ResolveHost(const std::string &host,
				int hint_family,
				int hint_socktype,
				int hint_proto,
				int hint_flags)
	{
		return ResolveHost(host.data(), hint_family, hint_socktype, hint_proto, hint_flags);
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

	template<std::size_t N>
	bool SamePacket(const ICMPPacket<N> &pack) noexcept
	{
		if(ip_header.ip_hl > 5)//with options
		{
			if(data.header_with_opts.icmp.type == 8)//ECHO_REPLY
			{
				return
					data.header_with_opts.icmp.responses.echo_reply.id == pack.header.un.echo.id &&
					data.header_with_opts.icmp.responses.echo_reply.seq == pack.header.un.echo.sequence;
			}
			else if(data.header_with_opts.icmp.type == 11)//TTL_TIMEOUT
			{
				return !std::memcmp(&data.header_with_opts.icmp.responses.ttl_with_options.data,
									&pack,
									8);
			}
			else
			{
				std::cout<<"Unexpected icmp type: "<<data.header_with_opts.icmp.type<<std::endl;
				return false;
			}
		}
		else//without options
		{
			if(data.icmp.type == 8)//ECHO_REPLY
			{
				return
					data.icmp.responses.echo_reply.id == pack.header.un.echo.id &&
					data.icmp.responses.echo_reply.seq == pack.header.un.echo.sequence;
			}
			else if(data.icmp.type == 11)//TTL_TIMEOUT
			{
				return !std::memcmp(&data.icmp.responses.ttl_without_options.data,
									&pack,
									8);
			}
			else
			{
				std::cout<<"Unexpected icmp type: "<<data.icmp.type<<std::endl;
				return false;
			}
		}
	}

	bool SameType(std::uint8_t type) const noexcept
	{
		if(ip_header.ip_hl > 5)
			return data.header_with_opts.icmp.type == type;

		return data.icmp.type == type;
	}

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

struct ReadResult
{
	sockaddr address;
	socklen_t address_len;
	std::chrono::milliseconds read_time;

	ReadResult() = default;

	ReadResult(const sockaddr *_address,
			   socklen_t _address_len,
			   std::chrono::milliseconds _read_time) noexcept
		: address_len(_address_len),
		  read_time(_read_time)
	{
		std::memcpy(&address, _address, _address_len);
	}

	ReadResult(const ReadResult &) = default;
	ReadResult(ReadResult &&) = default;
	ReadResult & operator=(const ReadResult &) = default;
	ReadResult & operator=(ReadResult &&) = default;
};

struct TraceConfig
{
	std::string host;
	int hops = 30;
	int samples = 3;

	TraceConfig() = default;

	constexpr TraceConfig(std::string_view _host, int _hops, int _samples) noexcept
		: host(_host),
		  hops(_hops),
		  samples(_samples) {}

	static TraceConfig Create(int argc, char **argv)
	{
		if(argc == 1)
			PrintHelpAndExit();

		TraceConfig config;
		for(int i = 1; i < argc; i++)
		{
			std::string_view argv_view(argv[i], std::strlen(argv[i]));
			if(argv_view == "--help")
			{
				PrintHelpAndExit();
			}
			else if(argv_view.starts_with("--host="))
			{
				auto host_value = SplitArgumentWithAssignment(argv_view);
				if(host_value.empty())
				{
					std::cout<<"No passed host!"<<std::endl;
					exit(EXIT_FAILURE);
				}

				config.host = host_value;
			}
			else if(argv_view.starts_with("--hops="))
			{
				config.hops = ParseNonZeroInt(argv_view, "hops");
			}
			else if(argv_view.starts_with("--samples="))
			{
				config.samples = ParseNonZeroInt(argv_view, "samples");
			}
			else
			{
				std::cout<<"Undefined argument: "<<argv_view<<std::endl;
				exit(EXIT_FAILURE);
			}
		}

		return config;
	}

private:
	[[noreturn]] static void PrintHelpAndExit()
	{
		std::cout<<"usage: trace [--hops=$value(>0)] [--samples=$value(>0)] --host=$host_name"<<"\n";
		std::cout<<"Flags:\n";
		std::cout<<"--help -> show usage infromation\n";
		std::cout<<"--host -> sets the host name which route we want to explore\n";
		std::cout<<"--hops -> sets the maximum TTL hops for socket."
					 " This value must be greater then zero\n";
		std::cout<<"--samples -> sets the maximum samples per hop."
					 " Each sample is a send/receive iteration with remote host information collection"
					 " and timer measurements!"
					 " This value must be greater than zero\n";
		exit(EXIT_SUCCESS);
	}

	static bool FromCharsResultGood(const std::from_chars_result &res, const char *end) noexcept
	{
		return (res.ec == std::errc(0) && res.ptr == end);
	}

	static int ParseNonZeroInt(std::string_view arg, const char *arg_name)
	{
		auto arg_value = SplitArgumentWithAssignment(arg);
		if(arg_value.empty())
		{
			std::cout<<"No passed "<<arg_name<<"!"<<std::endl;
			exit(EXIT_FAILURE);
		}

		int value = 0;
		auto end = arg_value.data() + arg_value.size();
		auto res = std::from_chars(arg_value.data(), end, value);
		int is_good = FromCharsResultGood(res, end);
		if(!is_good)
		{
			std::cout<<"Bad "<<arg_name<<" value!"<<std::endl;
			exit(EXIT_FAILURE);
		}

		if(value <= 0)
		{
			std::cout<<arg_name<<" value must be greater than zero!"<<std::endl;
			exit(EXIT_FAILURE);
		}

		return value;
	}

	static std::string_view SplitArgumentWithAssignment(std::string_view arg) noexcept
	{
		auto assignment_pos = arg.find("=");
		if(assignment_pos == std::string_view::npos)
			return {};

		return std::string_view(arg.begin() + assignment_pos + 1, arg.end());
	}
};

int main(int argc, char **argv)
{
	auto config = TraceConfig::Create(argc, argv);
	auto host_opt = Host::ResolveHost(config.host,
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

	std::vector<ReadResult> read_results;
	read_results.resize(config.samples);

	while(target_hops <= config.hops)
	{
		int ttl_set_res = sender.SetTTL(target_hops);
		if(ttl_set_res < 0)
		{
			std::cout<<strerror(errno)<<std::endl;
			return EXIT_FAILURE;
		}

		int i = 0;
		std::fill_n(read_results.begin(), config.samples, ReadResult{});
		//std::array<ReadResult, tries_per_hop> read_results = {};
		for(; i < config.samples; i++)
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

			auto read_time_start  = std::chrono::system_clock::now();

			int read_res = recvfrom(receiver.GetFD(),
									&header,
									sizeof(header),
									0,
									&recv_addr,
									&recv_addr_len);

			if(read_res < 0)
			{
				//std::cout<<strerror(errno)<<std::endl;
				continue;
			}

			auto read_delta =
				std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() -
																					read_time_start);

			//if(!header.SamePacket(packet))
			//	continue;

			if(!(header.SameType(ICMP_TIME_EXCEEDED) || header.SameType(ICMP_ECHOREPLY)))
				continue;

			read_results[i] = ReadResult(&recv_addr, recv_addr_len, read_delta);
		}

		std::cout<<"Hop: "<<target_hops<<"\t";

		char *ip = nullptr;
		std::optional<Host::HostName> remote_host_opt;
		for(const auto &read_res : read_results)
		{
			if(read_res.address.sa_family == AF_UNSPEC)
				continue;

			if(ip == nullptr)
				ip = inet_ntoa(reinterpret_cast<const sockaddr_in *>(&read_res.address)->sin_addr);

			auto host_name_opt = Host::ResolveAddress(&read_res.address, read_res.address_len);
			if(!remote_host_opt && host_name_opt)
				remote_host_opt = host_name_opt;
		}

		if(ip)
			std::cout<<"ip: "<<ip<<"\t";
		else
			std::cout<<"ip: UNRESOLVED_IP\t";

		if(remote_host_opt)
		{
			if(!remote_host_opt->IsHostEmpty())
				std::cout<<"host: "<<remote_host_opt->host<<"\t";
			else
				std::cout<<"host: UNRESOLVED_HOST\t";

			if(!remote_host_opt->IsServerEmpty())
				std::cout<<"server: "<<remote_host_opt->server<<"\t";
			else
				std::cout<<"server: UNRESOLVED_SERVER\t";
		}
		else
			std::cout<<"host: UNRESOLVED_HOST\tserver: UNRESOLVED_SERVER\t";

		std::cout<<"time: ";
		for(const auto &read_res : read_results)
		{
			if(read_res.read_time != std::chrono::milliseconds(0))
				std::cout<<read_res.read_time<<" ";
			else
				std::cout<<"* ";
		}
		std::cout<<std::endl;


		/*{
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

			std::cout<<"time: ";
			for(const auto time : tries_read_time)
				std::cout<<time<<" ";
			std::cout<<"\t";

			if(i != 0)
			{
				for(int j = 0; j < i; j++)
					std::cout<<"* ";
			}

			std::cout<<std::endl;
		}*/

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
