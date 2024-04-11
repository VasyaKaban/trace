#include "Host.h"
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>

Host::Host(const sockaddr &_address, const char *_name, socklen_t _address_len) noexcept
	: address(_address),
	  name(_name),
	  address_len(_address_len) {}

std::optional<Host> Host::ResolveHost(const char *host,
									  int hint_family,
									  int hint_socktype,
									  int hint_proto,
									  int hint_flags)
{
	addrinfo *addrinfo_result;
	addrinfo hints;
	std::memset(&hints, 0x0, sizeof(addrinfo));
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


std::optional<Host> Host::ResolveHost(const std::string &host,
									  int hint_family,
									  int hint_socktype,
									  int hint_proto,
									  int hint_flags)
{
	return ResolveHost(host.c_str(), hint_family, hint_socktype, hint_proto, hint_flags);
}

const char * Host::GetStringAddress(const sockaddr &addr)
{
	return inet_ntoa(reinterpret_cast<const sockaddr_in *>(&addr)->sin_addr);
}

const char * Host::GetStringAddress() const
{
	return GetStringAddress(address);
}

bool Host::IsSame(const sockaddr *addr, socklen_t addr_len) const noexcept
{
	if(address_len == addr_len)
		return std::memcmp(&address, addr, addr_len) == 0;

	return false;
}

HostName::HostName() noexcept
{
	std::fill_n(host, HOST_NAME_SIZE, '\0');
	std::fill_n(server, SERVER_NAME_SIZE,'\0');
}

std::optional<HostName> HostName::ResolveAddress(const sockaddr *addr, socklen_t len) noexcept
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

bool HostName::IsHostEmpty() const noexcept
{
	return host[0] == '\0';
}

bool HostName::IsServerEmpty() const noexcept
{
	return server[0] == '\0';
}
