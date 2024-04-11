#pragma once

#include <string>
#include <optional>
#include <sys/socket.h>

struct Host
{
	sockaddr address;
	std::string name;
	socklen_t address_len;

	Host() = default;
	~Host() = default;
	Host(const Host &) = default;
	Host(Host &&) = default;
	Host & operator=(const Host &) = default;
	Host & operator=(Host &&) = default;

	Host(const sockaddr &_address, const char *_name, socklen_t _address_len) noexcept;

	static std::optional<Host> ResolveHost(const char *host,
										   int hint_family,
										   int hint_socktype,
										   int hint_proto,
										   int hint_flags);

	static std::optional<Host> ResolveHost(const std::string &host,
										   int hint_family,
										   int hint_socktype,
										   int hint_proto,
										   int hint_flags);

	static const char * GetStringAddress(const sockaddr &addr);
	const char * GetStringAddress() const;
	bool IsSame(const sockaddr *addr, socklen_t addr_len) const noexcept;
};

struct HostName
{
	constexpr static std::size_t HOST_NAME_SIZE = 128;
	constexpr static std::size_t SERVER_NAME_SIZE = HOST_NAME_SIZE;
	char host[HOST_NAME_SIZE];
	char server[SERVER_NAME_SIZE];

	~HostName() = default;
	HostName(const HostName &) = default;
	HostName(HostName &&) = default;
	HostName & operator=(const HostName &) = default;
	HostName & operator=(HostName &&) = default;

	HostName() noexcept;

	static std::optional<HostName> ResolveAddress(const sockaddr *addr, socklen_t len) noexcept;

	bool IsHostEmpty() const noexcept;
	bool IsServerEmpty() const noexcept;
};

