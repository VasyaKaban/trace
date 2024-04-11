#pragma once

#include <utility>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>

class Socket
{
public:
	Socket() = default;
	~Socket();
	Socket(const Socket &) = delete;
	Socket(Socket &&s) noexcept;
	Socket & operator=(const Socket &) = delete;
	Socket & operator=(Socket &&s) noexcept;

	int Open(int family, int type, int proto) noexcept;

	void Close() noexcept;

	int SetReceiveTimeout(const timeval &t) noexcept;

	int SetTTL(int ttl) noexcept;

	int GetNativeHandle() const noexcept;

	int Bind(const sockaddr *address, socklen_t address_length) noexcept;

	int SentTo(const void *data,
			   std::size_t size,
			   int flags,
			   const sockaddr *address,
			   socklen_t address_length) noexcept;

	int RecvFrom(void *data,
				 std::size_t size,
				 int flags,
				 sockaddr *address,
				 socklen_t *address_length) noexcept;

private:
	int sock;
};
