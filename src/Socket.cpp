#include "Socket.h"

Socket::~Socket()
{
	Close();
}

Socket::Socket(Socket &&s) noexcept
	: sock(std::exchange(s.sock, 0)) {}

Socket & Socket::operator=(Socket &&s) noexcept
{
	Close();

	sock = std::exchange(s.sock, 0);

	return *this;
}

int Socket::Open(int family, int type, int proto) noexcept
{
	Close();

	int _sock = socket(family, type, proto);
	if(_sock < 0)
		return errno;

	sock = _sock;
	return 0;
}

void Socket::Close() noexcept
{
	if(sock != 0)
	{
		close(sock);
		sock = 0;
	}
}

int Socket::SetReceiveTimeout(const timeval &t) noexcept
{
	return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
}

int Socket::SetTTL(int ttl) noexcept
{
	return setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

int Socket::GetNativeHandle() const noexcept
{
	return sock;
}

int Socket::Bind(const sockaddr *address, socklen_t address_length) noexcept
{
	return bind(sock, address, address_length);
}

int Socket::SentTo(const void *data,
		   std::size_t size,
		   int flags,
		   const sockaddr *address,
		   socklen_t address_length) noexcept
{
	return sendto(sock, data, size, flags, address, address_length);
}

int Socket::RecvFrom(void *data,
					std::size_t size,
					int flags,
					sockaddr *address,
					socklen_t *address_length) noexcept
{
	return recvfrom(sock, data, size, flags, address, address_length);
}
