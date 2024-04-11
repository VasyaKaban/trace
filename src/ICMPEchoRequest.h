#pragma once

#include <cstdlib>
#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <netinet/ip_icmp.h>

template<std::size_t N>
struct ICMPEchoRequest
{
	icmphdr header;
	std::byte data[N];

	ICMPEchoRequest() = default;
	~ICMPEchoRequest() = default;
	ICMPEchoRequest(const ICMPEchoRequest &) = default;
	ICMPEchoRequest(ICMPEchoRequest &&) = default;
	ICMPEchoRequest & operator=(const ICMPEchoRequest &) = default;
	ICMPEchoRequest & operator=(ICMPEchoRequest &&) = default;

	template<typename T>
	ICMPEchoRequest(const icmphdr &_header, const T *ptr, std::size_t size) noexcept
	{
		header = _header;
		std::size_t copy_size = std::min(size, N);
		std::copy_n(ptr, copy_size, data);
		RecalculateChecksum();
	}

	template<typename T>
	ICMPEchoRequest(const icmphdr &_header, const T &_data) noexcept
	{
		header = _header;
		std::size_t copy_size = std::min(sizeof(T), N);
		std::copy_n(reinterpret_cast<const std::byte *>(&_data), copy_size, data);
		RecalculateChecksum();
	}

	template<typename T>
	ICMPEchoRequest & operator=(const T &_data) noexcept
	{
		std::size_t copy_size = std::min(sizeof(T), N);
		std::copy_n(reinterpret_cast<const std::byte *>(&_data), copy_size, data);
		RecalculateChecksum();
		return *this;
	}

	void RecalculateChecksum() noexcept
	{
		header.checksum = 0;
		std::uint64_t sum = 0;
		const std::uint16_t *repr = std::launder(reinterpret_cast<const std::uint16_t *>(this));
		for(std::size_t i = 0; i < sizeof(ICMPEchoRequest) / 2; i++)
		{
			std::uint16_t target_sum = *(repr + i);
			sum += target_sum;
			std::uint64_t carry = sum >> 16;
			sum = (sum & 0xFFFF) + carry;
		}

		if(N % 2 == 1)
			sum += *(std::launder(reinterpret_cast<const std::uint8_t *>(this)) + sizeof(ICMPEchoRequest) - 1);

		header.checksum = ~sum;
		//header.checksum = htons((~sum) & 0xFFFF);

	}

	bool IsSameEcho(const ICMPEchoRequest &packet) const noexcept
	{
		return
			header.type == packet.header.type &&
			header.code == packet.header.code &&
			header.checksum == packet.header.checksum &&
			header.un.echo.id == packet.header.un.echo.id &&
			header.un.echo.sequence == packet.header.un.echo.sequence;
	}
};
