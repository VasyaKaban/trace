#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <netinet/ip.h>
#include "ICMPEchoRequest.h"

template<std::size_t N>
struct ICMPEchoReply
{
	std::uint16_t id;
	std::uint16_t seq;

	std::byte data[N];
};

struct ICMPTTLWithIPOptions
{
	std::byte unused[4];
	ip ip_header;
	std::byte options[4];
	std::byte data[8];
};

struct ICMPTTLWithoutIPOptions
{
	std::byte unused[4];
	ip ip_header;
	std::byte data[8];
};

template<std::size_t N>
struct ICMPResponses
{
	std::uint8_t type;
	std::uint8_t code;
	std::uint16_t checksum;

	union
	{
		ICMPEchoReply<N> echo_reply;
		ICMPTTLWithIPOptions ttl_with_options;
		ICMPTTLWithoutIPOptions ttl_without_options;
	} responses;
};

template<std::size_t N>
struct ICMPResponse
{
	ip ip_header;

	union
	{
		union
		{
			std::byte options[4];
			ICMPResponses<N> icmp;
		} header_with_opts;

		ICMPResponses<N> icmp;
	} data;

	template<std::size_t RN>
	constexpr bool SamePacket(const ICMPEchoRequest<RN> &request) noexcept
	{
		if(ip_header.ip_hl > 5)//with options
		{
			if(data.header_with_opts.icmp.type == 8)//ECHO_REPLY
			{
				return
					data.header_with_opts.icmp.responses.echo_reply.id == request.header.un.echo.id &&
					data.header_with_opts.icmp.responses.echo_reply.seq == request.header.un.echo.sequence;
			}
			else if(data.header_with_opts.icmp.type == 11)//TTL_TIMEOUT
			{
				return !std::memcmp(&data.header_with_opts.icmp.responses.ttl_with_options.data,
									&request,
									8);
			}
			else
				return false;
		}
		else//without options
		{
			if(data.icmp.type == 8)//ECHO_REPLY
			{
				return
					data.icmp.responses.echo_reply.id == request.header.un.echo.id &&
					data.icmp.responses.echo_reply.seq == request.header.un.echo.sequence;
			}
			else if(data.icmp.type == 11)//TTL_TIMEOUT
			{
				return !std::memcmp(&data.icmp.responses.ttl_without_options.data,
									&request,
									8);
			}
			else
				return false;
		}
	}

	constexpr bool SameType(std::uint8_t type) const noexcept
	{
		if(ip_header.ip_hl > 5)
			return data.header_with_opts.icmp.type == type;

		return data.icmp.type == type;
	}

	constexpr bool SameCode(std::uint8_t code) const noexcept
	{
		if(ip_header.ip_hl > 5)
			return data.header_with_opts.icmp.code == code;

		return data.icmp.code == code;
	}
};
