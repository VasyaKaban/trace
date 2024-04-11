#pragma once

#include <chrono>
#include <sys/socket.h>

struct Sample
{
	sockaddr address;
	socklen_t address_len;
	std::chrono::milliseconds read_time;

	Sample() = default;
	~Sample() = default;
	Sample(const Sample &) = default;
	Sample(Sample &&) = default;
	Sample & operator=(const Sample &) = default;
	Sample & operator=(Sample &&) = default;

	Sample(const sockaddr *_address,
		   socklen_t _address_len,
		   std::chrono::milliseconds _read_time) noexcept;
};

