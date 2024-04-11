#include "Sample.h"

Sample::Sample(const sockaddr *_address,
			   socklen_t _address_len,
			   std::chrono::milliseconds _read_time) noexcept
	: address(*_address),
	  address_len(_address_len),
	  read_time(_read_time) {}
