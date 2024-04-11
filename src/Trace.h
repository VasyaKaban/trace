#pragma once

#include <string>
#include <unistd.h>

enum class TraceResult
{
	Success = 0,
	UnresolvedHost,
	Errno
};

TraceResult Trace(const std::string &host_name, int hops, int samples, timeval timeout, std::ostream &out);

