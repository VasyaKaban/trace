#include "Config.h"
#include "Trace.h"

int main(int argc, char **argv)
{
	Config defaults("", 30, 3, timeval{.tv_sec = 1, .tv_usec = 0});
	auto config = Config::Create(argc, argv, std::move(defaults));
	std::ostream &out = config.GetOutputStream();

	auto trace_result = Trace(config.host,
							  config.hops,
							  config.samples,
							  config.timeout,
							  out);

	if(trace_result == TraceResult::Errno)
		return errno;

	return static_cast<int>(trace_result);
}

