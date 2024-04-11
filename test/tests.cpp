//#define BOOST_TEST_MODULE TraceTest
//#define BOOST_TEST_MAIN
#include <boost/test/included/unit_test.hpp>
#include <boost/test/parameterized_test.hpp>

#include "../src/Trace.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <array>
#include <cassert>

struct TraceTest
{
	std::string host;
	int hops;
	int samples;
	timeval timeout;
	std::filesystem::path out_file;

	TraceResult expected_result;

	TraceTest(const std::string &_host,
			  int _hops,
			  int _samples,
			  TraceResult _expected_result,
			  timeval _timeout,
			  const std::filesystem::path &_out_file = "")
		: host(_host),
		  hops(_hops),
		  samples(_samples),
		  timeout(_timeout),
		  expected_result(_expected_result),
		  out_file(_out_file) {}
};

void AssertTestCase(const TraceTest &test)
{
	std::ofstream ofs;
	if(!test.out_file.empty())
	{
		ofs.open(test.out_file);
		BOOST_ASSERT(ofs.is_open());
	}

	auto result = Trace(test.host,
						test.hops,
						test.samples,
						test.timeout,
						(ofs.is_open() ? ofs : std::cout));

	BOOST_ASSERT(result == test.expected_result);

	if(ofs.is_open())
	{
		BOOST_ASSERT(std::filesystem::exists(test.out_file));
		if(result == TraceResult::Success && test.hops > 0 && test.samples > 0)
			BOOST_ASSERT(std::filesystem::file_size(test.out_file) > 0);

		ofs.close();
	}
}


boost::unit_test::test_suite * init_unit_test_suite(int argc, char **argv)
{
	static std::array tests =
	{
		TraceTest("www.google.com", 128, 3,
				  TraceResult::Success,
				  timeval{.tv_sec = 1, .tv_usec = 0}),

		TraceTest("www.bsuir.by",
				  30, 2,
				  TraceResult::Success,
				  timeval{.tv_sec = 1, .tv_usec = 0}),

		TraceTest("www.ewferg44543.com",
				  128, 3,
				  TraceResult::UnresolvedHost,
				  timeval{.tv_sec = 1, .tv_usec = 0}),

		TraceTest("www.onliner.by",
				  64, 2,
				  TraceResult::Success,
				  timeval{.tv_sec = 1, .tv_usec = 0},
				  "onliner_trace_result.txt"),

		TraceTest("www.youtube.com",
				  12, 5,
				  TraceResult::Success,
				  timeval{.tv_sec = 1, .tv_usec = 0}),

		TraceTest("www.cppreference.com",
				  48, 3,
				  TraceResult::Success,
				  timeval{.tv_sec = 3, .tv_usec = 0},
				  "cppreference_route.txt"),

		TraceTest("ww.wikipedia.com",
				  4434, 4354,
				  TraceResult::UnresolvedHost,
				  timeval{.tv_sec = 1, .tv_usec = 0},
				  "bad_wikipedia_host.txt"),

		TraceTest("www.wikipedia.com",
				  6, 3,
				  TraceResult::Success,
				  timeval{.tv_sec = 2, .tv_usec = 0}),

		TraceTest("www.boost.org",
				  6, 3,
				  TraceResult::Success,
				  timeval{.tv_sec = 0, .tv_usec = 5}),

		TraceTest("www.kernel.org", 32, 3,
				  TraceResult::Success,
				  timeval{.tv_sec = 1, .tv_usec = 0})
	};

	boost::unit_test::framework::master_test_suite()
		.add(BOOST_PARAM_TEST_CASE(&AssertTestCase, tests.data(), tests.data() + tests.size()));

	return 0;
}
