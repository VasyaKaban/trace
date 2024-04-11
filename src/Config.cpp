#include "Config.h"
#include <iostream>
#include <cstring>

Config::Config() noexcept
	: output_stream(std::ref(std::cout)){}

Config::Config(std::string_view _host, int _hops, int _samples, timeval _timeout)
	: host(_host),
	  hops(_hops),
	  samples(_samples),
	  timeout(_timeout),
	  output_stream(std::ref(std::cout)){}


Config::Config(std::string_view _host,
	   int _hops,
	   int _samples,
	   timeval _timeout,
	   std::ofstream &&_output_stream)
	: host(_host),
	  hops(_hops),
	  samples(_samples),
	  timeout(_timeout),
	  output_stream(std::move(_output_stream)) {}

Config Config::Create(int argc, char **argv, Config &&defaults)
{
	if(argc == 1)
		PrintHelpAndExit();

	Config config = std::move(defaults);
	for(int i = 1; i < argc; i++)
	{
		std::string_view argv_view(argv[i], std::strlen(argv[i]));
		if(argv_view == "--help")
			PrintHelpAndExit();
		else if(argv_view.starts_with("--host="))
		{
			auto host_opt = ParseString(argv_view);
			if(!host_opt)
			{
				std::cout<<"Bad host!"<<std::endl;
				exit(EXIT_FAILURE);
			}

			config.host = host_opt.value();
		}
		else if(argv_view.starts_with("--hops="))
		{
			auto hops_opt = ParseIntegral<int>(argv_view, 1);
			if(!hops_opt)
			{
				std::cout<<"Bad hops value!"<<std::endl;
				exit(EXIT_FAILURE);
			}

			config.hops = hops_opt.value();
		}
		else if(argv_view.starts_with("--samples="))
		{
			auto samples_opt = ParseIntegral<int>(argv_view, 1);
			if(!samples_opt)
			{
				std::cout<<"Bad hops value!"<<std::endl;
				exit(EXIT_FAILURE);
			}

			config.samples = samples_opt.value();
		}
		else if(argv_view.starts_with("--timeout="))
		{
			auto timeout_opt = ParseIntegral<std::uint64_t>(argv_view, 0);
			if(!timeout_opt)
			{
				std::cout<<"Bad timeout value!"<<std::endl;
				exit(EXIT_FAILURE);
			}

			//timeval -> seconds / microseconds -> sec, sec * 10^6
			//timeout -> sec * 10^3
			std::uint64_t seconds = timeout_opt.value() / 1000;
			std::uint64_t remain = timeout_opt.value() - seconds * 1000;
			std::uint64_t microseconds = remain * 1000;

			config.timeout.tv_sec = seconds;
			config.timeout.tv_usec = microseconds;
		}
		else if(argv_view.starts_with("--out_file="))
		{
			auto path_opt = ParseString(argv_view);
			if(!path_opt)
			{
				std::cout<<"Bad output file path value!"<<std::endl;
				exit(EXIT_FAILURE);
			}

			auto ofs_opt = OpenStream(path_opt.value());
			if(ofs_opt)
				config.output_stream = std::move(ofs_opt.value());
			else
				std::cout<<"Output strteam into the file: "<<argv_view<<" cannont be opened!"<<std::endl;
		}
		else
		{
			std::cout<<"Undefined argument: "<<argv_view<<std::endl;
			exit(EXIT_FAILURE);
		}
	}

	return config;
}

std::ostream & Config::GetOutputStream() noexcept
{
	if(std::holds_alternative<std::ofstream>(output_stream))
		return std::get<std::ofstream>(output_stream);
	else
		return std::get<std::reference_wrapper<std::ostream>>(output_stream).get();
}

[[noreturn]] void Config::PrintHelpAndExit()
{
	std::cout<<"usage: trace [--hops=$value(>0)] [--samples=$value(>0)] --host=$host_name [--timeout=$value(>0)] [--out_file=path]"<<"\n";
	std::cout<<"Flags:\n";
	std::cout<<"--help -> show usage infromation\n";
	std::cout<<"--host -> sets the host name which route we want to explore\n";
	std::cout<<"--hops -> sets the maximum TTL hops for socket."
				 " This value must be greater than zero\n";
	std::cout<<"--samples -> sets the maximum samples per hop."
				 " Each sample is a send/receive iteration with remote host information collection"
				 " and timer measurements!"
				 " This value must be greater than zero\n";
	std::cout<<"--timeout -> sets timeout in milliseconds for reading."
				 " This value must be a positive integer. \n";
	std::cout<<"--out_file -> sets the path for an output file."
				 " By default output will be flushed into the stdout\n";
	exit(EXIT_SUCCESS);
}

std::optional<std::ofstream> Config::OpenStream(const std::filesystem::path path) noexcept
{
	std::ofstream ofs;
	ofs.open(path);
	if(!ofs.is_open())
		return {};

	return ofs;
}

bool Config::FromCharsResultIsGood(const std::from_chars_result &res, const char *end) noexcept
{
	return (res.ec == std::errc(0) && res.ptr == end);
}

std::optional<std::string_view> Config::ParseString(std::string_view arg) noexcept
{
	auto value = SplitArgumentWithAssignment(arg);
	if(value.empty())
		return {};

	return value;
}

std::string_view Config::SplitArgumentWithAssignment(std::string_view arg) noexcept
{
	auto assignment_pos = arg.find("=");
	if(assignment_pos == std::string_view::npos)
		return {};

	return std::string_view(arg.begin() + assignment_pos + 1, arg.end());
}

