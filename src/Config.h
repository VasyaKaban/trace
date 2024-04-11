#pragma once

#include <string_view>
#include <string>
#include <variant>
#include <fstream>
#include <optional>
#include <filesystem>
#include <charconv>

struct Config
{
	std::string host;
	int hops = 30;
	int samples = 3;
	timeval timeout;
	std::variant<std::monostate, std::reference_wrapper<std::ostream>, std::ofstream> output_stream;

	Config() noexcept;
	Config(const Config &) = delete;
	Config(Config &&) = default;
	Config & operator=(const Config &) = delete;
	Config & operator=(Config &&) = default;

	Config(std::string_view _host, int _hops, int _samples, timeval _timeout);
	Config(std::string_view _host, int _hops, int _samples, timeval _timeout, std::ofstream &&_output_stream);

	static Config Create(int argc, char **argv, Config &&defaults);

	std::ostream & GetOutputStream() noexcept;

private:
	[[noreturn]] static void PrintHelpAndExit();
	static std::optional<std::ofstream> OpenStream(const std::filesystem::path path) noexcept;
	static bool FromCharsResultIsGood(const std::from_chars_result &res, const char *end) noexcept;
	static std::optional<std::string_view> ParseString(std::string_view arg) noexcept;
	static std::string_view SplitArgumentWithAssignment(std::string_view arg) noexcept;

	template<std::integral T>
	static std::optional<T> ParseIntegral(std::string_view arg,
										  T min = std::numeric_limits<T>::min(),
										  T max = std::numeric_limits<T>::max()) noexcept
	{
		auto arg_value = SplitArgumentWithAssignment(arg);
		if(arg_value.empty())
			return {};

		T value;
		auto res = std::from_chars(arg_value.data(), arg_value.data() + arg_value.size(), value);
		if(!FromCharsResultIsGood(res, arg_value.data() + arg_value.size()))
			return {};

		if(min <= value && value <= max)
			return value;

		return {};
	}
};
