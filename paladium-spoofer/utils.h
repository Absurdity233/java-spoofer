#pragma once

#include "includes.h"
#include <vector>
#include <ntstatus.h>
#include <codecvt>

#pragma comment(lib, "ntdll")


namespace utils {

	void create_console();
	std::wstring GetRegistryKeyPath(HKEY hKey);
	bool ends_with(std::wstring mainStr, std::wstring toMatch);
	std::wstring to_lower_w(const std::wstring& str);

	std::string to_lower_c(const std::string& str);

	inline bool contains(const std::string& str, const std::string& substring)
	{
		return str.find(substring) != std::string::npos;
	}

	inline bool contains(const std::wstring& str, const std::wstring& substring)
	{
		return str.find(substring) != std::wstring::npos;
	}
	inline bool contains_chinese(const std::string& str) {
		try {
			for (size_t i = 0; i < str.size(); ++i) {
				if ((str[i] & 0x80) != 0) {
					std::wstring wideStr;
					int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
					if (len <= 0) return false;
					wideStr.resize(len);
					MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wideStr[0], len);
					for (wchar_t ch : wideStr) {
						if (ch >= 0x4E00 && ch <= 0x9FFF) {
							return true;
						}
					}
					return false;
				}
			}
		}
		catch (...) {
			return false;
		}
		return false;
	}
	bool wstr_starts_with(const std::wstring& mainStr, const std::wstring& toMatch);
	HMODULE find_or_load_library(LPCSTR str);
	std::wstring read_file_to_wstr(const std::wstring& file_name);
	inline unsigned short hash_string(const wchar_t* str) {
		unsigned long long hash = 5381;
		wchar_t c{};

		while ((c = *str++)) {
			hash = ((hash << 5) + hash) + c;
		}

		return (unsigned short)(hash % 65536);
	}
	inline bool starts_with(const std::string& mainStr, const std::string& toMatch)
	{
		return mainStr.length() >= toMatch.length() &&
			mainStr.compare(0, toMatch.length(), toMatch) == 0;
	}
	inline std::string to_std_string2(const WCHAR* lpwstr) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
		return converter.to_bytes(lpwstr);
	}
	inline std::string to_std_string(const WCHAR* lpwstr) {
		int charNum = WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, nullptr, 0, nullptr, nullptr);

		char* cstr = new char[charNum];

		WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, cstr, charNum, nullptr, nullptr);
		std::string str(cstr);
		delete[] cstr;

		return str;
	}
	inline std::wstring to_std_wstring(const std::string& str) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
		return converter.from_bytes(str);
	}
	inline void trim_left(std::string& str)
	{
		str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](int ch) { return !std::isspace(ch); }));
	}

	/**
	 * @brief Trims (in-place) white spaces from the right side of std::string.
	 *        Taken from: http://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring.
	 * @param str - input std::string to remove white spaces from.
	 */
	inline void trim_right(std::string& str)
	{
		str.erase(std::find_if(str.rbegin(), str.rend(), [](int ch) { return !std::isspace(ch); }).base(), str.end());
	}

	/**
	 * @brief Trims (in-place) white spaces from the both sides of std::string.
	 *        Taken from: http://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring.
	 * @param str - input std::string to remove white spaces from.
	 */
	inline void trim(std::string& str)
	{
		trim_left(str);
		trim_right(str);
	}
}