#include "heypixel_shit.h"
#include <regex>
#include <Windows.h>
#include "utils.h"
#include "strutils.h"
std::wstring heypixel_shit::get_username()
{
	auto command = utils::to_std_string2(std::wstring(GetCommandLineW()).c_str());
	std::string usernameKey = "--username ";
	size_t startPos = command.find(usernameKey);

	if (startPos == std::string::npos) {
		return L"Default String";
	}

	startPos += usernameKey.length();
	size_t endPos = command.find(" ", startPos);

	if (endPos == std::string::npos) {
		endPos = command.length();
	}

	return utils::to_std_wstring(command.substr(startPos, endPos - startPos));
}
