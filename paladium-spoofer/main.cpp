#include "main.h"
#include <WbemCli.h>
#include <gl/GL.h>

#include "module_hooks.hpp"
#include "wmi_hook.hpp"
#include "detours.h"
#include "mac_spoof.h"
#include "heypixel_shit.h"
#include "strutils.h"
using namespace std;

static LSTATUS(APIENTRY* orig_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) = RegQueryValueExW;
static BOOL(WINAPI* orig_GetVolumeNameForVolumeMountPointW)(LPCWSTR, LPWSTR, DWORD) = GetVolumeNameForVolumeMountPointW;

static std::wstring value;

static void (*orig_nglGetTexImage)(GLenum target, GLint level, GLenum format, GLenum type, GLvoid* pixels);

static void hk_nglGetTexImage(GLenum target, GLint level, GLenum format, GLenum type, GLvoid* pixels) {
	system("msg %username% \"It seems like a screenshot has been taken.\"");
	orig_nglGetTexImage(target, level, format, type, pixels);
}

// 安全地将伪造的宽字符串写入 RegQueryValueExW 的 lpData 缓冲区
// 如果缓冲区不够大，返回 ERROR_MORE_DATA；否则拷贝数据并返回 ERROR_SUCCESS
static LSTATUS safe_write_reg_sz(const std::wstring& spoofed, LPBYTE lpData, LPDWORD lpcbData)
{
	DWORD requiredBytes = static_cast<DWORD>((spoofed.size() + 1) * sizeof(wchar_t)); // 含 null 终止符
	if (*lpcbData < requiredBytes) {
		*lpcbData = requiredBytes;
		return ERROR_MORE_DATA;
	}
	memcpy(lpData, spoofed.c_str(), requiredBytes);
	*lpcbData = requiredBytes;
	return ERROR_SUCCESS;
}

static LSTATUS APIENTRY hk_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	if (lpValueName == NULL)
		return orig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

	std::wstring valName(lpValueName);
	bool is_target = (valName == L"ProcessorNameString" || valName == L"VendorIdentifier" || valName == L"Identifier");

	if (!is_target)
		return orig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

	// 先调用原始函数，让系统填充 lpType 和实际数据
	LSTATUS origResult = orig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

	// 只在原始调用成功且类型为 REG_SZ 时才伪造
	DWORD resolvedType = lpType ? *lpType : REG_NONE;
	if (origResult != ERROR_SUCCESS || resolvedType != REG_SZ || !lpData || !lpcbData)
		return origResult;

	if (valName == L"ProcessorNameString")
	{
		static const std::wstring processor_name = utils::to_std_wstring(heypixel_shit::profile->cpu_name);
		return safe_write_reg_sz(processor_name, lpData, lpcbData);
	}
	else if (valName == L"VendorIdentifier")
	{
		static const std::wstring vendor_id = strutil::contains(heypixel_shit::profile->cpu_name, "Intel") ? L"GenuineIntel" : L"AuthenticAMD";
		return safe_write_reg_sz(vendor_id, lpData, lpcbData);
	}
	else if (valName == L"Identifier")
	{
		static const std::wstring id = (strutil::contains(heypixel_shit::profile->cpu_name, "Intel") ? L"Intel64 " : L"AuthenticAMD ") + utils::to_std_wstring(heypixel_shit::profile->cpu_identifier);
		return safe_write_reg_sz(id, lpData, lpcbData);
	}

	return origResult;
}


static BOOL WINAPI hk_GetVolumeNameForVolumeMountPointW(LPCWSTR lpszVolumeMountPoint, LPWSTR lpszVolumeName, DWORD cchBufferLength)
{
	BOOL success = orig_GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength);
	if (success && cchBufferLength > 0 && !value.empty()) {
		// cchBufferLength 是字符数（含 null）；安全拷贝，不越界
		size_t charsToCopy = min(value.size(), static_cast<size_t>(cchBufferLength) - 1);
		memcpy(lpszVolumeName, value.c_str(), charsToCopy * sizeof(wchar_t));
		lpszVolumeName[charsToCopy] = L'\0';
	}
	return success;
}
DWORD BootStrapThread(HANDLE _) {

	if (std::wstring(GetCommandLine()).find(L"-DToken") == std::wstring::npos)
	{
		return TRUE;
	}

	if (DetourIsHelperProcess()) {
		return TRUE;
	}
	utils::create_console();

	//value = utils::read_file_to_wstr(L"C:\\Users\\Public\\nt.dat");
	value = heypixel_shit::get_username();
	//std::wcout << "username :" << value << std::endl;
	//value = L"123123123";
	heypixel_shit::global_factor = utils::hash_string(value.c_str());
	heypixel_shit::profile = std::make_shared<hwid_profile>(utils::to_std_string(value.c_str()));
	heypixel_shit::start_time = std::chrono::steady_clock::now();


	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)orig_RegQueryValueExW, hk_RegQueryValueExW);
	wmi_hook::initialize(value);
	module_hooks::initialize_hooks();
	mac_spoof::initialize();
	DetourTransactionCommit();

	return 0;
}
