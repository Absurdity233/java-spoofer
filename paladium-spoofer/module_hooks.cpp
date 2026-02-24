#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <algorithm>
#include <string>
#include <cstdio>
#include <fstream>
#include <atomic>
#include <sstream>

#pragma comment(lib, "Wtsapi32.lib")
#include <WtsApi32.h>


#include "utils.h"
#include "detours.h"
#include "module_hooks.hpp"
#include <Psapi.h>
#include "heypixel_shit.h"

struct module_info {
	int index;
	std::string name;
	std::string baseAddress;
	std::string size;
	std::string path;
	std::string description;
	std::string version;
	std::string company;
};


static std::vector<module_info> module_infos;


// These DLLs are loaded by the spoofer
const wchar_t* names[] = {
	L"fastprox.dll",
	L"wbemcomn.dll",
};

// china solution for a china-tier anticheat
std::wstring whitelisted_names[] = {
	L"svchost.exe",
	L"cefsharp.browsersubprocess.exe",
	L"audiodg.exe",
	L"windowsterminal.exe",
	L"servicehub.settingshost.exe",
	L"spotify.exe",
	L"lghub_agent.exe",
	L"wininit.exe",
	L"chrome.exe",
	L"servicehub.indexingservice.exe",
	L"servicehub.host.netfx.x86.exe",
	L"java.exe",
	L"javaw.exe",
	L"runtimebroker.exe",
	L"servicehub.testWindowstorehost.exe",
	L"textinputhost.exe",
	L"unsecapp.exe",
	L"razer central.exe",
	L"rzsdkservice.exe",
	L"servicehub.indexingservice.exe",
	L"nvcontainer.exe",
	L"dllhost.exe",
	L"discord.exe",
	L"discordcanary.exe",
	L"discordptb.exe",
	L"rzchromastreamserver.exe",
	L"jcef_helper.exe",
	L"translucenttb.exe",
	L"ctfmon.exe",
	L"icue.exe",
	L"csrss.exe",
	L"lsalso.exe",
	L"gameinputsvc.exe",
	L"conhost.exe",
	L"applicationframehost.exe",
	L"nvidia web helper.exe",
	L"gamingservices.exe",
	L"icueupdateservice.exe",
	L"dwm.exe",
	L"firefox.exe",
	L"nvidia share.exe",
	L"wudfhost.exe",
	L"searchhost.exe",
	L"applemobiledeviceservice.exe",
	L"corsair.service.exe",
	L"servicehub.host.anycpu.exe",
	L"corsaircpuidservice.exe",
	L"corsairgamingaudiocfgservice64.exe",
	L"lghub_updater.exe",
	L"PC4399_WPFLauncher.exe",
	L"WPFLauncher.exe"
};

typedef BOOL(WINAPI* DefOrig_Module32NextW)(
	HANDLE hSnapshot,
	LPMODULEENTRY32W lpme
	);

DefOrig_Module32NextW Orig_Module32NextW = nullptr;

// Original function pointer
typedef BOOL(WINAPI* DefOrig_WTSEnumerateProcessesW)(
	_In_ HANDLE    hServer,
	_Inout_ DWORD* pLevel,
	_In_ DWORD SessionId,
	_Out_ LPWSTR* ppProcessInfo,
	_Out_ DWORD* pCount
	);

DefOrig_WTSEnumerateProcessesW Orig_WTSEnumerateProcessesExW = nullptr;
decltype(&EnumProcessModules) Orig_EnumProcessModules = nullptr;
decltype(&GetModuleFileNameExW) g_orig_GetModuleFileNameExW = nullptr;

/* DLLs to hide. Lowercase. Use * for any chars (e.g. loader-*.dll, mc-core-*.dll). */
static const wchar_t* hidden_module_names[] = {
	L"winmm.dll",
	L"mizoreagent.dll",
	L"mizorecore.dll",
	L"loader.dll",
	L"loader-*.dll",
	L"mc-core.dll",
	L"mc-core-*.dll",
	L"lib*.tmp",
	L"proxima_native.dll",
	L"skija.dll",
	NULL
};

static std::wstring get_filename_lower_from_path(const std::wstring& path) {
	std::wstring::size_type pos = path.find_last_of(L"\\/");
	std::wstring filename = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
	return utils::to_lower_w(filename);
}

/* * matches zero or more chars. Pattern and str must be lowercase. */
static bool match_wildcard(const std::wstring& pattern, const std::wstring& str) {
	std::wstring::size_type pi = 0, si = 0, star_pi = std::wstring::npos, star_si = std::wstring::npos;
	while (si < str.size()) {
		if (pi < pattern.size() && (pattern[pi] == L'*')) {
			star_pi = pi++;
			star_si = si;
			continue;
		}
		if (pi < pattern.size() && (pattern[pi] == str[si])) {
			pi++;
			si++;
			continue;
		}
		if (star_pi != std::wstring::npos) {
			pi = star_pi + 1;
			si = ++star_si;
			continue;
		}
		return false;
	}
	while (pi < pattern.size() && pattern[pi] == L'*') pi++;
	return pi == pattern.size();
}

static bool is_in_hidden_list(const std::wstring& filename_lower) {
	for (const wchar_t** p = hidden_module_names; *p != NULL; ++p) {
		std::wstring pat(*p);
		if (pat.find(L'*') != std::wstring::npos) {
			if (match_wildcard(pat, filename_lower)) return true;
		} else {
			if (filename_lower == pat) return true;
		}
	}
	return false;
}


BOOL WINAPI hk_WTSEnumerateProcessesW(
	_In_ HANDLE hServer, _Inout_ DWORD* pLevel, _In_ DWORD SessionId, _Out_ LPWSTR* ppProcessInfoEx, _Out_ DWORD* pCount
)
{
	BOOL res = Orig_WTSEnumerateProcessesExW(hServer, pLevel, SessionId, ppProcessInfoEx, pCount);
	if (!res || !ppProcessInfoEx || !pCount || *pCount == 0)
		return res;

	PWTS_PROCESS_INFO_EXW ppProcessInfo = (PWTS_PROCESS_INFO_EXW)*ppProcessInfoEx;
	DWORD writeIndex = 0;

	for (DWORD i = 0; i < *pCount; ++i)
	{
		if (!ppProcessInfo[i].pProcessName) continue;
		std::wstring wstr(ppProcessInfo[i].pProcessName);

		for (const auto& whitelisted_name : whitelisted_names) {
			if (utils::to_lower_w(wstr) == whitelisted_name) {
				if (writeIndex != i)
					ppProcessInfo[writeIndex] = ppProcessInfo[i];
				writeIndex++;
				break;
			}
		}
	}

	*pCount = writeIndex;
	return res;
}

BOOL WINAPI hk_Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
{
	while (true) {
		BOOL b = Orig_Module32NextW(hSnapshot, lpme);
		if (!b) return FALSE;

		wchar_t name[MAX_PATH] = { 0 };
		GetModuleFileNameW(lpme->hModule, name, MAX_PATH);
		std::wstring module_path(name);
		std::wstring filename_lower = get_filename_lower_from_path(module_path);

		// 1. Check hidden module list (wildcard matching)
		if (is_in_hidden_list(filename_lower))
			continue;

		// 2. Check module baseline whitelist (if loaded)
		if (!module_infos.empty()) {
			bool in_baseline = false;
			for (const auto& module : module_infos) {
				if (utils::ends_with(utils::to_lower_w(module_path), utils::to_std_wstring(module.name))) {
					in_baseline = true;
					break;
				}
			}
			if (!in_baseline)
				continue;
		}

		return TRUE;
	}
}

static DWORD WINAPI hk_GetModuleFileNameExW(
	HANDLE hProcess,
	HMODULE hModule,
	LPWSTR lpFilename,
	DWORD nSize
)
{
	DWORD ret = g_orig_GetModuleFileNameExW(hProcess, hModule, lpFilename, nSize);
	if (ret == 0 || nSize == 0) return ret;
	std::wstring path(lpFilename);
	std::wstring filename_lower = get_filename_lower_from_path(path);
	if (is_in_hidden_list(filename_lower)) {
		std::wcout << L"[mizore][modules] hiding module from GetModuleFileNameExW: " << path << std::endl;
		lpFilename[0] = L'\0';
		return 0;
	}
	return ret;
}

static std::atomic<bool> check_flag = false;
static BOOL detour_EnumProcessModules(
	_In_ HANDLE hProcess,
	_Out_writes_bytes_(cb) HMODULE* lphModule,
	_In_ DWORD cb,
	_Out_ LPDWORD lpcbNeeded
)
{
	BOOL result = Orig_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
	if (!result) return result;

	DWORD count = min(*lpcbNeeded, cb) / sizeof(HMODULE);
	DWORD writeIndex = 0;
	wchar_t path[MAX_PATH] = {};

	for (DWORD i = 0; i < count; i++) {
		if (!g_orig_GetModuleFileNameExW(hProcess, lphModule[i], path, MAX_PATH))
			continue;
		std::wstring module_path(path);
		std::wstring filename_lower = get_filename_lower_from_path(module_path);

		if (is_in_hidden_list(filename_lower))
			continue;

		if (utils::contains(utils::to_lower_w(module_path), L"voyage"))
			check_flag.store(true);

		// 只有基线非空时才做白名单过滤，防止基线为空时过滤掉所有模块导致崩溃
		if (!module_infos.empty()) {
			bool flag = false;
			for (auto& module : module_infos) {
				if (utils::ends_with(utils::to_lower_w(module_path), utils::to_std_wstring(module.name))) {
					flag = true;
					break;
				}
			}
			if (!flag)
				continue;
		}

		lphModule[writeIndex++] = lphModule[i];
	}
	*lpcbNeeded = writeIndex * sizeof(HMODULE);

	std::cout << "[mizore][modules] EnumProcessModules filtered to " << writeIndex << " modules (from " << count << ")" << std::endl;

	if (!check_flag.load()) {
		//if (heypixel_shit::has_exceeded(5)) __fastfail(-1);
	}
	return TRUE;
}

// --------------- jmap bypass: CreateProcessW hook，检测到 jmap 命令直接让 CreateProcess 失败 ---------------
static decltype(&CreateProcessW) Orig_CreateProcessW = nullptr;

static bool is_jmap_command(LPCWSTR cmd) {
	if (!cmd) return false;
	std::wstring lower;
	lower.reserve(wcslen(cmd));
	for (const wchar_t* p = cmd; *p; ++p) lower.push_back(static_cast<wchar_t>(towlower(*p)));
	return lower.find(L"jmap") != std::wstring::npos;
}

static std::string read_from_pipe(HANDLE hPipe) {
	DWORD dwRead;
	CHAR chBuf[4096];
	std::string result;
	BOOL bSuccess = FALSE;
	for (;;) {
		bSuccess = ReadFile(hPipe, chBuf, sizeof(chBuf), &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;
		result.append(chBuf, dwRead);
	}
	return result;
}

static BOOL WINAPI hk_CreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	// 1. jmap 拦截
	if (is_jmap_command(lpCommandLine) || is_jmap_command(lpApplicationName)) {
		std::cout << "[mizore][jmap] CreateProcessW blocked jmap command, returning ERROR_FILE_NOT_FOUND" << std::endl;
		SetLastError(ERROR_FILE_NOT_FOUND);
		return FALSE;
	}

	// 2. wmic 伪造（合并自 wmic_spoof，避免双重 CreateProcessW hook）
	if (lpCommandLine) {
		auto cmdLine = utils::to_std_string(lpCommandLine);
		utils::trim(cmdLine);
		cmdLine = utils::to_lower_c(cmdLine);
		bool baseboard_serial = (cmdLine == "wmic baseboard get serialnumber");
		bool disk_serial = (cmdLine == "wmic diskdrive get serialnumber");
		if (baseboard_serial || disk_serial) {
			HANDLE hReadPipe, hWritePipe;
			SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

			if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
				return FALSE;
			}
			if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
				CloseHandle(hReadPipe);
				CloseHandle(hWritePipe);
				return FALSE;
			}

			STARTUPINFOW si;
			ZeroMemory(&si, sizeof(STARTUPINFOW));
			si.cb = sizeof(STARTUPINFOW);
			si.hStdOutput = hWritePipe;
			si.hStdError = hWritePipe;
			si.dwFlags |= STARTF_USESTDHANDLES;

			auto result = Orig_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si, lpProcessInformation);

			CloseHandle(hWritePipe);

			if (!result) {
				CloseHandle(hReadPipe);
				return FALSE;
			}

			WaitForSingleObject(lpProcessInformation->hProcess, INFINITE);

			std::string outputData = read_from_pipe(hReadPipe);
			CloseHandle(hReadPipe);

			std::istringstream stream(outputData);
			std::string line;
			std::ostringstream output;
			while (std::getline(stream, line)) {
				if (!utils::contains(line, "SerialNumber") && !line.empty()) {
					if (!utils::contains(line, "Standard") && !utils::contains(line, "Default Value") && !utils::contains_chinese(line))
					{
						line = heypixel_shit::calculate(line, heypixel_shit::global_factor);
					}
				}
				output << line << "\n";
			}
			output.flush();

			// 只有调用者设置了 STARTF_USESTDHANDLES 时 hStdOutput 才有效
			if (lpStartupInfo && (lpStartupInfo->dwFlags & STARTF_USESTDHANDLES) && lpStartupInfo->hStdOutput) {
				std::string data = output.str();
				DWORD bytesWritten;
				WriteFile(
					lpStartupInfo->hStdOutput,
					data.c_str(),
					static_cast<DWORD>(data.size()),
					&bytesWritten,
					NULL
				);
			}
			return TRUE;
		}
	}

	return Orig_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}



static std::vector<module_info> parse_modules(const std::vector<std::string_view>& parts) {
	std::vector<module_info> modules;
	std::string wf;
	for (const auto& part : parts) {
		wf.append(part);
	}
	std::istringstream stream(wf);
	std::string line;

	while (std::getline(stream, line)) {
		std::istringstream lineStream(line);
		module_info module;
		lineStream >> module.index >> module.name >> module.baseAddress >> module.size;
		lineStream.ignore(); // 忽略空格
		std::getline(lineStream, module.path, '\t');
		std::getline(lineStream, module.description, '\t');
		std::getline(lineStream, module.version, '\t');
		std::getline(lineStream, module.company);
		module.name = utils::to_lower_c(module.name);
		modules.push_back(module);
	}

	return modules;
}

static std::vector<module_info> parse_modules_from_string(const std::string& content)
{
	std::vector<std::string_view> parts;
	parts.emplace_back(content.data(), content.size());
	return parse_modules(parts);
}

// 尝试从 USERPROFILE\mizore\clean_modules.txt 读取干净基线
// 成功时会直接覆盖全局 module_infos，并返回 true
static bool load_clean_modules_if_exists()
{
	wchar_t userProfile[MAX_PATH]{};
	DWORD upLen = GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
	if (upLen == 0 || upLen >= MAX_PATH)
		return false;

	std::wstring mizoreDir = std::wstring(userProfile) + L"\\mizore";
	std::wstring filePath = mizoreDir + L"\\clean_modules.txt";

	if (GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES)
		return false;

	FILE* fp = nullptr;
	if (_wfopen_s(&fp, filePath.c_str(), L"rb") != 0 || !fp)
		return false;

	std::string content;
	char buffer[4096];
	size_t read;
	while ((read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
	{
		content.append(buffer, read);
	}
	fclose(fp);

	if (content.empty())
		return false;

	auto modules = parse_modules_from_string(content);
	if (modules.empty())
		return false;

	module_infos = std::move(modules);
	std::cout << "[mizore][modules] loaded clean_modules.txt, modules=" << module_infos.size() << std::endl;
	return true;
}

static void write_clean_modules_if_needed()
{
	wchar_t userProfile[MAX_PATH]{};
	DWORD upLen = GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
	if (upLen == 0 || upLen >= MAX_PATH)
		return;

	std::wstring mizoreDir = std::wstring(userProfile) + L"\\mizore";
	CreateDirectoryW(mizoreDir.c_str(), nullptr);

	std::wstring filePath = mizoreDir + L"\\clean_modules.txt";
	if (GetFileAttributesW(filePath.c_str()) != INVALID_FILE_ATTRIBUTES)
		return;

	FILE* fp = nullptr;
	if (_wfopen_s(&fp, filePath.c_str(), L"wb") != 0 || !fp)
		return;

	for (const auto& module : module_infos) {
		std::string line;
		line.reserve(256);
		line.append(std::to_string(module.index)).append("\t")
			.append(module.name).append("\t")
			.append(module.baseAddress).append("\t")
			.append(module.size).append("\t")
			.append(module.path).append("\t")
			.append(module.description).append("\t")
			.append(module.version).append("\t")
			.append(module.company).append("\n");
		fwrite(line.data(), 1, line.size(), fp);
	}

	fclose(fp);
	std::cout << "[mizore][modules] wrote default clean_modules.txt with " << module_infos.size() << " modules" << std::endl;
}

void module_hooks::initialize_hooks()
{
	constexpr std::string_view part1 = R"(0	java.exe	0x7FF7CC400000	0xE000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\java.exe	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
1	ntdll.dll	0x7FFBF86B0000	0x217000	C:\WINDOWS\SYSTEM32\ntdll.dll	NT 层 DLL	10.0.22621.4391	Microsoft Corporation	
2	KERNEL32.DLL	0x7FFBF8280000	0xC4000	C:\WINDOWS\System32\KERNEL32.DLL	Windows NT 基本 API 客户端 DLL	10.0.22621.4391	Microsoft Corporation	
3	KERNELBASE.dll	0x7FFBF5B80000	0x3B9000	C:\WINDOWS\System32\KERNELBASE.dll	Windows NT 基本 API 客户端 DLL	10.0.22621.4391	Microsoft Corporation	
4	ucrtbase.dll	0x7FFBF5F40000	0x111000	C:\WINDOWS\System32\ucrtbase.dll	Microsoft® C Runtime Library	10.0.22621.3593	Microsoft Corporation	
5	jli.dll	0x7FFBD0B60000	0x18000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\jli.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
6	USER32.dll	0x7FFBF7660000	0x1AE000	C:\WINDOWS\System32\USER32.dll	多用户 Windows 用户 API 客户端 DLL	10.0.22621.4391	Microsoft Corporation	
7	COMCTL32.dll	0x7FFBE6A00000	0x292000	C:\WINDOWS\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.22621.4391_none_2715d37f73803e96\COMCTL32.dll	用户体验控件库	6.10.22621.4391	Microsoft Corporation	
8	win32u.dll	0x7FFBF6060000	0x26000	C:\WINDOWS\System32\win32u.dll	Win32u	10.0.22621.4460	Microsoft Corporation	
9	GDI32.dll	0x7FFBF83D0000	0x29000	C:\WINDOWS\System32\GDI32.dll	GDI Client DLL	10.0.22621.4036	Microsoft Corporation	
10	msvcrt.dll	0x7FFBF7B30000	0xA7000	C:\WINDOWS\System32\msvcrt.dll	Windows NT CRT DLL	7.0.22621.2506	Microsoft Corporation	
11	gdi32full.dll	0x7FFBF59B0000	0x11B000	C:\WINDOWS\System32\gdi32full.dll	GDI Client DLL	10.0.22621.4391	Microsoft Corporation	
12	msvcp_win.dll	0x7FFBF6270000	0x9A000	C:\WINDOWS\System32\msvcp_win.dll	Microsoft® C Runtime Library	10.0.22621.3374	Microsoft Corporation	
13	VCRUNTIME140.dll	0x7FFBCC360000	0x17000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\VCRUNTIME140.dll	Microsoft® C Runtime Library	14.0.24215.1	Microsoft Corporation	
14	IMM32.DLL	0x7FFBF7AF0000	0x31000	C:\WINDOWS\System32\IMM32.DLL	Multi-User Windows IMM32 API Client DLL	10.0.22621.3374	Microsoft Corporation	
15	vcruntime140_1.dll	0x7FFBD07F0000	0xC000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\vcruntime140_1.dll	Microsoft® C Runtime Library	14.27.29016.0	Microsoft Corporation	
16	msvcp140.dll	0x7FFB76290000	0x9D000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\msvcp140.dll	Microsoft® C Runtime Library	14.0.24215.1	Microsoft Corporation	
17	jvm.dll	0x7FFB45060000	0xC47000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\server\jvm.dll	OpenJDK 64-Bit server VM	17.0.2.0	Eclipse Adoptium	
18	ADVAPI32.dll	0x7FFBF8400000	0xB2000	C:\WINDOWS\System32\ADVAPI32.dll	高级 Windows 32 基本 API	10.0.22621.4391	Microsoft Corporation	
19	sechost.dll	0x7FFBF7810000	0xA7000	C:\WINDOWS\System32\sechost.dll	Host for SCM/SDDL/LSA Lookup APIs	10.0.22621.4391	Microsoft Corporation	
20	bcrypt.dll	0x7FFBF5AD0000	0x28000	C:\WINDOWS\System32\bcrypt.dll	Windows 加密基元库	10.0.22621.2506	Microsoft Corporation	
21	RPCRT4.dll	0x7FFBF8550000	0x114000	C:\WINDOWS\System32\RPCRT4.dll	远程过程调用运行时	10.0.22621.4249	Microsoft Corporation	
22	PSAPI.DLL	0x7FFBF6CD0000	0x8000	C:\WINDOWS\System32\PSAPI.DLL	Process Status Helper	10.0.22621.1	Microsoft Corporation	
23	WSOCK32.dll	0x7FFBCFF60000	0x9000	C:\WINDOWS\SYSTEM32\WSOCK32.dll	Windows Socket 32-Bit DLL	10.0.22621.1	Microsoft Corporation	
24	VERSION.dll	0x7FFBECF30000	0xA000	C:\WINDOWS\SYSTEM32\VERSION.dll	Version Checking and File Installation Libraries	10.0.22621.1	Microsoft Corporation	
25	WS2_32.dll	0x7FFBF8350000	0x71000	C:\WINDOWS\System32\WS2_32.dll	Windows Socket 2.0 32 位 DLL	10.0.22621.1	Microsoft Corporation	
26	SHLWAPI.dll	0x7FFBF7BE0000	0x5E000	C:\WINDOWS\System32\SHLWAPI.dll	外壳简易实用工具库	10.0.22621.4391	Microsoft Corporation	
27	winmm.dll	0x7FFBEBBE0000	0x34000	C:\WINDOWS\system32\winmm.dll	MCI API DLL	10.0.22621.4391	Microsoft Corporation	
28	kernel.appcore.dll	0x7FFBF4AE0000	0x18000	C:\WINDOWS\SYSTEM32\kernel.appcore.dll	AppModel API Host	10.0.22621.3958	Microsoft Corporation	
29	jimage.dll	0x7FFBCF9A0000	0xA000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\jimage.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
30	DBGHELP.DLL	0x7FFBF3000000	0x232000	C:\WINDOWS\SYSTEM32\DBGHELP.DLL	Windows Image Helper	10.0.22621.3593	Microsoft Corporation	
31	combase.dll	0x7FFBF63D0000	0x38F000	C:\WINDOWS\System32\combase.dll	用于 Windows 的 Microsoft COM	10.0.22621.4391	Microsoft Corporation	
32	OLEAUT32.dll	0x7FFBF7580000	0xD7000	C:\WINDOWS\System32\OLEAUT32.dll	OLEAUT32.DLL	10.0.22621.3672	Microsoft Corporation	
33	dbgcore.DLL	0x7FFBCABD0000	0x32000	C:\WINDOWS\SYSTEM32\dbgcore.DLL	Windows Core Debugging Helpers	10.0.22621.1	Microsoft Corporation	
34	bcryptPrimitives.dll	0x7FFBF5B00000	0x7B000	C:\WINDOWS\System32\bcryptPrimitives.dll	Windows Cryptographic Primitives Library	10.0.22621.4317	Microsoft Corporation	
35	java.dll	0x7FFBC3820000	0x25000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\java.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
36	jsvml.dll	0x7FFB5FCF0000	0xD6000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\jsvml.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
37	SHELL32.dll	0x7FFBF6D00000	0x876000	C:\WINDOWS\System32\SHELL32.dll	Windows Shell 公用 DLL	10.0.22621.4460	Microsoft Corporation	
38	windows.storage.dll	0x7FFBF38F0000	0x903000	C:\WINDOWS\SYSTEM32\windows.storage.dll	Microsoft WinRT Storage API	10.0.22621.4391	Microsoft Corporation	
39	wintypes.dll	0x7FFBF37B0000	0x13F000	C:\WINDOWS\SYSTEM32\wintypes.dll	Windows 基本类型 DLL	10.0.22621.3810	Microsoft Corporation	
40	SHCORE.dll	0x7FFBF6B70000	0xF9000	C:\WINDOWS\System32\SHCORE.dll	SHCORE	10.0.22621.4391	Microsoft Corporation	
41	profapi.dll	0x7FFBF58E0000	0x2B000	C:\WINDOWS\SYSTEM32\profapi.dll	User Profile Basic API	10.0.22621.4391	Microsoft Corporation	
42	net.dll	0x7FFBCB640000	0x19000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\net.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
43	WINHTTP.dll	0x7FFBF03A0000	0x136000	C:\WINDOWS\SYSTEM32\WINHTTP.dll	Windows HTTP 服务	10.0.22621.4391	Microsoft Corporation	
44	mswsock.dll	0x7FFBF4F60000	0x69000	C:\WINDOWS\system32\mswsock.dll	Microsoft Windows Sockets 2.0 服务提供程序	10.0.22621.2506	Microsoft Corporation	
45	nio.dll	0x7FFBCB100000	0x15000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\nio.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
46	zip.dll	0x7FFBB7F30000	0x18000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\zip.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
47	verify.dll	0x7FFBCCA00000	0x10000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\verify.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
48	management.dll	0x7FFBCC350000	0x9000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\management.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
49	management_ext.dll	0x7FFBCBA50000	0xB000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\management_ext.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
50	napinsp.dll	0x7FFBB0390000	0x17000	C:\WINDOWS\system32\napinsp.dll	电子邮件命名填充提供程序	10.0.22621.1	Microsoft Corporation	
51	pnrpnsp.dll	0x7FFBB0370000	0x1B000	C:\WINDOWS\system32\pnrpnsp.dll	PNRP 命名空间提供程序	10.0.22621.1	Microsoft Corporation	
52	DNSAPI.dll	0x7FFBF4540000	0x102000	C:\WINDOWS\SYSTEM32\DNSAPI.dll	DNS 客户端 API DLL	10.0.22621.4391	Microsoft Corporation	
53	IPHLPAPI.DLL	0x7FFBF44D0000	0x2D000	C:\WINDOWS\SYSTEM32\IPHLPAPI.DLL	IP 帮助程序 API	10.0.22621.1	Microsoft Corporation	
54	NSI.dll	0x7FFBF6CE0000	0x9000	C:\WINDOWS\System32\NSI.dll	NSI User-mode interface DLL	10.0.22621.1	Microsoft Corporation	
55	winrnr.dll	0x7FFBB03B0000	0x11000	C:\WINDOWS\System32\winrnr.dll	LDAP RnR Provider DLL	10.0.22621.1	Microsoft Corporation	
56	wshbth.dll	0x7FFBD55B0000	0x15000	C:\WINDOWS\system32\wshbth.dll	Windows Sockets Helper DLL	10.0.22621.3958	Microsoft Corporation	
57	nlansp_c.dll	0x7FFBB03D0000	0x27000	C:\WINDOWS\system32\nlansp_c.dll	NLA Namespace Service Provider DLL	10.0.22621.4391	Microsoft Corporation	
58	rasadhlp.dll	0x7FFBEE770000	0xA000	C:\Windows\System32\rasadhlp.dll	Remote Access AutoDial Helper	10.0.22621.1	Microsoft Corporation	
59	fwpuclnt.dll	0x7FFBEFD20000	0x83000	C:\WINDOWS\System32\fwpuclnt.dll	FWP/IPsec 用户模式 API	10.0.22621.4249	Microsoft Corporation	
)";

	constexpr std::string_view part2 = R"(60	api-ms-win-crt-utility-l1-1-1.dll	0x7FFB41B30000	0x26D3000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\runtime\api-ms-win-crt-utility-l1-1-1.dll				
61	CRYPT32.dll	0x7FFBF6090000	0x166000	C:\WINDOWS\System32\CRYPT32.dll	加密 API32	10.0.22621.4391	Microsoft Corporation	
62	libenvsdk.dll	0x7FFB40BA0000	0xF81000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\libenvsdk.dll	Netease Environment SDK	4.2.3.0	Netease	
63	WTSAPI32.dll	0x7FFBF4890000	0x14000	C:\WINDOWS\SYSTEM32\WTSAPI32.dll	Windows Remote Desktop Session Host Server SDK APIs	10.0.22621.1	Microsoft Corporation	
64	ntmarta.dll	0x7FFBF4BF0000	0x34000	C:\WINDOWS\SYSTEM32\ntmarta.dll	Windows NT MARTA 提供程序	10.0.22621.1	Microsoft Corporation	
65	SETUPAPI.DLL	0x7FFBF7C40000	0x474000	C:\WINDOWS\System32\SETUPAPI.DLL	Windows 安装程序 API	10.0.22621.2506	Microsoft Corporation	
66	cfgmgr32.DLL	0x7FFBF5670000	0x4E000	C:\WINDOWS\SYSTEM32\cfgmgr32.DLL	Configuration Manager DLL	10.0.22621.2506	Microsoft Corporation	
67	dhcpcsvc.DLL	0x7FFBF0360000	0x1F000	C:\WINDOWS\SYSTEM32\dhcpcsvc.DLL	DHCP 客户端服务	10.0.22621.2506	Microsoft Corporation	
68	Ole32.dll	0x7FFBF6760000	0x1A5000	C:\WINDOWS\System32\Ole32.dll	用于 Windows 的 Microsoft OLE	10.0.22621.3958	Microsoft Corporation	
69	CRYPTSP.dll	0x7FFBF51C0000	0x1B000	C:\WINDOWS\SYSTEM32\CRYPTSP.dll	Cryptographic Service Provider API	10.0.22621.3672	Microsoft Corporation	
70	rsaenh.dll	0x7FFBF4A40000	0x35000	C:\WINDOWS\system32\rsaenh.dll	Microsoft Enhanced Cryptographic Provider	10.0.22621.4249	Microsoft Corporation	
71	CRYPTBASE.dll	0x7FFBF51B0000	0xC000	C:\WINDOWS\SYSTEM32\CRYPTBASE.dll	Base cryptographic API DLL	10.0.22621.1	Microsoft Corporation	
72	Wintrust.dll	0x7FFBF6200000	0x6C000	C:\WINDOWS\System32\Wintrust.dll	Microsoft Trust Verification APIs	10.0.22621.4391	Microsoft Corporation	
73	MSASN1.dll	0x7FFBF5650000	0x12000	C:\WINDOWS\SYSTEM32\MSASN1.dll	ASN.1 Runtime APIs	10.0.22621.2506	Microsoft Corporation	
74	Normaliz.dll	0x7FFBF6CF0000	0x8000	C:\WINDOWS\System32\Normaliz.dll	Unicode Normalization DLL	10.0.22621.1	Microsoft Corporation	
75	clbcatq.dll	0x7FFBF69A0000	0xB0000	C:\WINDOWS\System32\clbcatq.dll	COM+ Configuration Catalog	2001.12.10941.16384	Microsoft Corporation	
76	wbemprox.dll	0x7FFBED090000	0x10000	C:\WINDOWS\system32\wbem\wbemprox.dll	WMI	10.0.22621.3672	Microsoft Corporation	
77	wbemcomn.dll	0x7FFBED010000	0x80000	C:\WINDOWS\SYSTEM32\wbemcomn.dll	WMI	10.0.22621.2506	Microsoft Corporation	
78	wbemsvc.dll	0x7FFBE9A50000	0x14000	C:\WINDOWS\system32\wbem\wbemsvc.dll	WMI	10.0.22621.3672	Microsoft Corporation	
79	fastprox.dll	0x7FFBE9A70000	0xF8000	C:\WINDOWS\system32\wbem\fastprox.dll	WMI Custom Marshaller	10.0.22621.4391	Microsoft Corporation	
80	amsi.dll	0x7FFBE54C0000	0x1D000	C:\WINDOWS\SYSTEM32\amsi.dll	Anti-Malware Scan Interface	10.0.22621.3527	Microsoft Corporation	
81	USERENV.dll	0x7FFBF5050000	0x28000	C:\WINDOWS\SYSTEM32\USERENV.dll	Userenv	10.0.22621.3527	Microsoft Corporation	
82	dhcpcsvc6.DLL	0x7FFBF0380000	0x19000	C:\WINDOWS\SYSTEM32\dhcpcsvc6.DLL	DHCPv6 客户端	10.0.22621.2506	Microsoft Corporation	
83	jna9691996989552144293.dll	0x7FFB801A0000	0x44000	C:\Users\Administrator\AppData\Local\Temp\jna-146731693\jna9691996989552144293.dll	JNA native library	6.1.1.0	Java(TM) Native Access (JNA)	
84	Pdh.dll	0x7FFBD0A70000	0x50000	C:\WINDOWS\SYSTEM32\Pdh.dll	Windows 性能数据助手 DLL	10.0.22621.4391	Microsoft Corporation	
85	perfos.dll	0x7FFBD9F70000	0x10000	C:\WINDOWS\System32\perfos.dll	Windows 系统性能对象 DLL	10.0.22621.1	Microsoft Corporation	
86	pfclient.dll	0x7FFBF2130000	0x10000	C:\WINDOWS\SYSTEM32\pfclient.dll	SysMain Client	10.0.22621.1	Microsoft Corporation	
87	lwjgl.dll	0x7FFB7BA70000	0x72000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\lwjgl.dll				
88	glfw.dll	0x7FFB79F50000	0x5E000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\glfw.dll				
89	uxtheme.dll	0x7FFBF1F50000	0xB1000	C:\WINDOWS\system32\uxtheme.dll	Microsoft UxTheme 库	10.0.22621.4391	Microsoft Corporation	
90	dinput8.dll	0x7FFB7AC50000	0x46000	C:\WINDOWS\SYSTEM32\dinput8.dll	Microsoft DirectInput	10.0.22621.1	Microsoft Corporation	
91	xinput1_4.dll	0x7FFBB2720000	0x11000	C:\WINDOWS\SYSTEM32\xinput1_4.dll	Microsoft 公共控制器 API	10.0.22621.1	Microsoft Corporation	
92	DEVOBJ.dll	0x7FFBF56C0000	0x2C000	C:\WINDOWS\SYSTEM32\DEVOBJ.dll	Device Information Set DLL	10.0.22621.2506	Microsoft Corporation	
93	inputhost.dll	0x7FFBDCC90000	0x213000	C:\WINDOWS\SYSTEM32\inputhost.dll	InputHost	10.0.22621.4391	Microsoft Corporation	
94	CoreMessaging.dll	0x7FFBF14A0000	0x133000	C:\WINDOWS\SYSTEM32\CoreMessaging.dll	Microsoft CoreMessaging Dll	10.0.22621.4391	Microsoft Corporation	
95	dwmapi.dll	0x7FFBF2170000	0x2B000	C:\WINDOWS\SYSTEM32\dwmapi.dll	Microsoft 桌面窗口管理器 API	10.0.22621.4391	Microsoft Corporation	
96	MSCTF.dll	0x7FFBF8120000	0x160000	C:\WINDOWS\System32\MSCTF.dll	MSCTF 服务器 DLL	10.0.22621.4391	Microsoft Corporation	
97	HID.DLL	0x7FFBF4200000	0xE000	C:\WINDOWS\SYSTEM32\HID.DLL	Hid 用户库	10.0.22621.1	Microsoft Corporation	
98	opengl32.dll	0x7FFB61F20000	0x100000	C:\WINDOWS\SYSTEM32\opengl32.dll	OpenGL Client DLL	10.0.22621.4391	Microsoft Corporation	
99	GLU32.dll	0x7FFBD14B0000	0x2D000	C:\WINDOWS\SYSTEM32\GLU32.dll	OpenGL 实用工具库 DLL	10.0.22621.2506	Microsoft Corporation	
100	dxcore.dll	0x7FFBF24F0000	0x37000	C:\WINDOWS\SYSTEM32\dxcore.dll	DXCore	10.0.22621.4391	Microsoft Corporation	
101	AppXDeploymentClient.dll	0x7FFBEF1A0000	0x144000	C:\Windows\System32\AppXDeploymentClient.dll	AppX 部署客户端 DLL	10.0.22621.4391	Microsoft Corporation	
102	nvoglv64.dll	0x7FFB4BEA0000	0x2638000	C:\WINDOWS\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_9425e4c3b1ac1c47\nvoglv64.dll	NVIDIA Compatible OpenGL ICD	32.0.15.6636	NVIDIA Corporation	
103	cryptnet.dll	0x7FFBECEF0000	0x32000	C:\WINDOWS\SYSTEM32\cryptnet.dll	Crypto Network Related API	10.0.22621.1	Microsoft Corporation	
104	wldp.dll	0x7FFBF5260000	0x49000	C:\WINDOWS\SYSTEM32\wldp.dll	Windows 锁定策略	10.0.22621.4036	Microsoft Corporation	
105	drvstore.dll	0x7FFBECD80000	0x162000	C:\WINDOWS\SYSTEM32\drvstore.dll	Driver Store API	10.0.22621.4391	Microsoft Corporation	
106	imagehlp.dll	0x7FFBF78C0000	0x1F000	C:\WINDOWS\System32\imagehlp.dll	Windows NT Image Helper	10.0.22621.1	Microsoft Corporation	
107	nvgpucomp64.dll	0x7FFBE6CA0000	0x2D10000	C:\WINDOWS\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_9425e4c3b1ac1c47\nvgpucomp64.dll	NVIDIA GPU Compiler Driver, Version 566.36	 32.0.15.6636	NVIDIA Corporation	
108	nvspcap64.dll	0x7FFBB23E0000	0x2FB000	C:\WINDOWS\system32\nvspcap64.dll	NVIDIA Game Proxy	11.0.1.184	NVIDIA Corporation	
109	powrprof.dll	0x7FFBF4840000	0x4D000	C:\WINDOWS\SYSTEM32\powrprof.dll	电源配置文件帮助程序 DLL	10.0.22621.3958	Microsoft Corporation	
110	UMPDC.dll	0x7FFBF4820000	0x13000	C:\WINDOWS\SYSTEM32\UMPDC.dll	User Mode Power Dependency Coordinator	10.0.22621.1	Microsoft Corporation	
111	WINSTA.dll	0x7FFBF4450000	0x66000	C:\WINDOWS\SYSTEM32\WINSTA.dll	Winstation Library	10.0.22621.4391	Microsoft Corporation	
112	textinputframework.dll	0x7FFBDCB40000	0x145000	C:\WINDOWS\SYSTEM32\textinputframework.dll	"TextInputFramework.DYNLINK"	10.0.22621.4391	Microsoft Corporation	
113	lwjgl_opengl.dll	0x7FFB79DB0000	0x58000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\lwjgl_opengl.dll				
114	lwjgl_stb.dll	0x7FFB76100000	0x7F000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\lwjgl_stb.dll				
115	mscms.dll	0x7FFBEDEE0000	0xBC000	C:\WINDOWS\SYSTEM32\mscms.dll	Microsoft 颜色匹配系统 DLL	10.0.22621.4455	Microsoft Corporation	
116	icm32.dll	0x7FFB813E0000	0x49000	C:\WINDOWS\SYSTEM32\icm32.dll	Microsoft Color Management Module (CMM)	10.0.22621.4455	Microsoft Corporation	
117	sunmscapi.dll	0x7FFBCB880000	0xE000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\sunmscapi.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
118	ncrypt.dll	0x7FFBF5350000	0x2D000	C:\WINDOWS\SYSTEM32\ncrypt.dll	Windows NCrypt 路由器	10.0.22621.4317	Microsoft Corporation	
)";
	constexpr std::string_view part3 = R"(119	NTASN1.dll	0x7FFBF5310000	0x37000	C:\WINDOWS\SYSTEM32\NTASN1.dll	Microsoft ASN.1 API	10.0.22621.1	Microsoft Corporation	
120	perfdisk.dll	0x7FFBCB750000	0x10000	C:\WINDOWS\System32\perfdisk.dll	Windows 磁盘性能对象 DLL	10.0.22621.1	Microsoft Corporation	
121	WMICLNT.dll	0x7FFBEFF10000	0x11000	C:\WINDOWS\System32\WMICLNT.dll	WMI Client API	10.0.22621.1	Microsoft Corporation	
122	gpapi.dll	0x7FFBF4FF0000	0x26000	C:\WINDOWS\SYSTEM32\gpapi.dll	组策略客户端 API	10.0.22621.3810	Microsoft Corporation	
123	WINNSI.DLL	0x7FFBF20F0000	0xD000	C:\WINDOWS\SYSTEM32\WINNSI.DLL	Network Store Information RPC interface	10.0.22621.1	Microsoft Corporation	
124	OpenAL.dll	0x7FFB4F980000	0x114000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\OpenAL.dll				
125	MMDevApi.dll	0x7FFBE4AB0000	0x9E000	C:\WINDOWS\System32\MMDevApi.dll	MMDevice API	10.0.22621.4111	Microsoft Corporation	
126	SAPIWrapper_x64.dll	0x7FFBAC040000	0x1A000	D:\MCLDownload\Game\.minecraft\versions\1.18\natives\SAPIWrapper_x64.dll				
127	sapi.dll	0x7FFB4EE70000	0x182000	C:\WINDOWS\System32\Speech\Common\sapi.dll	语音 API	5.3.29816.0	Microsoft Corporation	
128	AUDIOSES.DLL	0x7FFBD7600000	0x1ED000	C:\WINDOWS\SYSTEM32\AUDIOSES.DLL	音频会话	10.0.22621.4391	Microsoft Corporation	
129	resourcepolicyclient.dll	0x7FFBF24D0000	0x15000	C:\WINDOWS\SYSTEM32\resourcepolicyclient.dll	Resource Policy Client	10.0.22621.3527	Microsoft Corporation	
130	wshunix.dll	0x7FFBDA400000	0x8000	C:\WINDOWS\system32\wshunix.dll	AF_UNIX Winsock2 Helper DLL	10.0.22621.1	Microsoft Corporation	
131	CoreUIComponents.dll	0x7FFBEF360000	0x36D000	C:\WINDOWS\SYSTEM32\CoreUIComponents.dll	Microsoft Core UI Components Dll	10.0.22621.4391	Microsoft Corporation	
132	awt.dll	0x7FFB40A10000	0x18E000	D:\MCLDownload\ext\jre-v64-220420\jdk17\bin\awt.dll	OpenJDK Platform binary	17.0.2.0	Eclipse Adoptium	
133	apphelp.dll	0x7FFBF1940000	0x97000	C:\WINDOWS\SYSTEM32\apphelp.dll	应用程序兼容性客户端库	10.0.22621.4391	Microsoft Corporation	
134	javaw.exe	0x7FFBF1940000	0x97000	C:\WINDOWS\SYSTEM32\apphelp.dll	应用程序兼容性客户端库	10.0.22621.4391	Microsoft Corporation)";
	module_infos = parse_modules({part1, part2, part3});
	/*
	int index;
	std::string name;
	std::string baseAddress;
	std::string size;
	std::string path;
	std::string description;
	std::string version;
	std::string company;
	*/
	/*for (const auto& module : module_infos) {
		std::cout << "\nIndex: " << module.index << ", Name: " << module.name << ",Path: " << module.path
			<< "\nBaseAddress:" << module.baseAddress << ",Size:" << module.size
			<< "\nDescription:" << module.description << ",Version:" << module.version << ",Company" << module.company << std::endl;
	}*/

	write_clean_modules_if_needed();
	// 如果用户已经提供了自定义的 clean_modules.txt，这里会覆盖内置基线
	load_clean_modules_if_exists();

	HMODULE hK32 = utils::find_or_load_library("kernel32.dll");
	Orig_CreateProcessW = reinterpret_cast<decltype(Orig_CreateProcessW)>(GetProcAddress(hK32, "CreateProcessW"));
	Orig_Module32NextW = reinterpret_cast<DefOrig_Module32NextW>(GetProcAddress(hK32, "Module32NextW"));
	Orig_WTSEnumerateProcessesExW = reinterpret_cast<DefOrig_WTSEnumerateProcessesW>(GetProcAddress(utils::find_or_load_library("wtsapi32.dll"), "WTSEnumerateProcessesExW"));
	HMODULE hPsapi = utils::find_or_load_library("Psapi.dll");
	Orig_EnumProcessModules = reinterpret_cast<decltype(&K32EnumProcessModules)>(GetProcAddress(hPsapi, "EnumProcessModules"));
	g_orig_GetModuleFileNameExW = reinterpret_cast<decltype(g_orig_GetModuleFileNameExW)>(GetProcAddress(hPsapi, "GetModuleFileNameExW"));

	DetourAttach(&(PVOID&)Orig_CreateProcessW, hk_CreateProcessW);
	DetourAttach(&(PVOID&)g_orig_GetModuleFileNameExW, hk_GetModuleFileNameExW);
	DetourAttach(&(PVOID&)Orig_EnumProcessModules, detour_EnumProcessModules);
	DetourAttach(&(PVOID&)Orig_Module32NextW, hk_Module32NextW);
	DetourAttach(&(PVOID&)Orig_WTSEnumerateProcessesExW, hk_WTSEnumerateProcessesW);
}