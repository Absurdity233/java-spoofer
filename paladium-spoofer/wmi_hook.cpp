
#include <WbemIdl.h>
#include <iomanip>
#include <vector>
#include <fstream>
#include <optional>
#include <functional>
#include "utils.h"
#include "wmi_hook.hpp"
#include "detours.h"
#include "heypixel_shit.h"

namespace wmi_hook
{

	struct pass
	{
		std::wstring class_name;
		std::wstring wsz_name;
		std::function<std::wstring(const std::wstring& value)> lambda;
		pass(
			const std::wstring& class_name,
			const std::wstring& wsz_name,
			const std::function<std::wstring(const std::wstring&)>& lambda
		) : class_name(class_name),
			wsz_name(wsz_name),
			lambda(lambda) {}
	};



	typedef HRESULT(__stdcall* tGetFunc)(
		IWbemClassObject* pThis,
		LPCWSTR wszName,
		LONG lFlags,
		VARIANT* pVal,
		CIMTYPE* pType,
		long* plFlavor
		);

	static tGetFunc original_get_func = NULL;

	static std::wstring unique_hash_value;
	static std::vector<pass> passes;
	static std::optional<std::function<std::wstring(const std::wstring&)>> try_get_spoof_lambda(LPCWSTR class_name, LPCWSTR wsz_name)
	{
		for (auto& pass : passes)
		{
			if (lstrcmpiW(pass.class_name.c_str(), class_name) == 0 and lstrcmpiW(pass.wsz_name.c_str(), wsz_name) == 0)
			{
				return std::make_optional(pass.lambda);
			}

		}

		return std::nullopt;
	}
	static auto CIMTypeToString = [](CIMTYPE type) {
		switch (type) {
		case CIM_ILLEGAL: return "CIM_ILLEGAL";
		case CIM_EMPTY: return "CIM_EMPTY";
		case CIM_SINT8: return "CIM_SINT8";
		case CIM_UINT8: return "CIM_UINT8";
		case CIM_SINT16: return "CIM_SINT16";
		case CIM_UINT16: return "CIM_UINT16";
		case CIM_SINT32: return "CIM_SINT32";
		case CIM_UINT32: return "CIM_UINT32";
		case CIM_SINT64: return "CIM_SINT64";
		case CIM_UINT64: return "CIM_UINT64";
		case CIM_REAL32: return "CIM_REAL32";
		case CIM_REAL64: return "CIM_REAL64";
		case CIM_BOOLEAN: return "CIM_BOOLEAN";
		case CIM_STRING: return "CIM_STRING";
		case CIM_DATETIME: return "CIM_DATETIME";
		case CIM_REFERENCE: return "CIM_REFERENCE";
		case CIM_CHAR16: return "CIM_CHAR16";
		case CIM_OBJECT: return "CIM_OBJECT";
		case CIM_FLAG_ARRAY: return "CIM_FLAG_ARRAY";
		default: return "Unknown CIM Type";
		}
		};
	static std::ofstream outputFile;
	static HRESULT __stdcall hk_get_func(IWbemClassObject* pThis, LPCWSTR wszName, LONG lFlags, VARIANT* pVal, CIMTYPE* pType, long* plFlavor) {
		CIMTYPE type{};
		if (!pType)
		{
			pType = &type;
		}
		HRESULT hResult = original_get_func(pThis, wszName, lFlags, pVal, pType, plFlavor);

		if (hResult >= WBEM_S_NO_ERROR)
		{
			VARIANT v{};
			VariantInit(&v);
			std::wstring class_name;
			auto hr = original_get_func(pThis, L"__CLASS", 0, &v, 0, 0);
			if (SUCCEEDED(hr) && v.vt == VT_BSTR && v.bstrVal) {
				class_name = std::wstring(v.bstrVal);
			}
			VariantClear(&v);

			if (!class_name.empty()) {
				auto pass = try_get_spoof_lambda(class_name.c_str(), wszName);
				if (pass.has_value() && pVal && pVal->vt == VT_BSTR && pVal->bstrVal)
				{
					auto spoofed = pass.value()(pVal->bstrVal);
					SysFreeString(pVal->bstrVal);
					pVal->bstrVal = SysAllocString(spoofed.c_str());
				}
			}
		}

		return hResult;
	}

	void initialize(std::wstring unique_value)
	{
		unique_hash_value = unique_value;

		HMODULE fastprox_module = utils::find_or_load_library("fastprox.dll");
		original_get_func = (tGetFunc)GetProcAddress(fastprox_module, "?Get@CWbemObject@@UEAAJPEBGJPEAUtagVARIANT@@PEAJ2@Z");

		if (!original_get_func)
		{
			system("msg %username% couldn't find wmic get func");
			return;
		}

		DetourAttach(&(PVOID&)original_get_func, hk_get_func);

		passes.push_back(wmi_hook::pass(L"Win32_Processor", L"PROCESSORID", [](auto) -> auto {
			return utils::to_std_wstring(heypixel_shit::profile->cpuid);
			})
		);


		passes.push_back(wmi_hook::pass(L"Win32_BaseBoard", L"SERIALNUMBER", [](const std::wstring& value) -> auto {
			return utils::to_std_wstring(heypixel_shit::calculate(utils::to_std_string(value.c_str()), heypixel_shit::global_factor));
			})
		);
		
		passes.push_back(wmi_hook::pass(L"Win32_BaseBoard", L"MANUFACTURER", [](auto) -> auto {
			return utils::to_std_wstring(heypixel_shit::profile->manufacturer);
			})
		);

		passes.push_back(wmi_hook::pass(L"Win32_BaseBoard", L"VERSION", [](auto) -> auto {
			return utils::to_std_wstring(heypixel_shit::profile->version);
			})
		);

		passes.push_back(wmi_hook::pass(L"Win32_ComputerSystemProduct", L"UUID", [](auto) -> auto {
			return utils::to_std_wstring(heypixel_shit::profile->new_uuid);
			})
		);

		passes.push_back(wmi_hook::pass(L"Win32_DiskDrive", L"SERIALNUMBER", [](const std::wstring& value) -> auto {

			if (utils::wstr_starts_with(value,L"0000"))
			{
				return value;
			}
			return utils::to_std_wstring(heypixel_shit::calculate(utils::to_std_string(value.c_str()), heypixel_shit::global_factor));
			})
		);

		passes.push_back(wmi_hook::pass(L"Win32_DiskDrive", L"MODEL", [](const std::wstring& value) -> auto {
			auto factor = utils::hash_string(value.c_str());
			
			return utils::to_std_wstring(heypixel_shit::profile->get_disk_model(factor));
			})
		);





		// add identifiers that are parsed by paladium's anticheat to the spoof list
		/*
		ids.push_back({ L"BANKLABEL", [](LPCWSTR)-> std::wstring {
			return utils::to_std_wstring(heypixel_shit::profile->baseboard_id);
			} });
		*/

		/*
		ids.push_back(L"DRIVERVERSION");
		ids.push_back(L"MANUFACTURER");
		ids.push_back(L"MODEL");
		ids.push_back(L"DESCRIPTION");
		ids.push_back(L"SERIALNUMBER");
		ids.push_back(L"BUILDNUMBER");
		ids.push_back(L"PROCESSORID");
		ids.push_back(L"ANTECEDENT");
		ids.push_back(L"UUID");*/
	}
};