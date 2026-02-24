#include "hwid_profile.h"
#include "picosha2.h"
#include <regex>
static int get_num(const std::string& str);
static std::string sha1(const std::string& str);
static std::string format_core(const std::string& abbreviation);

struct CPU_INFO
{
	std::string name;
	std::string device;
	std::string model;
	std::string identifier;
};
const std::vector<CPU_INFO> CPU_INFOS = {
	{"i9-11900K ","BFEBFBFF000A0671","11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz","Family 6 Model 167 Stepping 1"},
	{"i7-12700K","BFEBFBFF00090672","12th Gen Intel(R) Core(TM) i7-12700K","Family 6 Model 151 Stepping 2"},
	{"i7-11700K","BFEBFBFF000A0671","11th Gen Intel(R) Core(TM) i5-11600K @ 3.90GHz","Family 6 Model 167 Stepping 1"},
	{"i7-10850K","BFEBFBFF000A0655","Intel(R) Core(TM) i7-10850K CPU @ 3.60GHz","Family 6 Model 165 Stepping 5"},
	{"i7-10750H","BFEBFBFF000A0652","Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz","Family 6 Model 165 Stepping 2"},
	{"i7-10700K","BFEBFBFF000A0654","Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz","Family 6 Model 165 Stepping 5"},
	{"i7-10700","BFEBFBFF000A0654","Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz","Family 6 Model 165 Stepping 5"},
	{"i7-9700K","BFEBFBFF000906EC","Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz","Family 6 Model 158 Stepping 13"},
	{"i7-9700K","BFEBFBFF000906EC","Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz","Family 6 Model 158 Stepping 12"},
	{"i7-9700","BFEBFBFF000906ED","Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz","Family 6 Model 158 Stepping 13"},
	{"i7-9700F","BFEBFBFF000906ED","Intel(R) Core(TM) i7-9700F CPU @ 3.00GHz","Family 6 Model 158 Stepping 13"},
	{"i7-8700K","BFEBFBFF000906EA","Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz","Family 6 Model 158 Stepping 10"},
	{"i7-8700","BFEBFBFF000906EA","Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz","Family 6 Model 158 Stepping 10"},
	{"i7-8700T","BFEBFBFF000906EA","Intel(R) Core(TM) i7-8700T CPU @ 2.40GHz","Family 6 Model 158 Stepping 10"},
	{"i7-6700K","BFEBFBFF000506E3","Intel(R) Core(TM) i5-6700K CPU @ 4.00GHz","Family 6 Model 94 Stepping 3"},
	{"i5-12500","BFEBFBFF00090672","12th Gen Intel(R) Core(TM) i5-12500","Family 6 Model 151 Stepping 5"},
	{"i5-11400F","BFEBFBFF000A0671","11th Gen Intel(R) Core(TM) i5-11400F @ 2.60GHz","Family 6 Model 167 Stepping 1"},
	{"i5-11400H","BFEBFBFF000806D1","11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz",},
	{"i5-10500","BFEBFBFF000A0655","Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz","Family 6 Model 165 Stepping 3"},
	{"i5-10400F","BFEBFBFF000A0650","Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz","Family 6 Model 165 Stepping 3"},
	{"i5-9600K","BFEBFBFF000906EC","Intel(R) Core(TM) i5-9600K CPU @ 3.70GHz","Family 6 Model 158 Stepping 13"},
	{"i5-9600KF","BFEBFBFF000906EC","11th Gen Intel(R) Core(TM) i5-9600KF @ 3.70GHz","Family 6 Model 158 Stepping 13"},
	{"i5-9500","BFEBFBFF000906EA","Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz","Family 6 Model 158 Stepping 10"},
	{"i5-1035G1","BFEBFBFF000706E5","Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz","Family 6 Model 126 Stepping 5"},
	{"i5-10210U","BFEBFBFF000806EC","Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz","Family 6 Model 142 Stepping 12"},
	{"i5-9400","BFEBFBFF000906EA","Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz","Family 6 Model 158 Stepping 13"},
	{"i5-9400F","BFEBFBFF000906EA","Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz","Family 6 Model 158 Stepping 10"},
	{"Ryzen 9 7950X","178BFBFF00A60F12","AMD Ryzen 9 7950X 16-Core Processor","Family 25 Model 97 Stepping 2"},
	{"Ryzen 5 7600X","178BFBFF00A60F12","AMD Ryzen 5 7600X 6-Core Processor","Family 25 Model 97 Stepping 2"},
	{"Ryzen 9 9950X","178BFBFF00B40F40","AMD Ryzen 9 9950X 16-Core Processor","Family 26 Model 68 Stepping 0"},
	{"Ryzen 9 7950X3D","178BFBFF00A60F12","AMD Ryzen 9 7950X3D 16-Core Processor","Family 25 Model 97 Stepping 2"},
	{"Ryzen 9 7900X3D","178BFBFF00A60F12","AMD Ryzen 9 7900X3D 12-Core Processor","Family 25 Model 97 Stepping 2"},
	{"Ryzen 9 3950X","178BFBFF00A60F12","AMD Ryzen 9 3950X3D 16-Core Processor","Family 23 Model 110 Stepping 0"},
};


const std::vector<std::string> MANUFACTURER = {
	"Micro-Star International Co., Ltd.", "COLORFUL", "HUAWEI",
	"ASUS", "Gigabyte", "Not Applicable", "HASEE", "Lenovo",
	"HP", "Dell"
};

const std::vector<std::string> VERSIONS = {
	"P??I", "A??", "B??", "C??", "m??", "R??",
	"Not Applicable", "unknown", "??", "Z??", "??"
};

std::vector<std::string> wifi_names_1 = {
		"Realtek PCIe GbE Family Controller-WFP Native MAC Layer LightWeight Filter-0000",
		"Realtek PCIe GbE Family Controller-Npcap Packet Driver (NPCAP)-0000",
		"Realtek PCIe GbE Family Controller-QoS Packet Scheduler-0000",
		"Realtek PCIe GbE Family Controller-WFP 802.3 MAC Layer LightWeight Filter-0000"
};


std::vector<std::string> wifi_names_2 = {
		"Microsoft Wi-Fi Direct Virtual Adapter-WFP Native MAC Layer LightWeight Filter-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter-Native WiFi Filter Driver-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter-Npcap Packet Driver (NPCAP)-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter-QoS Packet Scheduler-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter-WFP 802.3 MAC Layer LightWeight Filter-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter #2-WFP Native MAC Layer LightWeight Filter-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter #2-Native WiFi Filter Driver-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter #2-Npcap Packet Driver (NPCAP)-0000",
		"Microsoft Wi-Fi Direct Virtual Adapter #2-QoS Packet Scheduler-0000"
};

std::vector<std::string> wifi_names_3 = {
		"Intel(R) Wi-Fi 6 AX101",
		"Intel(R) Wi-Fi 6 AX200 160MHz",
		"Intel(R) Wi-Fi 6 AX201 160MHz",
		"Intel(R) Wi-Fi 6 AX203",
		"Intel(R) Wi-Fi 6 AX204 160MHz",
		"Killer(R) Wi-Fi 6 AX1650w 160MHz Wireless Network Adapter (200D2W)",
		"Killer(R) Wi-Fi 6 AX1650x 160MHz Wireless Network Adapter (200NGW)",
		"Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201D2W)",
		"Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)"
};
static std::vector<std::string>disk_names = {
	"SAMSUNG MZVKW512HMJP-000H1",
	"SAMSUNG MZVL21T0HCLR-00B00",
	"Samsung SSD 990 EVO Plus 4TB",
	"KINGSTON SV300S37A480G",
	"WD_BLACK SN850X 2000GB",
	"Samsung SSD 990 PRO 2TB",
	"Samsung SSD 850 EVO 1TB",
	"NVMe ADATA SX8200PNP",
	"KINGSTON SKC400S371T",
	"Samsung SSD 980 500GB",
	"Sabrent ROCKET 4.0 2TB",
	"INTEL SSDPEKNW010T8",
	"WDS500G3X0C-00SJG0",
	"NVMe CT1000T700SSD3",
	"WD_BLACK SN850 1TB",
	"HP SSD EX950 512GB",
	"ZTSSDPG3-480G-GE",
	"KINGSTON SHSS37A",
	"SanDisk SDSSDHP2",
	"ADATA SX8200NP",
	"CT2000T705SSD3",
	"CT1000P1SSD8",
	"ADATA SU800",
	"ADATA SP550",
	"R3SL480G",
};
#include "md5.h"
#include "strutils.h"
#include <format>
hwid_profile::hwid_profile(const std::string& uuid)
{
	auto id = get_num(picosha2::hash256_hex_string(uuid));

	auto hashed_uuid = sha1(uuid);
	cpuid = "BFEBFBFF" + hashed_uuid.substr(0, 8);
	std::transform(cpuid.begin(), cpuid.end(), cpuid.begin(), ::toupper);

	auto cpuid_sha1 = sha1(cpuid);
	auto cpuid_sha256 = picosha2::hash256_hex_string(cpuid);

	cpuid_sha1 = strutil::to_upper(cpuid_sha1);
	cpuid_sha256 = strutil::to_upper(cpuid_sha256);

	cpu_name = CPU_INFOS[id % (CPU_INFOS.size() - 1)].model;
	cpuid = CPU_INFOS[id % (CPU_INFOS.size() - 1)].device;
	cpu_identifier = CPU_INFOS[id % (CPU_INFOS.size() - 1)].identifier;
	disk_model = disk_names[id % (disk_names.size() - 1)];
	//cpu_name = format_core(id % 2 == 0 ? CORE_I5[id % (CORE_I5.size() -1)] : CPU_INFOS[id %( CPU_INFOS.size() -1)].name);

	baseboard_id = id % 2 == 0 ? "/" + MD5(uuid).toStr().substr(0, 7) + "/" + picosha2::hash256_hex_string(uuid).substr(0, 14) + "/" : "/" + MD5(uuid).toStr().substr(0, 15);

	version = std::string(VERSIONS[id % (VERSIONS.size() - 1)]);

	strutil::replace_all(version, "??", sha1(std::to_string(id)).substr(10, 12));
	manufacturer = MANUFACTURER[id % (MANUFACTURER.size() - 1)];
	disk = id % 2 == 0 ? std::format("{}_{}_{}_{}_{}_{}_{}_{}.", cpuid_sha1.substr(0, 4), cpuid_sha1.substr(4, 4), cpuid_sha1.substr(8, 4), cpuid_sha1.substr(12, 4), cpuid_sha1.substr(16, 4), cpuid_sha1.substr(20, 4), cpuid_sha1.substr(24, 4), cpuid_sha1.substr(28, 4)) : std::format("{}_{}_{}_{}.", cpuid_sha1.substr(16, 4), cpuid_sha1.substr(20, 4), cpuid_sha1.substr(24, 4), cpuid_sha1.substr(28, 4));

	mac_seed = sha1(uuid);
	new_uuid = std::format("{}-{}-{}-{}-{}", cpuid_sha256.substr(0, 8), cpuid_sha256.substr(8, 4), cpuid_sha256.substr(12, 4), cpuid_sha256.substr(16, 4), cpuid_sha256.substr(20, 12));

}

std::string hwid_profile::get_disk_model(unsigned int factor)
{
	
	return disk_names[factor % (disk_names.size() - 1)];
}

int get_num(const std::string& str) {
	std::regex regex(R"(\d+)");
	std::smatch match;

	if (std::regex_search(str, match, regex)) {
		return std::stoi(match.str());
	}
	return 0;
}
#include "sha1.hpp"
std::string sha1(const std::string& str)
{
	SHA1 hasher;
	hasher.update(str);
	return hasher.final();
}
static std::string get_generation(const std::string& abbreviation) {
	std::regex pattern("[A-Za-z]+(\\d+)");
	std::smatch match;

	if (std::regex_search(abbreviation, match, pattern)) {
		int gen = std::stoi(match[1].str());
		return std::to_string(gen);
	}
	return "Unknown";
}

static std::string get_model(const std::string& abbreviation) {
	std::regex pattern("([A-Za-z]+)\\d+");
	std::smatch match;

	if (std::regex_search(abbreviation, match, pattern)) {
		return match[1];
	}
	return "Unknown";
}

static std::string find_generation(const std::string& cpuModel) {
	std::regex regex("i[0-9]+-(\\d+)");
	std::smatch matcher;

	if (std::regex_search(cpuModel, matcher, regex)) {
		int gen = std::stoi(matcher[1].str().substr(0, 2));

		if (gen > 15) {
			return std::to_string(gen).substr(0, 1);
		}
		else {
			return std::to_string(gen);
		}
	}
	else {
		return "1";
	}
}
std::string format_core(const std::string& abbreviation)
{
	std::istringstream iss(abbreviation);
	std::string part;
	std::vector<std::string> parts;

	while (std::getline(iss, part, '-')) {
		parts.push_back(part);
	}

	if (parts.empty()) {
		return "Invalid abbreviation";
	}

	std::string generation = get_generation(parts[0]);
	std::string model = get_model(parts[0]);
	return find_generation(abbreviation) + "th Gen Intel(R) Core(TM) " + model + generation + "-" + parts[1];
}
