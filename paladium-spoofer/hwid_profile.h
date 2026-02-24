#pragma once
#include <string>
class hwid_profile
{
public:
	hwid_profile(const std::string& uuid);
	std::string get_disk_model(unsigned int factor);
	std::string cpu_identifier;
	std::string cpuid;
	std::string cpu_name;
	std::string manufacturer;

	std::string baseboard_id;
	std::string version;
	std::string disk;
	std::string disk_model;
	std::string mac_seed;
	std::string new_uuid;
};

