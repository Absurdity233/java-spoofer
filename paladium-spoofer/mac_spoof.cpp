#include "mac_spoof.h"
#include "includes.h"
#include "utils.h"
#include "detours.h"
#include "heypixel_shit.h"
#include <iostream>

typedef jbyteArray(JNICALL* GetMacAddr0Func)(JNIEnv*, jclass, jbyteArray, jstring, jint);
static GetMacAddr0Func Orig_GetMacAddr0 = nullptr;

static jbyteArray JNICALL hkGetMacAddr0(JNIEnv* env, jclass caller, jbyteArray addrArray, jstring name, jint index);

void mac_spoof::initialize()
{
	auto hNet = utils::find_or_load_library("net.dll");
	if (!hNet)
	{
		std::cout << "[mizore][mac] net.dll not found, skipping mac spoof" << std::endl;
		return;
	}
	Orig_GetMacAddr0 = (GetMacAddr0Func)GetProcAddress(hNet, "Java_java_net_NetworkInterface_getMacAddr0");
	if (!Orig_GetMacAddr0)
	{
		std::cout << "[mizore][mac] Java_java_net_NetworkInterface_getMacAddr0 not found, skipping mac spoof" << std::endl;
		return;
	}
	DetourAttach(&(PVOID&)Orig_GetMacAddr0, hkGetMacAddr0);
}

jbyteArray JNICALL hkGetMacAddr0(JNIEnv* env, jclass caller, jbyteArray addrArray, jstring name, jint index)
{
	auto result = Orig_GetMacAddr0(env, caller, addrArray, name, index);
	if (!result) return result;
	auto size = env->GetArrayLength(result);
	jbyte* buf = new jbyte[size];
	env->GetByteArrayRegion(result, 0, size, buf);
	for (size_t i = size / 2; i < size; i++)
	{
		buf[i] ^= heypixel_shit::global_factor;
	}
	env->SetByteArrayRegion(result, 0, size, buf);
	delete[] buf;
	return result;
}
