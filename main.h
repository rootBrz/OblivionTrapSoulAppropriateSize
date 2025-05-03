#pragma once

#include "OBSE/obse64/PluginAPI.h"
#include <minwindef.h>

inline constexpr const char *LOG_NAME = "precisesoulcapture.log";
inline OBSEMessagingInterface *OBSE_MESSAGE = nullptr;
inline PluginHandle PLUGIN_HANDLE = kPluginHandle_Invalid;
inline HMODULE DLL_HANDLE = nullptr;

unsigned int __stdcall InitThread(void *param);