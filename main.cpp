#include "main.h"
#include "utils.h"
#include <cstdint>
#include <cstdio>
#include <memoryapi.h>
#include <minwindef.h>
#include <process.h>
#include <processthreadsapi.h>
#include <windows.h>

unsigned int __stdcall InitThread(void *)
{
  FILE *log = fopen(LOG_NAME, "w");

  uintptr_t mainFuncAddr{FindPattern("72 32 48 85 FF 74 18 0F B6 8F")};

  fprintf(log, "Found address: 0x%p\n", (void *)mainFuncAddr);
  fclose(log);

  uint8_t patch[] = {0x75}; // replace jb with jne
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)mainFuncAddr, patch, sizeof(patch), NULL);

  _endthreadex(0);
  return 0;
}

// OBSE
extern "C"
{
  OBSEPluginVersionData OBSEPlugin_Version{
      OBSEPluginVersionData::kVersion,
      10,
      "Precise Soul Capture",
      "rootBrz",
      OBSEPluginVersionData::kAddressIndependence_Signatures,
      OBSEPluginVersionData::kStructureIndependence_NoStructs,
      {},
      {},
      {},
      {},
      {}};

  bool OBSEPlugin_Load(const OBSEInterface *obse)
  {
    PLUGIN_HANDLE = obse->GetPluginHandle();
    OBSE_MESSAGE = (OBSEMessagingInterface *)obse->QueryInterface(kInterface_Messaging);

    return true;
  }
};
