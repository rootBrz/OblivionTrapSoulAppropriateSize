#include "main.h"
#include "MinHook.h"
#include "utils.h"
#include <cstdint>
#include <cstdio>
#include <memoryapi.h>
#include <minwindef.h>
#include <process.h>
#include <processthreadsapi.h>
#include <windows.h>

extern "C" void *oFunc;
void *oFunc = nullptr;

static void Hook(void) __attribute__((naked));
static void Hook(void)
{
  __asm__ volatile(
      ".intel_syntax noprefix\n\t"
      "cvtdq2ps xmm6,xmm6\n\t"
      "lahf\n\t"
      "cmp WORD PTR [rbp+0x10], 0x193\n\t"
      "jne 1f\n\t"
      "movss xmm6, xmm7\n\t"
      "1:\n\t"
      "sahf\n\t"
      "jmp oFunc[rip]\n\t"
      ".att_syntax prefix\n\t"
      :
      :
      : "cc", "memory", "xmm6");
}

unsigned int __stdcall InitThread(void *)
{
  FILE *log = fopen(LOG_NAME, "w");

  // .text:0000000146671B68  0F 5B F6  cvtdq2ps SoulGemSize, SoulGemSize <--
  // .text:0000000146671B6B  0F 2F F7  comiss  SoulGemSize, SoulSize
  // .text:0000000146671B6E  72 32     jb      short loc_146671BA2
  void *comissAddr = (void *)(FindPattern("0F 2F F7 72 32 48 85 FF 74 18 0F B6 8F") - 3);

  fprintf(log, "Found address: 0x%p\n", comissAddr);
  fclose(log);

  // NOP cvtdq2ps instruction
  unsigned char patchNop[] = {0x90, 0x90, 0x90};
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)((uintptr_t)comissAddr), patchNop, sizeof(patchNop), NULL);

  MH_Initialize();
  MH_CreateHook(comissAddr, (LPVOID)Hook, &oFunc);
  MH_EnableHook(comissAddr);

  // NOP F7 byte and replace jb to jne
  unsigned char patch[] = {0x90, 0x75};
  WriteProcessMemory(GetCurrentProcess(), (LPVOID)((uintptr_t)comissAddr + 5), patch, sizeof(patch), NULL);

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
