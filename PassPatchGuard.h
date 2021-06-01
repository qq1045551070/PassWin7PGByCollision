#pragma once

// 算法碰撞方式过 PG
#ifndef PASSPG
#define PASSPG

#include "DriverEntry.h"

// 获取 PXE
PULONG64 GetPxeAddress(PVOID addr);

// 获取 PDPTE
PULONG64 GetPpeAddress(PVOID addr);

// 获取 PDE
PULONG64 GetPdeAddress(PVOID addr);

// 获取 PTE
PULONG64 GetPteAddress(PVOID addr);

// 搜索 PG Context
NTSTATUS SearchPatchGuardContext();

// 开始绕过 PG
NTSTATUS StartPassPatchGuard();

// PG Context CmpAppendDllSection 算法碰撞
// 判断是否为 CmpAppendDllSection 函数
BOOLEAN PatchGuardCmpDecryByXor(PVOID addr, size_t size);

BOOLEAN PatchGuardCmpDecryByXorWin10(PVOID addr, size_t size);

// PG Context 算法碰撞
VOID PatchGuardEncryptCode(PUCHAR Context, ULONG_PTR ContextKey, ULONG_PTR ContextSizeOfBytes);

// 拦截 PG 执行
ULONG_PTR HookExecPatchGuard(ULONG_PTR Unuse, ULONG_PTR Context);

#endif

