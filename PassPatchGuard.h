#pragma once

// �㷨��ײ��ʽ�� PG
#ifndef PASSPG
#define PASSPG

#include "DriverEntry.h"

// ��ȡ PXE
PULONG64 GetPxeAddress(PVOID addr);

// ��ȡ PDPTE
PULONG64 GetPpeAddress(PVOID addr);

// ��ȡ PDE
PULONG64 GetPdeAddress(PVOID addr);

// ��ȡ PTE
PULONG64 GetPteAddress(PVOID addr);

// ���� PG Context
NTSTATUS SearchPatchGuardContext();

// ��ʼ�ƹ� PG
NTSTATUS StartPassPatchGuard();

// PG Context CmpAppendDllSection �㷨��ײ
// �ж��Ƿ�Ϊ CmpAppendDllSection ����
BOOLEAN PatchGuardCmpDecryByXor(PVOID addr, size_t size);

BOOLEAN PatchGuardCmpDecryByXorWin10(PVOID addr, size_t size);

// PG Context �㷨��ײ
VOID PatchGuardEncryptCode(PUCHAR Context, ULONG_PTR ContextKey, ULONG_PTR ContextSizeOfBytes);

// ���� PG ִ��
ULONG_PTR HookExecPatchGuard(ULONG_PTR Unuse, ULONG_PTR Context);

#endif

