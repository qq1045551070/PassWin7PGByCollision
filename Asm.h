#ifndef ASM
#define ASM

#include "DriverEntry.h"

// ��ȡ KiRetireDpcList ������ַ
extern ULONG64 GetKiRetireDpcList();

extern void AsmModifyCode(PVOID szTargetAddress, PVOID JmpCode);

// ��д INT 1 �жϺ���
extern void MyKiDebugTrapOrFault();

// ROR ����
extern ULONG_PTR __ROR64(ULONG_PTR FollowContextKey, UCHAR RorBit);

// BTC ����
extern ULONG_PTR __BTC64(ULONG_PTR FollowContextKey);

#endif