#ifndef ASM
#define ASM

#include "DriverEntry.h"

// 获取 KiRetireDpcList 函数地址
extern ULONG64 GetKiRetireDpcList();

extern void AsmModifyCode(PVOID szTargetAddress, PVOID JmpCode);

// 重写 INT 1 中断函数
extern void MyKiDebugTrapOrFault();

// ROR 操作
extern ULONG_PTR __ROR64(ULONG_PTR FollowContextKey, UCHAR RorBit);

// BTC 操作
extern ULONG_PTR __BTC64(ULONG_PTR FollowContextKey);

#endif