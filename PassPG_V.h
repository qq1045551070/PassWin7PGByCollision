#pragma once

// V 校的时间回溯方式过 PG
#ifndef PASSPG_V
#define PASSPG_V

#include "DriverEntry.h"

// 初始化函数
VOID PassPG_V_Init();

// 初始化 DPC 回调函数
VOID PassPG_V_InitDpc(PKDEFERRED_ROUTINE DpcRoutine);

#endif
