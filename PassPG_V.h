#pragma once

// V У��ʱ����ݷ�ʽ�� PG
#ifndef PASSPG_V
#define PASSPG_V

#include "DriverEntry.h"

// ��ʼ������
VOID PassPG_V_Init();

// ��ʼ�� DPC �ص�����
VOID PassPG_V_InitDpc(PKDEFERRED_ROUTINE DpcRoutine);

#endif
