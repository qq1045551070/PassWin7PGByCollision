#include "PassPG_V.h"
#include "Over_Tools.h"
#include "Asm.h"

ULONG_PTR g_KiRetireDpcListAddress;

// Dpc �ص�
VOID PassPG_V_DpcRoutine(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	g_KiRetireDpcListAddress = GetKiRetireDpcList();
	ULONG_PTR dwKiRetireDpcListEnd = g_KiRetireDpcListAddress;
	UCHAR * i = NULL;

	

}

// ��ʼ������
VOID PassPG_V_Init()
{
	PassPG_V_InitDpc(PassPG_V_DpcRoutine);
}

// ��ʼ�� DPC �ص�����
VOID PassPG_V_InitDpc(PKDEFERRED_ROUTINE DpcRoutine)
{
	// ��ʼ�� DPC �ṹ��
	PKDPC dwDpc = (PKDPC)sfExAllocate(sizeof(KDPC));
	RtlZeroMemory(dwDpc, sizeof(KDPC));
	KeInitializeDpc(dwDpc, DpcRoutine, NULL);
	KeInsertQueueDpc(dwDpc, NULL, NULL);
}
