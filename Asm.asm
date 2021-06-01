
.code

AsmModifyCode proc
	push rdx;
	push rax;
	push rdi;
	push rsi;

	mov rdi, rcx;
	mov rsi, rdx;

	; 清空 rdx, rax
	mov rdx, 0h;
	mov rax, 0h;
	; 读取 JmpCode
	CMPXCHG16B [rsi];
	; Modify 目标内存
	CMPXCHG16B [rdi];

	pop rsi;
	pop rdi;
	pop rax;
	pop rdx;
	ret;
AsmModifyCode endp

MyKiDebugTrapOrFault proc
	
	swapgs;

	push rsi;
	push rdi;

	; 获取当前进程的 EPROCESS


	pop rdi;
	pop rsi;

MyKiDebugTrapOrFault endp

; X64 ror 操作
__ROR64 proc
	mov rax, rcx; 参数一
	mov rcx, rdx; 参数二
	ror rax, cl;
	ret;
__ROR64 endp

;ULONG_PTR __BTC64(ULONG_PTR FollowContextKey)
__BTC64 proc
	mov rax, rcx
	btc	rax, rax
	ret
__BTC64 endp

GetKiRetireDpcList proc
	; 这里为什么是加上0x40呢，因为通过IDA我发现在DPC函数中
	; 调用这个函数的时候会有一行sub rsp,38h的指令
	mov rax, rsp;
	add rax, 40h;
	mov rax, [rax];  获取 KiRetireDpcList 函数地址
	ret;
GetKiRetireDpcList endp

end