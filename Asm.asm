
.code

AsmModifyCode proc
	push rdx;
	push rax;
	push rdi;
	push rsi;

	mov rdi, rcx;
	mov rsi, rdx;

	; ��� rdx, rax
	mov rdx, 0h;
	mov rax, 0h;
	; ��ȡ JmpCode
	CMPXCHG16B [rsi];
	; Modify Ŀ���ڴ�
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

	; ��ȡ��ǰ���̵� EPROCESS


	pop rdi;
	pop rsi;

MyKiDebugTrapOrFault endp

; X64 ror ����
__ROR64 proc
	mov rax, rcx; ����һ
	mov rcx, rdx; ������
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
	; ����Ϊʲô�Ǽ���0x40�أ���Ϊͨ��IDA�ҷ�����DPC������
	; �������������ʱ�����һ��sub rsp,38h��ָ��
	mov rax, rsp;
	add rax, 40h;
	mov rax, [rax];  ��ȡ KiRetireDpcList ������ַ
	ret;
GetKiRetireDpcList endp

end