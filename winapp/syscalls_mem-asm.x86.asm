.686
.XMM
.MODEL flat, c
ASSUME fs:_DATA
.code

EXTERN SW3_GetSyscallNumber: PROC
EXTERN local_is_wow64: PROC
EXTERN internal_cleancall_wow64_gate: PROC

NtSuspendProcess PROC
		push ebp
		mov ebp, esp
		push 059993788h                  ; Load function hash into ECX.
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_59993788:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_59993788
		mov ecx, eax
		call local_is_wow64
		test eax, eax
		je is_native
		call internal_cleancall_wow64_gate
		push ret_address_epilog_59993788
		push ret_address_epilog_59993788
		xchg eax, ecx
		jmp ecx
		jmp finish
	is_native:
		mov eax, ecx
		push ret_address_epilog_59993788
		call do_sysenter_interrupt_59993788
	finish:
		lea esp, [esp+4]
	ret_address_epilog_59993788:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_59993788:
		mov edx, esp
		sysenter
		ret
NtSuspendProcess ENDP

end