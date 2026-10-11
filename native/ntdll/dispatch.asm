; SPDX-License-Identifier: GPL-2.0-only
;
; native/ntdll/dispatch.asm
; User-mode kernel entry point trampolines and loader init thunk for NT 5.1 x86
;
.386p
.model flat

EXTRN _LdrpInitialize@12:PROC
EXTRN _ZwContinue@8:PROC
EXTRN _ZwCallbackReturn@12:PROC
EXTRN _ZwRaiseException@12:PROC
EXTRN _RtlDispatchException@8:PROC
EXTRN _RtlRaiseException@4:PROC

PcTeb                   EQU 0018h
TebPeb                  EQU 0030h
PebKernelCallbackTable  EQU 002Ch
TbExceptionCode         EQU 01A4h

ErExceptionCode         EQU 0000h
ErExceptionFlags        EQU 0004h
ErExceptionRecord       EQU 0008h
ErExceptionAddress      EQU 000Ch
ErNumberParameters      EQU 0010h
ExceptionRecordSize     EQU 0050h
EXCEPTION_NONCONTINUABLE EQU 0001h

_TEXT SEGMENT DWORD PUBLIC 'CODE'
ASSUME DS:FLAT, ES:FLAT, SS:NOTHING, FS:NOTHING, GS:NOTHING

;------------------------------------------------------------------------------
; VOID NTAPI LdrInitializeThunk(
;     PVOID NormalContext,
;     PVOID SystemArgument1,
;     PVOID SystemArgument2,
;     CONTEXT ContinueContext
; )
;------------------------------------------------------------------------------
ALIGN 4
PUBLIC _LdrInitializeThunk@16
_LdrInitializeThunk@16 PROC NEAR
    lea     eax, [esp + 16]         ; Compute pointer to CONTEXT on stack
    mov     [esp + 4], eax          ; Replace NormalContext with &Context
    xor     ebp, ebp
    jmp     _LdrpInitialize@12
_LdrInitializeThunk@16 ENDP

;------------------------------------------------------------------------------
; BOOLEAN NTAPI LdrpCallInitRoutine(
;     PDLL_INIT_ROUTINE InitRoutine,
;     PVOID DllHandle,
;     ULONG Reason,
;     PCONTEXT Context
; )
;------------------------------------------------------------------------------
ALIGN 4
PUBLIC _LdrpCallInitRoutine@16
_LdrpCallInitRoutine@16 PROC NEAR
    push    ebp
    mov     ebp, esp
    push    esi
    push    edi
    push    ebx
    mov     esi, esp
    push    dword ptr [ebp + 20]    ; Context
    push    dword ptr [ebp + 16]    ; Reason
    push    dword ptr [ebp + 12]    ; DllHandle
    call    dword ptr [ebp + 8]     ; InitRoutine
    mov     esp, esi
    pop     ebx
    pop     edi
    pop     esi
    pop     ebp
    ret     16
_LdrpCallInitRoutine@16 ENDP

;------------------------------------------------------------------------------
; VOID NTAPI KiUserApcDispatcher(
;     PKNORMAL_ROUTINE NormalRoutine,
;     PVOID NormalContext,
;     PVOID SystemArgument1,
;     PVOID SystemArgument2,
;     CONTEXT ContinueContext
; )
;------------------------------------------------------------------------------
ALIGN 4
PUBLIC _KiUserApcDispatcher@20
_KiUserApcDispatcher@20 PROC NEAR
    lea     edi, [esp + 16]         ; edi -> ContinueContext
    pop     eax                     ; eax = NormalRoutine
    call    eax                     ; Call NormalRoutine(NormalContext, SysArg1, SysArg2)
    push    1                       ; TestAlert = TRUE
    push    edi                     ; ContinueContext
    call    _ZwContinue@8
    ret
_KiUserApcDispatcher@20 ENDP

;------------------------------------------------------------------------------
; VOID NTAPI KiUserCallbackDispatcher(
;     ULONG ApiNumber,
;     PVOID InputBuffer,
;     ULONG InputLength
; )
;------------------------------------------------------------------------------
ALIGN 4
PUBLIC _KiUserCallbackDispatcher@12
_KiUserCallbackDispatcher@12 PROC NEAR
    add     esp, 4                  ; Skip return address
    pop     edx                     ; edx = ApiNumber
    mov     eax, fs:[PcTeb]
    mov     eax, [eax + TebPeb]
    mov     eax, [eax + PebKernelCallbackTable]
    call    dword ptr [eax + edx*4]
    xor     ecx, ecx
    xor     edx, edx
    int     2bh
    int     3
_KiUserCallbackDispatcher@12 ENDP

;------------------------------------------------------------------------------
; VOID NTAPI KiUserExceptionDispatcher(
;     PEXCEPTION_RECORD ExceptionRecord,
;     PCONTEXT ContextRecord
; )
;------------------------------------------------------------------------------
ALIGN 4
PUBLIC _KiUserExceptionDispatcher@8
_KiUserExceptionDispatcher@8 PROC NEAR
    mov     ecx, [esp + 4]          ; ecx = ContextRecord
    mov     ebx, [esp]              ; ebx = ExceptionRecord
    push    ecx
    push    ebx
    call    _RtlDispatchException@8
    or      al, al
    je      short kued_unhandled

    pop     ebx
    pop     ecx
    push    0                       ; TestAlert = FALSE
    push    ecx                     ; ContextRecord
    call    _ZwContinue@8
    jmp     short kued_fail

kued_unhandled:
    pop     ebx                     ; ebx = ExceptionRecord
    pop     ecx                     ; ecx = ContextRecord
    push    0                       ; FirstChance = FALSE
    push    ecx                     ; ContextRecord
    push    ebx                     ; ExceptionRecord
    call    _ZwRaiseException@12

kued_fail:
    sub     esp, ExceptionRecordSize
    mov     [esp + ErExceptionCode], eax
    mov     dword ptr [esp + ErExceptionFlags], EXCEPTION_NONCONTINUABLE
    mov     [esp + ErExceptionRecord], ebx
    mov     dword ptr [esp + ErNumberParameters], 0
    push    esp
    call    _RtlRaiseException@4
    ret     8
_KiUserExceptionDispatcher@8 ENDP

;------------------------------------------------------------------------------
; NTSTATUS NTAPI KiRaiseUserExceptionDispatcher(VOID)
;------------------------------------------------------------------------------
ALIGN 4
PUBLIC _KiRaiseUserExceptionDispatcher@0
_KiRaiseUserExceptionDispatcher@0 PROC NEAR
    push    ebp
    mov     ebp, esp
    sub     esp, ExceptionRecordSize
    mov     [esp + ErExceptionAddress], eax
    mov     eax, fs:[PcTeb]
    mov     eax, [eax + TbExceptionCode]
    mov     [esp + ErExceptionCode], eax
    mov     dword ptr [esp + ErExceptionFlags], 0
    mov     dword ptr [esp + ErExceptionRecord], 0
    mov     dword ptr [esp + ErNumberParameters], 0
    push    esp
    call    _RtlRaiseException@4
    mov     eax, [esp + ErExceptionCode]
    mov     esp, ebp
    pop     ebp
    ret
_KiRaiseUserExceptionDispatcher@0 ENDP

_TEXT ENDS
END
