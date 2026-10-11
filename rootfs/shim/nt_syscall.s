# SPDX-License-Identifier: GPL-2.0-only
.text
.globl DoNtSyscall
.type DoNtSyscall, @function
DoNtSyscall:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi

    movl 8(%ebp), %eax      /* syscall ID */
    movl 12(%ebp), %esi     /* args array */
    movl 16(%ebp), %ecx     /* num_args */

    testl %ecx, %ecx
    jz 2f
    leal (%esi, %ecx, 4), %esi
1:
    subl $4, %esi
    pushl (%esi)
    loop 1b

2:
    pushl $0                /* Dummy return address for KiFastSystemCall [esp+8] arg alignment */
    movl $0x7FFE0300, %edx
    call *%edx

    leal -12(%ebp), %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl

.globl __kernel_vsyscall
.type __kernel_vsyscall, @function
__kernel_vsyscall:
    pushl %ebp
    pushl %edi
    pushl %esi
    pushl %edx
    pushl %ecx
    pushl %ebx
    pushl %eax
    call __nt_linux_syscall
    addl $4, %esp
    popl %ebx
    popl %ecx
    popl %edx
    popl %esi
    popl %edi
    popl %ebp
    retl

