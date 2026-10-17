/* SPDX-License-Identifier: GPL-2.0-only */
/* musl 1.2.5 i386 pthread_impl.h: map_base/map_size occupy words 11/12,
 * stack/stack_size occupy words 13/14. Never overwrite mapping ownership:
 * pthread_exit and pthread_join use it to unmap the libc-owned allocation. */
static void shim_set_musl_i386_stack(unsigned int *tcb, unsigned int stack_top,
                                     unsigned int stack_bytes) {
    tcb[13] = stack_top;
    tcb[14] = stack_bytes;
}
