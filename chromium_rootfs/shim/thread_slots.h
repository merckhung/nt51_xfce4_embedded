/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after SHIM_PTHREAD and the NT wait/close wrappers are defined. */
static void shim_forget_unmapped_thread_memory(unsigned long start, unsigned long end) {
    for (int i = 0; i < MAX_PTHREADS; i++) {
        if (!g_pthreads[i].in_use) continue;
        if (g_pthreads[i].tls_base >= start && g_pthreads[i].tls_base < end)
            g_pthreads[i].tls_base = 0;
        unsigned long ctid = (unsigned long)g_pthreads[i].ctid;
        if (ctid >= start && ctid < end) g_pthreads[i].ctid = NULL;
    }
}

static int shim_claim_pthread_slot(void) {
    for (int i = 0; i < MAX_PTHREADS; i++) {
        if (__sync_bool_compare_and_swap(&g_pthreads[i].in_use, 0, 1)) return i;
        /* 2 means retiring. A cleared child TID does not mean NT has finished
         * using the stack. Hold its handle until termination is observable. */
        if (__sync_bool_compare_and_swap(&g_pthreads[i].in_use, 2, 3)) {
            HANDLE thread = g_pthreads[i].thread_handle;
            LARGE_INTEGER zero = { .QuadPart = 0 };
            if (thread && Nt_WaitForSingleObject(thread, 0, &zero) == 0) {
                Nt_Close(thread);
                g_pthreads[i].thread_handle = NULL;
                __sync_lock_test_and_set(&g_pthreads[i].in_use, 1);
                return i;
            }
            __sync_lock_test_and_set(&g_pthreads[i].in_use, 2);
        }
    }
    return -1;
}
