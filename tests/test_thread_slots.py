# SPDX-License-Identifier: GPL-2.0-only
"""Stress the real slot allocator with mock NT thread termination handles."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stddef.h>
#define MAX_PTHREADS 16
struct handle { volatile int signaled, closed; };
typedef struct handle *HANDLE;
typedef struct { long long QuadPart; } LARGE_INTEGER;
static int Nt_WaitForSingleObject(HANDLE h, int alertable, LARGE_INTEGER *timeout) {
    assert(!alertable && timeout->QuadPart == 0);
    return __atomic_load_n(&h->signaled, __ATOMIC_ACQUIRE) ? 0 : 0x102;
}
static int closed_count;
static void Nt_Close(HANDLE h) {
    assert(h->signaled);
    assert(__sync_bool_compare_and_swap(&h->closed, 0, 1));
    __sync_fetch_and_add(&closed_count, 1);
}
static struct {
    volatile int in_use;
    HANDLE thread_handle;
    unsigned long tls_base;
    int *ctid;
} g_pthreads[MAX_PTHREADS];
#include "thread_slots.h"
static volatile int owner[MAX_PTHREADS];
static struct handle handles[16001];
static int created;
static void *worker(void *arg) {
    int id = (int)(long)arg;
    for (int n = 0; n < 2000; n++) {
        int slot;
        while ((slot = shim_claim_pthread_slot()) < 0) sched_yield();
        assert(__sync_bool_compare_and_swap(&owner[slot], 0, id));
        int index = __sync_fetch_and_add(&created, 1);
        HANDLE h = &handles[index];
        g_pthreads[slot].thread_handle = h;
        sched_yield();
        __sync_lock_test_and_set(&g_pthreads[slot].in_use, 2);
        /* The thread still uses its stack after publishing its cleared TID. */
        sched_yield();
        assert(owner[slot] == id);
        __sync_lock_test_and_set(&owner[slot], 0);
        __atomic_store_n(&h->signaled, 1, __ATOMIC_RELEASE);
    }
    return NULL;
}
int main(void) {
    g_pthreads[0].in_use = 1;
    g_pthreads[0].tls_base = 0x100100;
    g_pthreads[0].ctid = (int *)0x100120;
    g_pthreads[1].in_use = 2;
    g_pthreads[1].tls_base = 0x200100;
    g_pthreads[1].ctid = (int *)0x200120;
    shim_forget_unmapped_thread_memory(0x100000, 0x101000);
    assert(!g_pthreads[0].tls_base && !g_pthreads[0].ctid);
    assert(g_pthreads[1].tls_base == 0x200100 && g_pthreads[1].ctid == (int *)0x200120);
    struct handle held = {0};
    for (int i = 0; i < MAX_PTHREADS; i++) g_pthreads[i].in_use = 1;
    g_pthreads[0].thread_handle = &held;
    g_pthreads[0].in_use = 2;
    assert(shim_claim_pthread_slot() == -1); /* Retiring is not terminated. */
    held.signaled = 1;
    assert(shim_claim_pthread_slot() == 0 && held.closed);
    for (int i = 0; i < MAX_PTHREADS; i++) {
        g_pthreads[i].thread_handle = NULL;
        g_pthreads[i].in_use = 0;
    }
    pthread_t threads[8];
    for (long i = 0; i < 8; i++) assert(!pthread_create(&threads[i], NULL, worker, (void *)(i + 1)));
    for (int i = 0; i < 8; i++) assert(!pthread_join(threads[i], NULL));
    assert(created == 16000 && closed_count >= created - MAX_PTHREADS);
    puts("16000 lifecycles: no concurrent slot ownership or live-stack reuse");
}
'''


class ThreadSlotTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'host C compiler required')
    def test_stack_attributes_preserve_mapping_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'stack.c'
            executable = Path(directory)/'stack'
            source.write_text(r'''
#include <assert.h>
#include "musl_thread_stack.h"
int main(void) {
    unsigned int tcb[32], original[32];
    for (unsigned i = 0; i < 32; i++) tcb[i] = original[i] = 0x10000000U + i;
    shim_set_musl_i386_stack(tcb, 0x08000000U, 0x00100000U);
    assert(tcb[13] == 0x08000000U && tcb[14] == 0x00100000U);
    assert(tcb[11] == original[11] && tcb[12] == original[12]);
    for (unsigned i = 0; i < 32; i++)
        if (i != 13 && i != 14) assert(tcb[i] == original[i]);
}
''')
            subprocess.run(['cc', '-O2', '-std=c11',
                            '-I'+str(PROJECT/'chromium_rootfs/shim'), str(source),
                            '-o', str(executable)], check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, timeout=10)

    @unittest.skipUnless(shutil.which('cc'), 'host C compiler required')
    def test_concurrent_claim_and_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'slots.c'
            executable = Path(directory)/'slots'
            source.write_text(HARNESS)
            subprocess.run(['cc', '-O2', '-std=c11', '-pthread',
                            '-I'+str(PROJECT/'chromium_rootfs/shim'), str(source),
                            '-o', str(executable)], check=True, capture_output=True)
            result = subprocess.run([str(executable)], check=True, capture_output=True,
                                    text=True, timeout=20)
            self.assertIn('16000 lifecycles', result.stdout)
