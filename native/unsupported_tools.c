/* SPDX-License-Identifier: GPL-2.0-only */
/* Retained dispatch symbols reject commands whose original implementations fabricated success. */
#include <stdio.h>
static int unsupported(int argc, char **argv) {
    fprintf(stderr, "%s: unavailable in this image\n", argc && argv ? argv[0] : "command");
    return 127;
}
int gcc_main(int a,char **v) { return unsupported(a,v); }
int gxx_main(int a,char **v) { return unsupported(a,v); }
int cpp_main(int a,char **v) { return unsupported(a,v); }
int gdb_main(int a,char **v) { return unsupported(a,v); }
int test_cxx_main(int a,char **v) { return unsupported(a,v); }
int sshd_main(int a,char **v) { return unsupported(a,v); }
int ssh_main(int a,char **v) { return unsupported(a,v); }
int ssh_keygen_main(int a,char **v) { return unsupported(a,v); }
int scp_main(int a,char **v) { return unsupported(a,v); }
int openssh_applet_main(int a,char **v) { return unsupported(a,v); }
