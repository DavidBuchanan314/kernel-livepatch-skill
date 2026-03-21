#include "vmlinux.h"

int init_module(void);
void cleanup_module(void);

static const char __modinfo_vermagic[]
    __attribute__((section(".modinfo"), used)) =
    "vermagic=" VERMAGIC;

__attribute__((section(".gnu.linkonce.this_module"), used))
struct module __this_module = {
    .name = MODNAME,
    .init = init_module,
    .exit = cleanup_module,
};

/* aarch64 module loader requires these sections to exist. */
__asm__(
    ".pushsection .plt,\"ax\",@progbits\n\t"
    ".byte 0\n\t"
    ".popsection\n\t"
    ".pushsection .init.plt,\"a\",@progbits\n\t"
    ".byte 0\n\t"
    ".popsection\n\t"
    ".pushsection .text.ftrace_trampoline,\"ax\",@progbits\n\t"
    ".byte 0\n\t"
    ".popsection\n\t"
    ".pushsection .init.text.ftrace_trampoline,\"a\",@progbits\n\t"
    ".byte 0\n\t"
    ".popsection\n\t"
);
