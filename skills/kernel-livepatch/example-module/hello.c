#define MODNAME "hello"
#include "kmod.h"

int init_module(void)
{
    _printk("hello world\n");
    return 0;
}

void cleanup_module(void)
{
    _printk("goodbye world\n");
}
