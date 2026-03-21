CC     = gcc
CFLAGS = -ffreestanding -fno-stack-protector -O2 -Wall -Wno-unused -std=gnu11

.PHONY: all clean

all: hello.ko

hello.ko: hello.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f hello.ko
