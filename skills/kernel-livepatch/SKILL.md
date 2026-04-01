# Kernel Live-Patch Skill

The tools here allow claude to live-patch the running kernel, without requiring source or even headers.

Workflow:

1. Dump the running kernel with `kdump_sections.py` (this step requires root - you may need to prompt the user to invoke sudo. all other steps must be done autonomously.). This step must be done for each session, since ASLR changes on each boot. Output goes to `./kdump/` by default.
2. Load the dump into a headless ghidra project with `ghidra_load.py`
3. Decompile+disassemble functions of interest using `ghidra_print_func.py <function_name>`. Any addresses you see here are absolute, ASLR is already accounted for. Hint: Grep `./kdump/kallsyms` for available symbols.
4. Reconstruct kernel headers using `gen_vmlinux_h.py`
5. Devise a kernel patch strategy, and write a kernel module to perform the patching. (see ./example-module/ for an example).
	- It's ok to hardcode addresses.
	- You can do simple instruction patches with text_peek()
	- For nontrivial hooks, use register_kprobe()
	- NOTE: not all symbols are available! Grep the generated vmlinux.h to see what is. Anything defined as a macro is not present, you'll need to work around this. Some symbols may be available in `./kdump/kallsyms` but not in vmlinux.h, if they're missing BTF info.
	- Ideally, you should have the module revert any patches when unloaded.
6. Compile the module and instruct the user to insmod it.

Additional useful tools:

- Use `read_kdump.py` to read subsections of an existing kernel dump.
