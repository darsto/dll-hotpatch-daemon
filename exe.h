/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#ifndef DLL_HOTPATCH_DAEMON_EXE
#define DLL_HOTPATCH_DAEMON_EXE

#include <stdbool.h>

struct exe_process;

struct exe_process *exe_start(bool start_paused);
void exe_unpause(struct exe_process *proc);
int exe_rehook_dll(struct exe_process *proc);
int exe_attach_gdb(struct exe_process *proc, int gdbserverport);
bool exe_is_running(struct exe_process *proc);
void exe_interrupt(struct exe_process *proc);
unsigned exe_get_pid(struct exe_process *proc);
void exe_free(struct exe_process *proc);

#endif /* DLL_HOTPATCH_DAEMON_EXE */