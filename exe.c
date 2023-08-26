/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <winbase.h>
#include <windows.h>
#include <winsock2.h>

/* tlhelp32.h is broken, must come after windows.h */
#include <tlhelp32.h>

#include "common.h"
#include "exe.h"

struct exe_process {
	DWORD pid;
	HANDLE handle;
	HANDLE mainthread;
	struct gdbproxy *gdb;

	HMODULE dllmodule;
	char dllname[PATH_MAX];
};

struct remote_call_ctx {
	HANDLE prochandle;

	FARPROC fn_addr;
	void *fn_arg;

	size_t timeout_ms;

	void **ret;
};

static int
remote_call(struct remote_call_ctx *ctx)
{
	HANDLE thr;
	DWORD thr_state;
	unsigned start_ts, ts;

	if (ctx->fn_addr == 0x0) {
		return -EINVAL;
	}

	thr = CreateRemoteThread(ctx->prochandle, NULL, 0,
				 (LPTHREAD_START_ROUTINE)ctx->fn_addr,
				 (LPVOID)ctx->fn_arg, 0, NULL);
	if (thr == NULL) {
		return -EIO;
	}

	start_ts = GetTickCount();
	while (GetExitCodeThread(thr, &thr_state)) {
		if (thr_state != STILL_ACTIVE) {
			break;
		}

		Sleep(50);
		if (ctx->timeout_ms == 0) {
			continue;
		}

		ts = GetTickCount();
		if (ts - start_ts > ctx->timeout_ms) {
			TerminateThread(thr, 1);
			CloseHandle(thr);
			return -ETIMEDOUT;
		}
	}

	if (ctx->ret) {
		*ctx->ret = (void *)thr_state;
	}

	CloseHandle(thr);

	return 0;
}

/* CreateRemoteThread() accepts only one parameter, but GetProcAddress()
 * requires two. We'll use the following thunk of code two decompose a
 * single buffer into two arguments, then call GetProcAddress().
 *
 * This function will be copied to another process' address space. Must
 * be position independent.
 *
 * The following buffer is expected at [esp]:
 * [ GetProcAddress ] [ hModule ] [ Null-terminated string ]
 * 0x0      ...       0x4   ...   0x8 0x9 0xA 0xB 0xC 0xD ...
 */
__attribute__((noinline, section("callprocaddress_thunk"))) static DWORD WINAPI
callprocaddress_thunk(void *ctx)
{
	FARPROC(WINAPI * getprocaddr)(HMODULE, const char *) = *(void **)ctx;
	HMODULE hmod = *(void **)(ctx + 4);
	const char *str = (const char *)(ctx + 8);

	void (*fn)(void) = (void *)getprocaddr(hmod, str);
	fn();
	return 0;
}

static int
remote_callprocaddress(HANDLE prochandle, HMODULE dll, const char *fn_name)
{
	LPVOID thunk;
	LPVOID thunk_data;
	int rc;

	extern unsigned char __start_callprocaddress_thunk[];
	extern unsigned char __stop_callprocaddress_thunk[];

	size_t thunk_size = (size_t)((uintptr_t)__stop_callprocaddress_thunk -
				     (uintptr_t)__start_callprocaddress_thunk);
	thunk = VirtualAllocEx(prochandle, NULL, thunk_size, MEM_RESERVE | MEM_COMMIT,
			       PAGE_EXECUTE_READWRITE);
	if (thunk == NULL) {
		goto err;
	}

	rc = WriteProcessMemory(prochandle, thunk, (LPCVOID)callprocaddress_thunk,
				thunk_size, NULL);
	if (rc == 0) {
		goto err_free_thunk;
	}

	size_t thunk_data_size = 4 + 4 + strlen(fn_name) + 1;
	thunk_data = VirtualAllocEx(prochandle, NULL, thunk_data_size,
				    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (thunk_data == NULL) {
		goto err;
	}

	char *buf = calloc(1, thunk_data_size);
	assert(buf != NULL);

	*(uint32_t *)buf =
	    (uint32_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
	*(uint32_t *)(buf + 4) = (uint32_t)dll;
	memcpy(buf + 8, fn_name, strlen(fn_name) + 1);

	rc = WriteProcessMemory(prochandle, thunk_data, (LPCVOID)buf, thunk_data_size,
				NULL);
	free(buf);

	if (rc == 0) {
		goto err_free_data;
	}

	rc = remote_call(&(struct remote_call_ctx){ .prochandle = prochandle,
						    .fn_addr = (FARPROC)thunk,
						    .fn_arg = thunk_data,
						    .timeout_ms = 0,
						    .ret = NULL });

	VirtualFreeEx(prochandle, thunk_data, 0, MEM_RELEASE);
	VirtualFreeEx(prochandle, thunk, 0, MEM_RELEASE);
	return rc;

err_free_data:
	VirtualFreeEx(prochandle, thunk_data, 0, MEM_RELEASE);
err_free_thunk:
	VirtualFreeEx(prochandle, thunk, 0, MEM_RELEASE);
err:
	return -1;
}

/** Detach a specific HMODULE dll from given pid */
static int
detach_dll(HANDLE prochandle, HMODULE dll)
{
	int rc = remote_callprocaddress(prochandle, dll, "Deinit");
	if (rc == 0) {
		/* Deinit probably doesn't exist in the DLL, unload anyway */
	}

	return remote_call(&(struct remote_call_ctx){
	    .prochandle = prochandle,
	    .fn_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"),
	    .fn_arg = dll,
	    .timeout_ms = 1500,
	    .ret = NULL });
}

/** Inject dll at given path to given pid */
static HMODULE
inject_dll(HANDLE prochandle, char *path_to_dll)
{
	LPVOID ext_path_to_dll;
	HMODULE injected_dll = NULL;
	int rc;

	ext_path_to_dll = VirtualAllocEx(prochandle, NULL, strlen(path_to_dll) + 1,
					 MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (ext_path_to_dll == NULL) {
		goto err;
	}

	rc = WriteProcessMemory(prochandle, ext_path_to_dll, path_to_dll,
				strlen(path_to_dll) + 1, NULL);
	if (rc == 0) {
		goto err_free;
	}

	rc = remote_call(&(struct remote_call_ctx){
	    .prochandle = prochandle,
	    .fn_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
	    .fn_arg = ext_path_to_dll,
	    .timeout_ms = 0,
	    .ret = (void **)&injected_dll });

	if (rc != 0) {
		goto err_free;
	}

	VirtualFreeEx(prochandle, ext_path_to_dll, 0, MEM_RELEASE);
	DeleteFile(path_to_dll);
	return injected_dll;

err_free:
	VirtualFreeEx(prochandle, ext_path_to_dll, 0, MEM_RELEASE);
err:
	return NULL;
}

#define INJECT_MAX_RETRIES 9
static int
exe_inject_tmp_dll(struct exe_process *proc)
{
	int i;
	BOOL ok;

	for (i = 0; i < INJECT_MAX_RETRIES; i++) {
		_snprintf(proc->dllname, sizeof(proc->dllname), "%s\\hook_%u.dll",
			  g_dll_dir_path, i);
		DeleteFile(proc->dllname);
		ok = CopyFile(g_dll_path, proc->dllname, true);
		if (ok) {
			break;
		}

		/* the file from previous injection might still exist (e.g. when
		 * windows search or some antivirus is still processing it). The
		 * file will be removed eventually, just retry now with another
		 * one */
	}

	if (i == INJECT_MAX_RETRIES) {
		return -ELIBBAD;
	}

	proc->dllmodule = inject_dll(proc->handle, proc->dllname);
	if (proc->dllmodule == NULL) {
		return -ELIBBAD;
	}

	return 0;
}

bool
exe_is_running(struct exe_process *proc)
{
	DWORD exit_code;

	if (proc->pid == 0) {
		return false;
	}

	GetExitCodeProcess(proc->handle, &exit_code);
	return exit_code == STILL_ACTIVE;
}

void
exe_interrupt(struct exe_process *proc)
{
	assert(proc != NULL);
	DebugBreakProcess(proc->handle);
}

unsigned
exe_get_pid(struct exe_process *proc)
{
	return (unsigned)proc->pid;
}

static void
resume_all_threads(DWORD proc_id)
{
	HANDLE h;
	THREADENTRY32 te;

	h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h == INVALID_HANDLE_VALUE) {
		return;
	}

	te.dwSize = sizeof(te);
	if (!Thread32First(h, &te)) {
		CloseHandle(h);
		return;
	}

	do {
		if (te.dwSize < FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				    sizeof(te.th32OwnerProcessID)) {
			continue;
		}

		if (te.th32OwnerProcessID != proc_id) {
			continue;
		}

		HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
		if (thread != NULL) {
			ResumeThread(thread);
			CloseHandle(thread);
		}

		te.dwSize = sizeof(te);
	} while (Thread32Next(h, &te));

	CloseHandle(h);
}

int
exe_rehook_dll(struct exe_process *proc)
{
	int rc;

	if (proc->dllmodule != NULL) {
		rc = detach_dll(proc->handle, proc->dllmodule);
		if (rc != 0) {
			return rc;
		}
		proc->dllmodule = NULL;
	}
	rc = exe_inject_tmp_dll(proc);
	if (rc != 0) {
		return -ELIBBAD;
	}

	resume_all_threads(proc->pid);

	return 0;
}

struct exe_process *
exe_start(bool start_paused)
{
	STARTUPINFO startup_info = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	struct exe_process *proc;
	BOOL ok;

	proc = calloc(1, sizeof(*proc));
	assert(proc != NULL);

	SetCurrentDirectory(g_exe_dir_path);
	SetDllDirectory(g_dll_dir_path);

	startup_info.cb = sizeof(startup_info);
	ok = CreateProcess(
	    NULL, g_exe_path, NULL, NULL, FALSE,
	    CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL,
	    &startup_info, &proc_info);
	if (!ok) {
		goto err_free;
	}

	SetCurrentDirectory(g_workdir);

	proc->pid = proc_info.dwProcessId;
	proc->handle = OpenProcess(PROCESS_ALL_ACCESS, 0, proc->pid);
	if (proc->handle == NULL) {
		fprintf(stderr, "OpenProcess() failed\n");
		goto err_free;
	}

	/* remove the original DLL dependency */
	void *iat_entry_addr = (void *)0x10ea168;
	char zeroes[20] = { 0 };
	DWORD prevProt;

	ok = VirtualProtectEx(proc->handle, iat_entry_addr, sizeof(zeroes),
			      PAGE_READWRITE, &prevProt);
	ok = ok && WriteProcessMemory(proc->handle, iat_entry_addr, zeroes,
				      sizeof(zeroes), NULL);
	ok = ok && VirtualProtectEx(proc->handle, iat_entry_addr, sizeof(zeroes),
				    prevProt, &prevProt);
	ok = ok && exe_inject_tmp_dll(proc) == 0;
	if (!ok) {
		fprintf(stderr, "WriteProcessMemory() failed\n");
		TerminateProcess(proc->handle, 1);
		CloseHandle(proc->handle);
		goto err_free;
	}

	proc->mainthread = proc_info.hThread;
	if (!start_paused) {
		exe_unpause(proc);
	}

	return proc;

err_free:
	free(proc);
	return NULL;
}

void
exe_unpause(struct exe_process *proc)
{
	if (proc->mainthread != NULL) {
		ResumeThread(proc->mainthread);
		proc->mainthread = NULL;
	}
}

/* gdbproxy.c */
struct gdbproxy;
struct gdbproxy *gdbproxy_start(struct exe_process *proc, int gdbserverport);
void gdbproxy_notifydead(struct gdbproxy *gdb, struct exe_process *proc);
/* called from gdbproxy.c */
void
exe_notifydead_gdb(struct exe_process *proc, struct gdbproxy *gdb)
{
	assert(proc->gdb == gdb);
	proc->gdb = NULL;
}

void
exe_free(struct exe_process *proc)
{
	if (proc == NULL) {
		return;
	}

	if (exe_is_running(proc)) {
		TerminateProcess(proc->handle, 1);
	}

	if (proc->gdb) {
		gdbproxy_notifydead(proc->gdb, proc);
		proc->gdb = NULL;
	}

	CloseHandle(proc->handle);
	free(proc);
}

int
exe_attach_gdb(struct exe_process *proc, int gdbserverport)
{
	struct gdbproxy *gdb;

	assert(proc != NULL);
	assert(proc->gdb == NULL);

	gdb = gdbproxy_start(proc, gdbserverport);
	if (gdb == NULL) {
		return -1;
	}

	proc->gdb = gdb;
	return 0;
}
