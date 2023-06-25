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

/** Detach a specific HMODULE dll from given pid */
static int
detach_dll(HANDLE prochandle, HMODULE dll)
{
	HANDLE thr;
	uintptr_t free_lib_winapi_addr;
	DWORD thr_state;
	unsigned start_ts, ts;

	free_lib_winapi_addr =
	    (uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
	if (free_lib_winapi_addr == 0x0) {
		return -ENOSYS;
	}

	thr = CreateRemoteThread(prochandle, NULL, 0,
				 (LPTHREAD_START_ROUTINE)free_lib_winapi_addr,
				 (LPVOID)dll, 0, NULL);
	if (thr == NULL) {
		return -EIO;
	}

	start_ts = GetTickCount();
	while (GetExitCodeThread(thr, &thr_state)) {
		if (thr_state != STILL_ACTIVE) {
			break;
		}

		Sleep(50);

		ts = GetTickCount();
		if (ts - start_ts > 1500) {
			TerminateThread(thr, 1);
			CloseHandle(thr);
			return -ETIMEDOUT;
		}
	}

	CloseHandle(thr);

	return 0;
}

/** Inject dll at given path to given pid */
static HMODULE
inject_dll(HANDLE prochandle, char *path_to_dll)
{
	HANDLE thr;
	LPVOID ext_path_to_dll;
	LPVOID load_lib_winapi_addr;
	HMODULE injected_dll = NULL;
	DWORD thr_state;
	int rc;

	load_lib_winapi_addr =
	    (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (load_lib_winapi_addr == NULL) {
		goto err;
	}

	ext_path_to_dll =
	    (LPVOID)VirtualAllocEx(prochandle, NULL, strlen(path_to_dll) + 1,
				   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (ext_path_to_dll == NULL) {
		goto err;
	}

	rc = WriteProcessMemory(prochandle, ext_path_to_dll, path_to_dll,
				strlen(path_to_dll) + 1, NULL);
	if (rc == 0) {
		goto err_free;
	}

	thr = CreateRemoteThread(prochandle, NULL, 0,
				 (LPTHREAD_START_ROUTINE)load_lib_winapi_addr,
				 ext_path_to_dll, 0, NULL);
	if (thr == NULL) {
		goto err_free;
	}

	while (GetExitCodeThread(thr, &thr_state)) {
		if (thr_state != STILL_ACTIVE) {
			injected_dll = (HMODULE)thr_state;
			break;
		}
	}

	VirtualFreeEx(prochandle, ext_path_to_dll, 0, MEM_RELEASE);
	CloseHandle(thr);

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
