/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <winsock2.h>

#include "common.h"
#include "exe.h"
#include "sock.h"

struct gdbproxy_session;

/**
 * gdbserver proxy listening for connections on a specified port.
 * It will wait for the first connection, only then start the actual
 * gdbserver and attach to \c proc. After that connection is closed,
 * the gdbserver will be terminated, but the process should remain
 * running. Any simultaneous connections to the gdbserver will be
 * rejected - only one is supported.
 */
struct gdbproxy {
	int fd;
	struct exe_process *proc;
	struct gdbproxy_session *session;
};

struct gdbproxy_session {
	struct gdbproxy *proxy;

	int fd;
	HANDLE stdout_rd;
	HANDLE stdout_wr;
	HANDLE stdin_rd;
	HANDLE stdin_wr;
	DWORD pid;

	bool init_breakpoint_removed;
	char remote_workdir[PATH_MAX];
};

static void
unset_close_handle(HANDLE *h)
{
	if (*h) {
		CloseHandle(*h);
		*h = NULL;
	}
}

/* exe.c */
void exe_notifydead_gdb(struct exe_process *proc, struct gdbproxy *gdb);

static void
gdbproxy_session_terminate(struct gdbproxy_session *ssn)
{
	HANDLE prochandle;

	fprintf(stderr, "[r] $ detach gdb\n");
	assert(ssn->proxy->session == ssn);

	/* close the gdbserver connection listener */
	sock_uninstall_poll_fd(ssn->proxy->fd);
	closesocket(ssn->proxy->fd);

	/* notify the exe it should no longer use us */
	if (ssn->proxy->proc) {
		exe_notifydead_gdb(ssn->proxy->proc, ssn->proxy);
	}

	/* stop input (and close its connection) */
	sock_uninstall_poll_fd(ssn->fd);
	closesocket(ssn->fd);

	/* stop output */
	sock_uninstall_poll_handle(ssn->stdout_rd);

	/* terminate gdb itself */
	if (ssn->pid) {
		prochandle = OpenProcess(PROCESS_TERMINATE, false, ssn->pid);
		if (prochandle) {
			TerminateProcess(prochandle, 1);
			CloseHandle(prochandle);
		}
	}

	unset_close_handle(&ssn->stdin_rd);
	unset_close_handle(&ssn->stdin_wr);
	unset_close_handle(&ssn->stdout_rd);
	unset_close_handle(&ssn->stdout_wr);

	free(ssn->proxy);
	free(ssn);
}

static int
handle_gdb_input_timeout(int _unused, void *ctx)
{
	struct gdbproxy_session *ssn = ctx;

	exe_interrupt(ssn->proxy->proc);
	return 0;
}

static int
handle_gdb_input(int sockfd, void *ctx)
{
	struct gdbproxy_session *ssn = ctx;
	char buf[4096];
	char *cmd;
	int cmdsize, rc, off;
	int token;
	int written;

	rc = recv(sockfd, buf, sizeof(buf), 0);
	if (rc <= 0) {
		gdbproxy_session_terminate(ssn);
		return 0;
	}

	buf[rc] = 0;
	if (buf[rc - 1] == '\n') {
		buf[rc - 1] = 0;
	}

	// fprintf(stderr, "user gdb input: %s\n", buf);

	rc = sscanf(buf, "%d %n %*s", &token, &off);
	if (rc == 0) {
		cmd = buf;
		cmdsize = sizeof(buf) - 1; /* -1 for newline */
		token = 0;
	} else {
		/* skip the command id (just an incrementing number) */
		cmd = buf + off;
		cmdsize = sizeof(buf) - off - 1;
	}

	/* a no-op gdb command that generates a ^done response
	 * we'll use it to "ignore" user commands */
	const char *noop_cmd = "-enable-timings no";

	if (strstr(cmd, "-file-exec-and-symbols ") == cmd) {
		snprintf(cmd, cmdsize, "-file-exec-and-symbols %s", g_exe_path);
		//
	} else if (strstr(cmd, "-environment-cd ") == cmd) {
		snprintf(cmd, cmdsize, "-environment-cd %s", g_workdir);
	} else if (strstr(cmd, "-target-select remote ") == cmd) {
		snprintf(cmd, cmdsize, "%s", noop_cmd);
		//
	} else if (strcmp(cmd, "-exec-run") == 0) {
		snprintf(cmd, cmdsize, "-exec-continue");
		//
	} else if (strcmp(cmd, "kill") == 0) {
		snprintf(cmd, cmdsize, "detach");
	}

	// fprintf(stderr, "processed gdb input: %s\n", buf);

	rc = strlen(buf);
	buf[rc++] = '\n';

	/* If we rehook while the process is running under GDB, there will be
	 * messages printed from GDB about new thread (for injection) and then about
	 * the newly loaded library. If our SuspendThread aligns unfortunately with
	 * this thread/process info enumeration by GDB, we may get GDB into a deadlock,
	 * which will no longer consume the input, and eventually lockout our entire
	 * daemon due to this blocking write. Resuming all threads have likely succeeded,
	 * but GDB has remained stuck.
	 *
	 * This is a very rare problem. It could be a GDB bug, but we're on thin ice
	 * and nobody expects threads to suddenly suspend. If it happens, we can kick
	 * GDB by interrupting our debugged process. This will cause GDB to unstuck
	 * and just propagate the interrupt to the user. The interrupt is going to be
	 * slightly unexpected on the user side, but it's better than deadlocking.
	 */
	written = sock_write_handle_timeout(ssn->stdin_wr, buf, rc, 1000,
					    handle_gdb_input_timeout, ssn);
	if (written < 0) {
		fprintf(stderr, "gdb stdin closed; terminating gdb\n");
		gdbproxy_session_terminate(ssn);
		return 0;
	}

	return 0;
}

static int
handle_gdb_output(int sockfd, void *ctx)
{
	struct gdbproxy_session *ssn = ctx;
	char buf[4096];
	int rc;

	rc = recv(sockfd, buf, sizeof(buf), 0);
	if (rc <= 0) {
		fprintf(stderr, "gdb died?\n");
		gdbproxy_session_terminate(ssn);
		return 0;
	}

	// fprintf(stderr, "gdb output: %s\n", buf);

	if (!ssn->init_breakpoint_removed &&
	    strstr(buf, "Cannot insert breakpoint 1.") != NULL) {
		const char *cmd = "d 1\n";
		sock_write_handle_timeout(ssn->stdin_wr, (void *)cmd, strlen(cmd), 1000,
					  handle_gdb_input_timeout, ssn);

		ssn->init_breakpoint_removed = true;
	}

	send(ssn->fd, buf, rc, 0);
	return 0;
}

static int
gdbproxyfd_handler(int sockfd, void *ctx)
{
	struct gdbproxy *proxy = ctx;
	struct gdbproxy_session *ssn = NULL;
	STARTUPINFO startup = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	SECURITY_ATTRIBUTES saAttr = { 0 };
	BOOL ok;
	char buf[4096];
	int rc;
	struct sockaddr_in cli = {};
	int len = sizeof(cli);

	int connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
	if (connfd < 0) {
		perror("acccept failed");
		if (proxy->session == NULL) {
			/* close down the gdbserver */
			return 1;
		}
		/* otherwise ignore the failure, the new connection would be dropped
		 * anyway */
		return 0;
	}

	if (proxy->session != NULL) {
		fprintf(
		    stderr,
		    "rejecting another simultaneous connection to a single gdbserver\n");
		closesocket(connfd);
		return 0;
	}

	ssn = calloc(1, sizeof(*ssn));
	assert(ssn != NULL);
	ssn->proxy = proxy;
	ssn->fd = connfd;

	proxy->session = ssn;

	saAttr.nLength = sizeof(saAttr);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	ok = CreatePipe(&ssn->stdin_rd, &ssn->stdin_wr, &saAttr, 0);
	ok = ok && SetHandleInformation(ssn->stdin_wr, HANDLE_FLAG_INHERIT, 0);
	ok = ok && CreatePipe(&ssn->stdout_rd, &ssn->stdout_wr, &saAttr, 0);
	ok = ok && SetHandleInformation(ssn->stdout_rd, HANDLE_FLAG_INHERIT, 0);
	if (!ok) {
		fprintf(stderr, "failed to create gdb pipes: %ld\n", GetLastError());
		gdbproxy_session_terminate(ssn);
		return 0;
	}

	if (ssn->proxy->proc == NULL || !exe_is_running(ssn->proxy->proc)) {
		fprintf(stderr, "the program died prematurely?\n");
		gdbproxy_session_terminate(ssn);
		return 0;
	}

	startup.cb = sizeof(startup);
	startup.hStdError = ssn->stdout_wr;
	startup.hStdOutput = ssn->stdout_wr;
	startup.hStdInput = ssn->stdin_rd;
	startup.dwFlags |= STARTF_USESTDHANDLES;

	/* Start the GDB with async programatic interface, attach it to ssn->proxy->proc,
	 * and also set an invalid breakpoint so GDB interrupts as soon as it's run.
	 * GDB clients, including VSCode, always resume the execution after they attach.
	 * This breakpoints essentially prevents that. We'll remove after it's first hit.
	 */
	snprintf(buf, sizeof(buf),
		 "gdb.exe --interpreter=mi2 -ex=\"set mi-async on\" -ex=\"b *0\" "
		 "-ex=\"attach %d\" %s",
		 exe_get_pid(ssn->proxy->proc), g_exe_path);
	ok = CreateProcess(NULL, buf, NULL, NULL, TRUE, 0, NULL, NULL, &startup,
			   &proc_info);
	if (!ok) {
		fprintf(stderr, "failed to start gdb: %ld\n", GetLastError());
		gdbproxy_session_terminate(ssn);
		return 0;
	}

	ssn->init_breakpoint_removed = false;

	/* if paused, unpause (unsuspend) */
	exe_unpause(ssn->proxy->proc);

	ssn->pid = proc_info.dwProcessId;

	rc = sock_install_poll_handle(ssn->stdout_rd, handle_gdb_output, ssn);
	assert(rc == 0);
	rc = sock_install_poll_fd(ssn->fd, handle_gdb_input, ssn);
	assert(rc == 0);

	return 0;
}

struct gdbproxy *
gdbproxy_start(struct exe_process *proc, int gdbserverport)
{
	struct gdbproxy *proxy;
	int fd;

	assert(proc != NULL);
	assert(exe_is_running(proc));

	fd = sock_bind_listen(INADDR_ANY, gdbserverport);
	if (fd < 0) {
		fprintf(stderr, "Could not bind to %d\n", gdbserverport);
		return NULL;
	}

	proxy = calloc(1, sizeof(*proxy));
	assert(proxy != NULL);

	proxy->fd = fd;
	proxy->proc = proc;

	sock_install_poll_fd(proxy->fd, gdbproxyfd_handler, proxy);
	return proxy;
}

void
gdbproxy_notifydead(struct gdbproxy *proxy, struct exe_process *proc)
{
	assert(proxy->proc == proc);
	proxy->proc = NULL;
}