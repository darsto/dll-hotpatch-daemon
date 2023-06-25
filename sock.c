/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <winsock2.h>

#include "common.h" /* errnos */
#include "sock.h"

#define MAX_SOCKETS 16
#define MAX_HANDLES 4
#define LOCAL_IPC_PORT 61170

struct sock_pollfd_entry {
	int fd;
	sock_event_fn fn;
	void *ctx;
};

struct sock_pollhandle_entry {
	HANDLE rhandle;
	sock_event_fn fn;
	void *ctx;

	HANDLE thr;
};

struct sock_write_h_thr_ctx {
	HANDLE whandle;
	size_t timeout_ms;

	sock_event_fn timeout_fn;
	void *timeout_ctx;

	volatile bool finished;
};

struct sock_ctx {
	struct sock_pollfd_entry fds[MAX_SOCKETS];
	struct sock_pollhandle_entry handles[MAX_HANDLES];

	fd_set fdset;
	int ipc_fd;

	HANDLE write_h_thr;

	HANDLE write_h_thr_start_event;
	HANDLE write_h_thr_done_event;

	volatile struct sock_write_h_thr_ctx write_h_thr_ctx;
};

struct sock_ipc_init_msg {
	sock_event_fn fn;
	void *ctx;
};

static volatile bool g_sock_init;
static struct sock_ctx g_sock;

int
sock_bind_listen(int inaddr, int port)
{
	int sockfd;
	struct sockaddr_in servaddr = {};

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(inaddr);
	servaddr.sin_port = htons(port);

	if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
		perror("bind failed");
		return -1;
	}

	if (listen(sockfd, 5) != 0) {
		perror("listen failed");
		return -1;
	}

	return sockfd;
}

int
sock_install_poll_fd(int sockfd, sock_event_fn msg_fn, void *ctx)
{
	struct sock_pollfd_entry *entry;

	assert(sockfd != -1);
	for (int i = 0; i < MAX_SOCKETS; i++) {
		entry = &g_sock.fds[i];
		if (entry->fd != -1) {
			continue;
		}

		entry->fd = sockfd;
		entry->fn = msg_fn;
		entry->ctx = ctx;
		return 0;
	}

	assert(false);
	return -ETOOMANYREFS;
}

int
sock_uninstall_poll_fd(int sockfd)
{
	struct sock_pollfd_entry *entry;

	assert(sockfd != -1);
	for (int i = 0; i < MAX_SOCKETS; i++) {
		entry = &g_sock.fds[i];
		if (entry->fd != sockfd) {
			continue;
		}

		entry->fd = -1;
		entry->fn = NULL;
		entry->ctx = NULL;
		return 0;
	}

	assert(false);
	return -ENOENT;
}

static int
close_uninstall_poll_fd_by_fn(sock_event_fn fn, void *ctx)
{
	struct sock_pollfd_entry *entry;

	for (int i = 0; i < MAX_SOCKETS; i++) {
		entry = &g_sock.fds[i];
		if (entry->fd < 0 || entry->fn != fn || entry->ctx != ctx) {
			continue;
		}

		entry->fd = -1;
		entry->fn = NULL;
		entry->ctx = NULL;
		return 0;
	}

	assert(false);
	return -ENOENT;
}

/* not present in MinGW headers */
BOOL WINAPI CancelSynchronousIo(HANDLE hThread);

int
sock_uninstall_poll_handle(HANDLE handle)
{
	struct sock_pollhandle_entry *entry;
	DWORD thr_state;
	size_t i;

	assert(handle != 0);
	for (i = 0; i < MAX_HANDLES; i++) {
		entry = &g_sock.handles[i];
		if (entry->rhandle != handle) {
			continue;
		}

		break;
	}

	if (i == MAX_HANDLES) {
		assert(false);
		return 0;
	}

	CancelSynchronousIo(entry->thr);
	while (GetExitCodeThread(entry->thr, &thr_state)) {
		if (thr_state != STILL_ACTIVE) {
			break;
		}

		Sleep(20);
	}

	/* do not trigger the fn anymore */
	close_uninstall_poll_fd_by_fn(entry->fn, entry->ctx);

	entry->rhandle = NULL;
	entry->fn = NULL;
	entry->ctx = NULL;
	CloseHandle(entry->thr);
	entry->thr = NULL;

	return 0;
}

int
sock_poll(void)
{
	size_t num_fds = 0;
	int rc;

	FD_ZERO(&g_sock.fdset);

	for (int i = 0; i < MAX_SOCKETS; i++) {
		struct sock_pollfd_entry *entry = &g_sock.fds[i];
		if (entry->fd >= 0) {
			FD_SET(entry->fd, &g_sock.fdset);
			num_fds++;
		}
	}

	if (num_fds == 0) {
		return -ENOENT;
	}

	rc = select(0, &g_sock.fdset, NULL, NULL, NULL);
	if (rc == SOCKET_ERROR) {
		perror("select");
		return -rc;
	}

	for (int i = 0; i < MAX_SOCKETS; i++) {
		struct sock_pollfd_entry *entry = &g_sock.fds[i];

		if (!FD_ISSET(entry->fd, &g_sock.fdset)) {
			continue;
		}

		rc = entry->fn(entry->fd, entry->ctx);
		if (rc) {
			closesocket(entry->fd);
			entry->fd = -1;
			entry->fn = NULL;
			entry->ctx = NULL;
		}
	}

	return 0;
}

static DWORD WINAPI
pipe_thread_fn(void *ctx)
{
	struct sock_pollhandle_entry *entry = ctx;
	char buf[4096];
	int ipc_fd;
	DWORD read;
	bool ok;

	ipc_fd = sock_install_poll_localfd(entry->fn, entry->ctx);
	if (ipc_fd < 0) {
		fprintf(stderr, "ipcfd_exec() failed: %d\n", -ipc_fd);
		return 1;
	}

	while (true) {
		ok = ReadFile(entry->rhandle, buf, sizeof(buf), &read, NULL);
		if (!ok || read == 0) {
			break;
		}

		send(ipc_fd, buf, read, 0);
	}

	/* close the connection, which should also make the poll fn trigger
	 * and fail on recv(). */
	closesocket(ipc_fd);
	return 0;
}

int
sock_install_poll_handle(HANDLE handle, sock_event_fn msg_fn, void *ctx)
{
	struct sock_pollhandle_entry *entry;
	HANDLE thr;
	size_t i;
	DWORD tid;

	assert(handle != 0);
	for (i = 0; i < MAX_HANDLES; i++) {
		entry = &g_sock.handles[i];
		if (entry->rhandle != NULL) {
			continue;
		}

		entry->rhandle = handle;
		entry->fn = msg_fn;
		entry->ctx = ctx;
		break;
	}

	if (i == MAX_HANDLES) {
		assert(false);
		return -ETOOMANYREFS;
	}

	/**
	 * We can't run select() on pipe, so we create a thread that's blocking on
	 * ReadFile() and then forwards all data to the IPC socket.
	 */
	thr = CreateThread(NULL, 0, pipe_thread_fn, entry, 0, &tid);
	if (!thr) {
		entry->rhandle = NULL;
		entry->fn = NULL;
		entry->ctx = NULL;
		return -1;
	}

	entry->thr = thr;
	return 0;
}

static DWORD WINAPI
write_handle_check_timeout_fn(void *_ctx)
{
	unsigned start_ts, ts;

	WaitForSingleObject(g_sock.write_h_thr_start_event, INFINITE);
	while (g_sock_init) {
		volatile struct sock_write_h_thr_ctx *ctx = &g_sock.write_h_thr_ctx;

		start_ts = GetTickCount();
		while (!ctx->finished) {
			Sleep(10);

			ts = GetTickCount();
			if (ts - start_ts > ctx->timeout_ms) {
				ctx->timeout_fn(-1, (void *)ctx->timeout_ctx);
				break;
			}
		}
		SetEvent(g_sock.write_h_thr_done_event);

		WaitForSingleObject(g_sock.write_h_thr_start_event, INFINITE);
	}

	return 0;
}

int
sock_write_handle_timeout(HANDLE handle, void *buf, size_t len, size_t timeout_ms,
			  sock_event_fn timeout_fn, void *timeout_ctx)
{
	volatile struct sock_write_h_thr_ctx *ctx = &g_sock.write_h_thr_ctx;
	DWORD written;
	BOOL ok;

	ctx->whandle = handle;
	ctx->timeout_ms = timeout_ms;
	ctx->timeout_fn = timeout_fn;
	ctx->timeout_ctx = timeout_ctx;
	ctx->finished = false;
	SetEvent(g_sock.write_h_thr_start_event);

	ok = WriteFile(handle, buf, len, &written, NULL);
	g_sock.write_h_thr_ctx.finished = true;

	WaitForSingleObject(g_sock.write_h_thr_done_event, INFINITE);
	if (!ok) {
		written = -EIO;
	}

	return (int)written;
}

static int
ipcfd_accept_handler(int sockfd, void *ctx)
{
	struct sockaddr_in cli = {};
	int len = sizeof(cli);
	struct sock_ipc_init_msg init_msg;
	int rc;

	int connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
	if (connfd < 0) {
		perror("ipc: acccept failed");
		return 0;
	}

	rc = recv(connfd, (void *)&init_msg, sizeof(init_msg), 0);
	if (rc <= 0) {
		fprintf(stderr, "ipc: recv failed: %d\n", errno);
		return 0;
	}

	if (rc != sizeof(init_msg)) {
		fprintf(stderr, "ipc: invalid init msg size (got %d, expected %d)\n", rc,
			sizeof(init_msg));
		return 0;
	}

	assert(init_msg.fn);
	sock_install_poll_fd(connfd, init_msg.fn, init_msg.ctx);
	return 0;
}

int
sock_install_poll_localfd(sock_event_fn fn, void *ctx)
{
	struct sockaddr_in servaddr = {};
	struct sock_ipc_init_msg init_msg;
	int connfd, rc;

	init_msg.fn = fn;
	init_msg.ctx = ctx;

	connfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connfd == -1) {
		perror("ipc: socket");
		assert(false);
		return -1;
	}

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servaddr.sin_port = htons(LOCAL_IPC_PORT);

	rc = connect(connfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (rc == SOCKET_ERROR) {
		perror("ipc: connect");
		assert(false);
		closesocket(connfd);
		return -1;
	}

	send(connfd, (void *)&init_msg, sizeof(init_msg), 0);
	return connfd;
}

int
sock_init(void)
{
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	DWORD tid;

	if (g_sock_init) {
		return -EALREADY;
	}

	WSAStartup(versionWanted, &wsaData);

	for (int i = 0; i < MAX_SOCKETS; i++) {
		struct sock_pollfd_entry *entry = &g_sock.fds[i];
		entry->fd = -1;
	}

	g_sock.ipc_fd = sock_bind_listen(INADDR_LOOPBACK, LOCAL_IPC_PORT);
	if (g_sock.ipc_fd < 0) {
		fprintf(stderr, "can't listen on the local ipc port %d: %d\n",
			LOCAL_IPC_PORT, -g_sock.ipc_fd);
		return g_sock.ipc_fd;
	}

	g_sock.write_h_thr_start_event =
	    CreateEvent(NULL, FALSE, FALSE, "handle_write_thr_start_event");
	if (g_sock.write_h_thr_start_event == NULL) {
		closesocket(g_sock.ipc_fd);
		return -1;
	}

	g_sock.write_h_thr_done_event =
	    CreateEvent(NULL, FALSE, FALSE, "handle_write_thr_done_event");
	if (g_sock.write_h_thr_done_event == NULL) {
		CloseHandle(g_sock.write_h_thr_start_event);
		closesocket(g_sock.ipc_fd);
		return -1;
	}

	g_sock.write_h_thr =
	    CreateThread(NULL, 0, write_handle_check_timeout_fn, NULL, 0, &tid);
	if (!g_sock.write_h_thr) {
		CloseHandle(g_sock.write_h_thr_done_event);
		CloseHandle(g_sock.write_h_thr_start_event);
		closesocket(g_sock.ipc_fd);
		return -1;
	}

	sock_install_poll_fd(g_sock.ipc_fd, ipcfd_accept_handler, NULL);

	g_sock_init = true;
	return 0;
}

void
sock_deinit(void)
{
	DWORD thr_state;

	g_sock_init = false;
	sock_uninstall_poll_fd(g_sock.ipc_fd);

	SetEvent(g_sock.write_h_thr_start_event);
	while (GetExitCodeThread(g_sock.write_h_thr, &thr_state)) {
		if (thr_state != STILL_ACTIVE) {
			break;
		}

		Sleep(20);
	}

	CloseHandle(g_sock.write_h_thr_done_event);
	CloseHandle(g_sock.write_h_thr_start_event);
	CloseHandle(g_sock.write_h_thr);

	closesocket(g_sock.ipc_fd);
	g_sock.ipc_fd = -1;

	for (int i = 0; i < MAX_SOCKETS; i++) {
		struct sock_pollfd_entry *entry = &g_sock.fds[i];
		assert(entry->fd == -1);
	}

	for (int i = 0; i < MAX_HANDLES; i++) {
		struct sock_pollhandle_entry *entry = &g_sock.handles[i];
		assert(entry->rhandle == NULL);
	}
}