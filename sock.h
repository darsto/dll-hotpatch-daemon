/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#ifndef DLL_HOTPATCH_DAEMON_SOCK
#define DLL_HOTPATCH_DAEMON_SOCK

#include <winnt.h> /* HANDLE */
#include <winsock2.h>/* INADDR_* */

/**
 * The simple Windows I/O API includes only select(), and that works only
 * for network sockets. This library fills the gap by providing a common
 * poll() for network and HANDLEs (which are files or readable pipes).
 *
 * This library is single-threaded only.
 */

typedef int (*sock_event_fn)(int sockfd, void *ctx);

/**
 * Init a socket poll. Can be only called once.
 */
int sock_init(void);

/**
 * A simple helper function to open a TCP socket, bind it to `inaddr`:`port`,
 * listen, and return.
 */
int sock_bind_listen(int inaddr, int port);

/**
 * Add fd to the poll group, execute `msg_fn` as long as the fd is
 * readable (or got closed).
 */
int sock_install_poll_fd(int fd, sock_event_fn msg_fn, void *ctx);

/**
 * Undo sock_install_poll_fd() or sock_install_poll_localfd().
 * Its fn will be no longer called.
 */
int sock_uninstall_poll_fd(int sockfd);

/**
 * Add HANDLE to the poll group, execute `msg_fn` as long as the handle
 * is readable.
 */
int sock_install_poll_handle(HANDLE handle, sock_event_fn msg_fn, void *ctx);

/**
 * Undo sock_install_poll_handle(). Its fn will be no longer called.
 */
int sock_uninstall_poll_handle(HANDLE handle);

/**
 * Helper function to write to a handle and detect potential timeout.
 * If write hasn't finished in `timeout_ms`, `timeout_fn` will be called
 * on a separate thread, which may e.g. call CancelSynchronousIo() on the
 * original, main thread.
 */
int sock_write_handle_timeout(HANDLE handle, void *buf, size_t len, size_t timeout_ms,
			      sock_event_fn timeout_fn, void *timeout_ctx);

/**
 * Open a dummy socket polled on the main thread. The socket fd is returned.
 * Any data sent to it will be handled with `fn`.
 */
int sock_install_poll_localfd(sock_event_fn fn, void *ctx);

/**
 * Poll all installed fds and handles and execute their callbacks.
 * This may block indefinitely.
 */
int sock_poll(void);

/**
 * Deinit the library. After this, sock_init() may be called again.
 */
void sock_deinit(void);

#endif /* DLL_HOTPATCH_DAEMON_SOCK */