/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "exe.h"
#include "sock.h"

#define MASTER_PORT 61171

static struct exe_process *g_proc;

/* common.h */
char g_exe_path[PATH_MAX];
char g_exe_dir_path[PATH_MAX];
char g_dll_path[PATH_MAX];
char g_dll_dir_path[PATH_MAX];
char g_workdir[PATH_MAX];

void
conn_echo(int connfd, const char *fmt, ...)
{
	char buf[2048];
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	send(connfd, buf, rc <= sizeof(buf) ? rc : sizeof(buf), 0);
	fprintf(stderr, "[r] %s", buf);
}

static int
conn_exec_unsafe(int connfd, const char *cmd)
{
	FILE *fp;
	char path[1048];

	/* Open the command for reading. */
	snprintf(path, sizeof(path), "%s 2>&1", cmd);
	/* we need to run e.g. gcc, so there's no point in further security checks... */
	fp = popen(path, "r");
	if (fp == NULL) {
		assert(false);
		return -1;
	}

	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path), fp) != NULL) {
		send(connfd, path, strlen(path), 0);
	}

	return pclose(fp);
}

/* handle singular external msg on one connection of master port */
static int
conn_recv(int connfd, void *ctx)
{
	char buf[1024];
	char tmpbuf[1024];
	char *argv[64] = {};
	char *c;
	int argc;
	int rc;
	bool need_new_word = false;

	/* cleanup any dead process */
	if (g_proc && !exe_is_running(g_proc)) {
		exe_free(g_proc);
		g_proc = NULL;
	}

	rc = recv(connfd, buf, sizeof(buf) - 1, 0);
	if (rc <= 0) {
		return 1;
	}

	if (rc > 0 && buf[rc - 1] == '\n') {
		buf[rc - 1] = 0;
	}
	buf[rc] = 0;

	snprintf(tmpbuf, sizeof(tmpbuf), "%s", buf);

	c = tmpbuf;
	argc = 0;
	argv[argc++] = c;

	while (*c) {
		if (*c == ' ' || *c == '\t') {
			*c = 0;
			need_new_word = true;
			c++;
			continue;
		}

		if (need_new_word) {
			argv[argc++] = c;
			need_new_word = false;
		}

		c++;
	}

	/* TODO API for registering handlers? */

	if (strcmp(argv[0], "hook") == 0) {
		if (g_proc == NULL) {
			conn_echo(connfd, "$ start exe\n");
			g_proc = exe_start(false);
			if (g_proc == NULL) {
				conn_echo(connfd, "Could not start the process");
			}
		} else {
			conn_echo(connfd, "$ rehook dll\n");
			rc = exe_rehook_dll(g_proc);
			if (rc == -ELIBBAD) {
				conn_echo(connfd, "DLL inject failed\n");
			} else if (rc == -ETIMEDOUT) {
				conn_echo(connfd,
					  "DLL detach timeout out (1500ms). Is the "
					  "program stopped in gdb?\n");
			} else if (rc > 0) {
				conn_echo(connfd, "DLL detach failed (rc %d)\n", -rc);
			}
		}
	} else if (strcmp(argv[0], "gdb") == 0) {
		conn_echo(connfd, "$ gdb\n");
		if (!argv[1]) {
			conn_echo(connfd, "Missing port number");
			return 1;
		}
		int port = atoi(argv[1]);

		if (g_proc == NULL) {
			g_proc = exe_start(true);
			if (g_proc == NULL) {
				conn_echo(connfd, "Could not start the process");
				return 1;
			}
		}

		rc = exe_attach_gdb(g_proc, port);
		if (rc != 0) {
			conn_echo(connfd, "Could not start gdb. Is the port taken? (%d)",
				  port);
		}
	} else {
		conn_exec_unsafe(connfd, buf);
	}

	/* TODO do not close the connection after every message */
	return 1;
}

/* accept external connection to master port */
static int
masterfd_accept_conn(int sockfd, void *ctx)
{
	struct sockaddr_in cli = {};
	int len = sizeof(cli);

	int connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
	if (connfd < 0) {
		perror("acccept failed");
		return 0;
	}

	sock_install_poll_fd(connfd, conn_recv, NULL);

	return 0;
}

static void
get_dir_path(char *dstbuf, size_t dstbufsize, const char *fullpath)
{
	snprintf(dstbuf, dstbufsize, "%s", fullpath);

	char *delim1 = strrchr(dstbuf, '\\');
	char *delim2 = strrchr(dstbuf, '/');
	char *delim = delim2 > delim1 ? delim2 : delim1;
	if (delim) {
		delim[0] = 0;
	}
}

static void
print_usage(const char *exename)
{
	fprintf(stderr, "Usage: %s -e /path/to/exe -d /path/to/dll\n", exename);
}

int
main(int argc, char *argv[])
{
	int masterfd;
	int rc, opt;

	while ((opt = getopt(argc, argv, "e:d:")) != -1) {
		switch (opt) {
		case 'e':
			snprintf(g_exe_path, sizeof(g_exe_path), "%s", optarg);
			get_dir_path(g_exe_dir_path, sizeof(g_exe_dir_path), g_exe_path);
			break;
		case 'd':
			snprintf(g_dll_path, sizeof(g_dll_path), "%s", optarg);
			get_dir_path(g_dll_dir_path, sizeof(g_dll_dir_path), g_dll_path);
			break;
		default:
			fprintf(stderr, "Wrong parameter '-%c'\n", opt);
			print_usage(argv[0]);
			return 1;
		}
	}

	if (g_exe_path[0] == 0 || g_dll_path[0] == 0) {
		print_usage(argv[0]);
		return 1;
	}

	GetCurrentDirectory(sizeof(g_workdir), g_workdir);
	fprintf(stderr, "Working dir: \"%s\"\n", g_workdir);

	rc = sock_init();
	if (rc < 0) {
		fprintf(stderr, "sock_init() failed: %d\n", -rc);
		return -rc;
	}

	/* create an fd */
	masterfd = sock_bind_listen(INADDR_ANY, MASTER_PORT);
	if (masterfd < 0) {
		fprintf(stderr, "can't listen on master port %d: %d\n", MASTER_PORT, -rc);
		return -masterfd;
	}
	sock_install_poll_fd(masterfd, masterfd_accept_conn, NULL);

	fprintf(stderr, "Server started on port %d (fd=%d)\n", MASTER_PORT, masterfd);

	while (1) {
		rc = sock_poll();
		if (rc < 0) {
			break;
		}
	}

	sock_uninstall_poll_fd(masterfd);
	sock_deinit();
	return 0;
}
