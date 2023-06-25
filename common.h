/* SPDX-License-Identifier: MIT
 * Copyright(c) 2019-2023 Darek Stojaczyk
 */

#ifndef DLL_HOTPATCH_DAEMON_COMMON
#define DLL_HOTPATCH_DAEMON_COMMON

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef ETOOMANYREFS
#define ETOOMANYREFS 109 /* Too many references: cannot splice */
#endif

#ifndef EALREADY
#define EALREADY 114 /* Operation already in progress */
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT 110 /* Connection timed out */
#endif

#ifndef ELIBBAD
#define ELIBBAD 80 /* Accessing a corrupted shared library */
#endif

/* main.c */
extern char g_exe_path[];
extern char g_exe_dir_path[];
extern char g_dll_path[];
extern char g_dll_dir_path[];
extern char g_workdir[];

#endif /* DLL_HOTPATCH_DAEMON_COMMON */