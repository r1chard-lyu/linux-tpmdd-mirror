/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _UAPI_LINUX_ROOTNS_H
#define _UAPI_LINUX_ROOTNS_H

/**
 * DOC: Root namespace system calls
 *
 * ``rootns_create()`` takes a single flags parameter that combines namespace
 * selection and creation options, and returns a rootns control fd.
 *
 * Userspace must install a root mount via
 * %FSCONFIG_SET_ROOTNS and %MOVE_MOUNT_T_ROOTNS_ROOT before calling
 * ``rootns_enter()``.
 */

/**
 * DOC: Root namespace flags
 *
 * Namespace selection flags:
 *
 * * %ROOTNS_CGROUP
 * * %ROOTNS_UTS
 * * %ROOTNS_IPC
 * * %ROOTNS_USER
 * * %ROOTNS_PID
 * * %ROOTNS_NET
 *
 * Set a namespace bit to create the corresponding namespace for the rootns.
 * If a namespace bit is clear, that namespace is inherited from the caller.
 *
 * Other flags:
 *
 * * %ROOTNS_KILL_ON_CLOSE: send %SIGKILL to rootns init when the last
 *   reference to the rootns fd is released.
 * * %ROOTNS_CLOSE_ON_EXEC: set close-on-exec on the fd returned by
 *   ``rootns_create()``.
 *
 * Convenience masks:
 *
 * * %ROOTNS_ALL_NAMESPACES: all namespace selection flags.
 * * %ROOTNS_ALL_FLAGS: all valid flags accepted by ``rootns_create()``.
 */
enum {
	ROOTNS_CGROUP		= 0x00000001,
	ROOTNS_UTS		= 0x00000002,
	ROOTNS_IPC		= 0x00000004,
	ROOTNS_USER		= 0x00000008,
	ROOTNS_PID		= 0x00000010,
	ROOTNS_NET		= 0x00000020,
	ROOTNS_KILL_ON_CLOSE	= 0x00000100,
	ROOTNS_CLOSE_ON_EXEC	= 0x00000200,
	ROOTNS_ALL_NAMESPACES	= 0x0000003f,
	ROOTNS_ALL_FLAGS	= 0x0000033f,
};

#endif /* _UAPI_LINUX_ROOTNS_H */
