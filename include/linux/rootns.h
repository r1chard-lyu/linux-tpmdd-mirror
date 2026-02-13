/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 */

#ifndef _LINUX_ROOTNS_H
#define _LINUX_ROOTNS_H

#include <linux/fs.h>
#include <linux/refcount.h>
#include <linux/resource.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/path.h>
#include <linux/seqlock.h>
#include <linux/srcu.h>

struct fs_struct;
struct file;
struct ns_common;
struct nsproxy;
struct pid;
struct task_struct;

enum rootns_state {
	ROOTNS_NEW	= 0,	/* Init not started */
	ROOTNS_FORKING	= 1,	/* Init fork admitted but not committed */
	ROOTNS_RUNNING	= 2,	/* Init has been committed */
	ROOTNS_DEAD	= 3,	/* Init has exited */
};

/*
 * The rootns object.
 */
struct rootns {
	refcount_t		usage;
	u64			id;
	int			exit_code;	/* The exit code of 'init' */
	struct rusage		rusage;		/* Resource usage of 'init' */
	const struct cred	*cred;		/* Creds for this rootns, including userns */
	struct nsproxy		*ns;		/* This rootns's namespaces */
	struct path		root;		/* The root of the rootns's fs namespace */
	struct task_struct	*init;		/* The 'init' task for this rootns */
	struct pid		*init_pid;	/* The 'init' task's TGID (pid ref) */
	struct pid_namespace	*pid_ns;	/* The process ID namespace for this rootns */
	void			*security;	/* LSM data */
	struct list_head	members;	/* Member processes, guarded with ->lock */
	struct srcu_struct	member_srcu;
	spinlock_t		members_lock;	/* Guards members and rootns lifecycle state */
	wait_queue_head_t	waitq;		/* Someone waiting for init to exit waits here */
	unsigned int		flags;		/* Validated rootns_create() flags */
	bool			fs_ready;	/* Root mount installed and enterable */
	u8			state;		/* Root namespace lifecycle state */
};

#ifdef CONFIG_ROOTNS
extern struct rootns init_rootns;

struct rootns *get_rootns(struct rootns *c);
void put_rootns(struct rootns *c);
bool is_rootns_file(struct file *file);
int copy_rootns(unsigned long flags, struct task_struct *tsk,
		struct rootns *rootns);
void exit_rootns(struct task_struct *tsk);
void rootns_tag_ns(struct rootns *rootns, struct ns_common *ns);
void rootns_tag_nsproxy(struct rootns *rootns, struct nsproxy *ns, u64 flags);
bool rootns_may_setns(struct rootns *rootns, struct ns_common *ns);
#else
static inline struct rootns *get_rootns(struct rootns *c)
{
	return NULL;
}

static inline void put_rootns(struct rootns *c)
{
}

static inline bool is_rootns_file(struct file *file)
{
	return false;
}

static inline int copy_rootns(unsigned long flags, struct task_struct *tsk,
			      struct rootns *rootns)
{
	return 0;
}

static inline void exit_rootns(struct task_struct *tsk)
{
}

static inline void rootns_tag_ns(struct rootns *rootns, struct ns_common *ns)
{
}

static inline void rootns_tag_nsproxy(struct rootns *rootns,
				     struct nsproxy *ns, u64 flags)
{
}

static inline bool rootns_may_setns(struct rootns *rootns,
				    struct ns_common *ns)
{
	return true;
}
#endif /* CONFIG_ROOTNS */

#endif /* _LINUX_ROOTNS_H */
