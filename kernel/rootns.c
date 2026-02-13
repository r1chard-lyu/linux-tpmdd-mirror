// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 */

#include <linux/poll.h>
#include <linux/wait.h>
#include <uapi/linux/wait.h>
#include <linux/init_task.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/anon_inodes.h>
#include <linux/rootns.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/nsfs.h>
#include <linux/pid.h>
#include <linux/compat.h>
#include <uapi/linux/rootns.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
 * Get a reference to a rootns.
 */
struct rootns *get_rootns(struct rootns *c)
{
	refcount_inc(&c->usage);
	return c;
}

/*
 * Drop a reference on a rootns and clear it if it is no longer in use.
 */
void put_rootns(struct rootns *c)
{
	if (!c || !refcount_dec_and_test(&c->usage))
		return;

	WARN_ON(!list_empty(&c->members));
	if (c->pid_ns)
		put_pid_ns(c->pid_ns);
	if (c->ns)
		put_nsproxy(c->ns);
	path_put(&c->root);

	if (c->init_pid)
		put_pid(c->init_pid);
	if (c->cred)
		put_cred(c->cred);
	cleanup_srcu_struct(&c->member_srcu);
	kfree(c);
}

/*
 * Allow the user to poll for the rootns dying.
 */
static unsigned int rootns_poll(struct file *file, poll_table *wait)
{
	struct rootns *rootns = file->private_data;
	unsigned int mask = 0;

	poll_wait(file, &rootns->waitq, wait);

	if (READ_ONCE(rootns->state) == ROOTNS_DEAD)
		mask |= POLLHUP;

	return mask;
}

static int __rootns_kill(struct rootns *rootns, int sig, bool priv)
{
	struct task_struct *init;
	struct pid *pid;
	int ret;

	spin_lock(&rootns->members_lock);
	init = rootns->init;
	if (init)
		get_task_struct(init);
	spin_unlock(&rootns->members_lock);

	if (!init)
		return -ESRCH;

	pid = get_task_pid(init, PIDTYPE_TGID);
	put_task_struct(init);
	if (!pid)
		return -ESRCH;

	ret = kill_pid(pid, sig, priv);
	put_pid(pid);
	return ret;
}

static int rootns_release(struct inode *inode, struct file *file)
{
	struct rootns *rootns = file->private_data;

	if (rootns->flags & ROOTNS_KILL_ON_CLOSE)
		__rootns_kill(rootns, SIGKILL, true);
	put_rootns(rootns);
	return 0;
}

static const struct file_operations rootns_fops = {
	.poll		= rootns_poll,
	.release	= rootns_release,
};

/*
 * Returns true if the file is a rootns.
 */
bool is_rootns_file(struct file *file)
{
	return file->f_op == &rootns_fops;
}
