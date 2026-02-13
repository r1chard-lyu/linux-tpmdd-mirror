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
#include <linux/rculist.h>
#include <uapi/linux/rootns.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

struct rootns init_rootns = {
	.usage		= REFCOUNT_INIT(2),
	.cred		= NULL,
	.ns		= &init_nsproxy,
	.init		= &init_task,
	.pid_ns		= &init_pid_ns,
	.members	= LIST_HEAD_INIT(init_rootns.members),
	.flags		= 0,
	.fs_ready	= true,
	.state		= ROOTNS_RUNNING,
	.members_lock	= __SPIN_LOCK_UNLOCKED(init_rootns.members_lock),
};

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

/*
 * Attach a child task as a member of the inherited rootns. The first entering
 * task sets ROOTNS_FORKING.
 */
int copy_rootns(unsigned long flags, struct task_struct *tsk,
		struct rootns *rootns)
{
	struct nsproxy *ns = tsk->nsproxy;
	struct rootns *c = rootns;
	bool admitted = false;
	int ret = -ECANCELED;

	if (!rootns && ns)
		c = ns->rootns;
	if (!c)
		return rootns ? ret : 0;
	if (!rootns && c == &init_rootns)
		return 0;
	if (unlikely(!c->ns))
		return rootns ? -EOPNOTSUPP : 0;

	spin_lock(&c->members_lock);

	if (c->state == ROOTNS_DEAD && rootns)
		ret = -ESRCH;

	if (c->state != ROOTNS_DEAD) {
		if (!rootns) {
			admitted = true;
		} else if (c->state == ROOTNS_RUNNING) {
			admitted = true;
		} else if (c->state == ROOTNS_NEW) {
			c->state = ROOTNS_FORKING;
			admitted = true;
		}
	}

	if (admitted) {
		get_task_struct(tsk);
		list_add_tail_rcu(&tsk->rootns_member, &c->members);
		get_rootns(c);
		ret = 0;
	}

	spin_unlock(&c->members_lock);
	return ret;
}

/*
 * Remove an exiting process from a rootns.
 *
 * If the rootns init process exits, signal all remaining rootns members for
 * termination.
 */
void exit_rootns(struct task_struct *tsk)
{
	bool init_exited = false;
	struct rootns *c;
	struct nsproxy *ns = tsk->nsproxy;
	struct task_struct *p;
	struct kernel_siginfo si = {
		.si_signo = SIGKILL,
		.si_code  = SI_KERNEL,
	};

	if (!ns)
		return;

	c = ns->rootns;
	if (!c)
		return;
	if (c == &init_rootns)
		return;
	if (unlikely(!c->ns))
		return;

	spin_lock(&c->members_lock);
	list_del_rcu(&tsk->rootns_member);

	if (c->init == tsk) {
		init_exited = true;
		c->init = NULL;
		c->exit_code = tsk->exit_code;
		getrusage(tsk, RUSAGE_BOTH, &c->rusage);
		smp_wmb(); /* Order exit_code vs ROOTNS_DEAD. */
		WRITE_ONCE(c->state, ROOTNS_DEAD);
	} else if (c->state == ROOTNS_FORKING &&
		   list_empty(&c->members)) {
		c->state = ROOTNS_NEW;
	}

	spin_unlock(&c->members_lock);
	synchronize_srcu(&c->member_srcu);
	put_task_struct(tsk);

	if (init_exited) {
		int idx;

		wake_up_poll(&c->waitq, EPOLLHUP);
		idx = srcu_read_lock(&c->member_srcu);
		list_for_each_entry_srcu(p, &c->members, rootns_member,
					 srcu_read_lock_held(&c->member_srcu)) {
			send_sig_info(SIGKILL, &si, p);
		}
		srcu_read_unlock(&c->member_srcu, idx);
	}

	put_rootns(c);
}

/*
 * Create credentials for a rootns. Drop keyrings from the new credential to
 * avoid unnecessary pinning. LSM auditing runs in security_rootns_alloc().
 */
static const struct cred *create_rootns_creds(unsigned int flags)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return ERR_PTR(-ENOMEM);

#ifdef CONFIG_KEYS
	key_put(new->thread_keyring);
	new->thread_keyring = NULL;
	key_put(new->process_keyring);
	new->process_keyring = NULL;
	key_put(new->session_keyring);
	new->session_keyring = NULL;
	key_put(new->request_key_auth);
	new->request_key_auth = NULL;
#endif
	if (!(flags & ROOTNS_USER))
		return new;

	ret = create_user_ns(new);
	if (ret < 0)
		goto err;
	new->euid = new->user_ns->owner;
	new->egid = new->user_ns->group;

	new->uid = new->euid;
	new->suid = new->euid;
	new->fsuid = new->euid;
	new->gid = new->egid;
	new->sgid = new->egid;
	new->fsgid = new->egid;
	ret = set_cred_ucounts(new);
	if (ret < 0)
		goto err;
	return new;

err:
	abort_creds(new);
	return ERR_PTR(ret);
}

/*
 * Create a new rootns.
 */
static struct rootns *create_rootns(unsigned int flags)
{
	const struct cred *cred;
	struct rootns *c;
	struct fs_struct *fs;
	struct nsproxy *ns;
	unsigned int clone_flags = 0;
	int ret;

	c = kzalloc_obj(*c, GFP_KERNEL);
	if (!c)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&c->members);
	init_waitqueue_head(&c->waitq);
	spin_lock_init(&c->members_lock);
	refcount_set(&c->usage, 1);
	ret = init_srcu_struct(&c->member_srcu);
	if (ret)
		goto err_free_cont;

	c->flags = flags;
	c->fs_ready = false;

	cred = create_rootns_creds(flags);
	if (IS_ERR(cred)) {
		ret = PTR_ERR(cred);
		goto err_cont;
	}
	c->cred = cred;

	ret = -ENOMEM;
	fs = copy_fs_struct(current->fs);
	if (!fs)
		goto err_cont;

	if (flags & ROOTNS_CGROUP)
		clone_flags |= CLONE_NEWCGROUP;
	if (flags & ROOTNS_UTS)
		clone_flags |= CLONE_NEWUTS;
	if (flags & ROOTNS_IPC)
		clone_flags |= CLONE_NEWIPC;
	if (flags & ROOTNS_PID)
		clone_flags |= CLONE_NEWPID;
	if (flags & ROOTNS_NET)
		clone_flags |= CLONE_NEWNET;

	ret = -EPERM;
	if (!ns_capable(cred->user_ns, CAP_SYS_ADMIN))
		goto err_fs;

	ns = create_new_namespaces(clone_flags, current->nsproxy, cred->user_ns, fs);
	if (IS_ERR(ns)) {
		ret = PTR_ERR(ns);
		goto err_fs;
	}

	c->ns = ns;
	ns->rootns = c;
	c->pid_ns = get_pid_ns(c->ns->pid_ns_for_children);
	c->root = fs->root;
	fs->root = (struct path){};
	free_fs_struct(fs);
	fs = NULL;

	nsproxy_ns_active_get(ns);

	return c;

err_fs:
	if (fs)
		free_fs_struct(fs);

err_cont:
	put_rootns(c);
	return ERR_PTR(ret);
err_free_cont:
	kfree(c);
	return ERR_PTR(ret);
}

/*
 * Create a new rootns object.
 */
SYSCALL_DEFINE1(rootns_create, unsigned int, flags)
{
	struct rootns *c;
	int fd;

	if (flags & ~ROOTNS_ALL_FLAGS)
		return -EINVAL;
	if (unlikely(!current->nsproxy->rootns ||
		     !current->nsproxy->rootns->ns))
		return -EOPNOTSUPP;

	c = create_rootns(flags);
	if (IS_ERR(c))
		return PTR_ERR(c);

	fd = anon_inode_getfd("rootns", &rootns_fops, c,
			      O_RDWR | (flags & ROOTNS_CLOSE_ON_EXEC ? O_CLOEXEC : 0));
	if (fd < 0)
		put_rootns(c);

	return fd;
}

/*
 * Wait for rootns init to exit and report results for the caller.
 *
 * Returns caller-visible init TGID on success, 0 for WNOHANG when still
 * running, and -ECHILD when init pid is not visible in caller pidns.
 */
static long rootns_wait_common(int rootnsfd, unsigned int options,
			       int *status, struct rusage *ru)
{
	long ret;
	struct pid *init_pid;
	struct rootns *rootns;
	struct fd f = fdget(rootnsfd);
	struct pid_namespace *pid_ns = task_active_pid_ns(current);

	if (fd_empty(f))
		return -EBADF;
	ret = -EINVAL;
	if (!is_rootns_file(fd_file(f)))
		goto out;
	if (options & ~WNOHANG)
		goto out;

	rootns = fd_file(f)->private_data;
	if (!(options & WNOHANG)) {
		ret = wait_event_killable(rootns->waitq,
					  READ_ONCE(rootns->state) == ROOTNS_DEAD);
		if (ret)
			goto out;
	} else if (READ_ONCE(rootns->state) != ROOTNS_DEAD) {
		ret = 0;
		goto out;
	}

	init_pid = READ_ONCE(rootns->init_pid);
	if (!init_pid) {
		ret = -ECHILD;
		goto out;
	}
	ret = pid_nr_ns(init_pid, pid_ns);
	if (ret <= 0) {
		ret = -ECHILD;
		goto out;
	}

	smp_rmb(); /* Pairs with the wmb in exit_rootns() */
	if (status)
		*status = READ_ONCE(rootns->exit_code);
	if (ru)
		*ru = rootns->rusage;

out:
	fdput(f);
	return ret;
}

SYSCALL_DEFINE4(rootns_wait, int, rootnsfd, int __user *, status,
		unsigned int, options, struct rusage __user *, ru)
{
	int code;
	long ret;
	struct rusage rusage;

	ret = rootns_wait_common(rootnsfd, options,
				 status ? &code : NULL,
				 ru ? &rusage : NULL);
	if (ret <= 0)
		return ret;

	if (status && put_user(code, status))
		return -EFAULT;
	if (ru && copy_to_user(ru, &rusage, sizeof(rusage)))
		return -EFAULT;
	return ret;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(rootns_wait, int, rootnsfd,
		       compat_int_t __user *, status,
		       unsigned int, options,
		       struct compat_rusage __user *, ru)
{
	int code;
	long ret;
	struct rusage rusage;

	ret = rootns_wait_common(rootnsfd, options,
				 status ? &code : NULL,
				 ru ? &rusage : NULL);
	if (ret <= 0)
		return ret;

	if (status && put_user(code, status))
		return -EFAULT;
	if (ru && put_compat_rusage(&rusage, ru))
		return -EFAULT;
	return ret;
}
#endif
