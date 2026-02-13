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
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/cgroup_namespace.h>
#include <linux/nsproxy.h>
#include <linux/nsfs.h>
#include <linux/pid.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <linux/atomic.h>
#include <linux/ns_common.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
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

static atomic64_t rootns_id = ATOMIC64_INIT(0);

void rootns_tag_ns(struct rootns *rootns, struct ns_common *ns)
{
	if (!rootns || rootns == &init_rootns || !ns)
		return;

	ns->rootns_id = rootns->id;
}

void rootns_tag_nsproxy(struct rootns *rootns, struct nsproxy *ns, u64 flags)
{
	if (!rootns || !ns)
		return;

	if (flags & CLONE_NEWNS)
		rootns_tag_ns(rootns, &ns->mnt_ns->ns);
#ifdef CONFIG_UTS_NS
	if (flags & CLONE_NEWUTS)
		rootns_tag_ns(rootns, &ns->uts_ns->ns);
#endif
#ifdef CONFIG_IPC_NS
	if (flags & CLONE_NEWIPC)
		rootns_tag_ns(rootns, &ns->ipc_ns->ns);
#endif
#ifdef CONFIG_PID_NS
	if (flags & CLONE_NEWPID)
		rootns_tag_ns(rootns, &ns->pid_ns_for_children->ns);
#endif
#ifdef CONFIG_CGROUPS
	if (flags & CLONE_NEWCGROUP)
		rootns_tag_ns(rootns, &ns->cgroup_ns->ns);
#endif
#ifdef CONFIG_NET_NS
	if (flags & CLONE_NEWNET)
		rootns_tag_ns(rootns, &ns->net_ns->ns);
#endif
#ifdef CONFIG_TIME_NS
	if (flags & CLONE_NEWTIME)
		rootns_tag_ns(rootns, &ns->time_ns_for_children->ns);
#endif
}

bool rootns_may_setns(struct rootns *rootns, struct ns_common *ns)
{
	if (!ns)
		return false;
	if (!rootns || rootns == &init_rootns)
		return true;
	if (is_current_namespace(ns))
		return true;

	return ns->rootns_id == rootns->id;
}

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
	security_rootns_free(c);
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
	c->id = atomic64_inc_return(&rootns_id);
	c->fs_ready = false;

	cred = create_rootns_creds(flags);
	if (IS_ERR(cred)) {
		ret = PTR_ERR(cred);
		goto err_cont;
	}
	c->cred = cred;
	if (flags & ROOTNS_USER)
		rootns_tag_ns(c, &cred->user_ns->ns);

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
	rootns_tag_nsproxy(c, ns, clone_flags);
	c->pid_ns = get_pid_ns(c->ns->pid_ns_for_children);
	c->root = fs->root;
	fs->root = (struct path){};
	free_fs_struct(fs);
	fs = NULL;

	nsproxy_ns_active_get(ns);

	ret = security_rootns_alloc(c, flags);
	if (ret < 0)
		goto err_fs;
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

static int contain_kill_members(struct rootns *rootns, int sig)
{
	int err;
	int idx;
	int ret = 0;
	struct pid *pid;
	int other_err = 0;
	bool any_perm = false;
	bool any_other = false;
	bool any_success = false;
	struct task_struct *p;

	idx = srcu_read_lock(&rootns->member_srcu);
	list_for_each_entry_srcu(p, &rootns->members, rootns_member,
				 srcu_read_lock_held(&rootns->member_srcu)) {
		pid = task_pid_type(p, PIDTYPE_TGID);
		if (!pid)
			continue;

		err = kill_pid(pid, sig, 0);

		if (!err) {
			any_success = true;
		} else if (err == -EPERM) {
			any_perm = true;
		} else if (err != -ESRCH && !any_other) {
			any_other = true;
			other_err = err;
		}
	}
	srcu_read_unlock(&rootns->member_srcu, idx);

	if (any_success)
		ret = 0;
	else if (any_other)
		ret = other_err;
	else if (any_perm)
		ret = -EPERM;
	else
		ret = -ESRCH;

	return ret;
}

/*
 * Send a signal to all current rootns members.
 */
SYSCALL_DEFINE2(rootns_kill, int, rootnsfd, int, sig)
{
	int ret = 0;
	struct rootns *rootns;
	struct fd f = fdget(rootnsfd);

	if (fd_empty(f))
		return -EBADF;
	ret = -EINVAL;
	if (!is_rootns_file(fd_file(f)))
		goto out;

	rootns = fd_file(f)->private_data;
	if (!valid_signal(sig)) {
		ret = -EINVAL;
		goto out;
	}

	ret = contain_kill_members(rootns, sig);
	goto out;

out:
	fdput(f);
	return ret;
}

/*
 * Enter an existing rootns.
 *
 * The target rootns pid namespace must be visible from the caller's active
 * pid namespace so the parent receives a usable pid return value.
 */
SYSCALL_DEFINE1(rootns_enter, int, rootnsfd)
{
	int ret;
	struct rootns *rootns;
	bool fs_ready;
	struct fd f = fdget(rootnsfd);
	struct kernel_clone_args args = {
		.exit_signal = SIGCHLD,
	};

	if (fd_empty(f))
		return -EBADF;
	ret = -EINVAL;
	if (is_rootns_file(fd_file(f))) {
		rootns = fd_file(f)->private_data;

		args.rootns = rootns;
		spin_lock(&rootns->members_lock);
		fs_ready = rootns->fs_ready;
		spin_unlock(&rootns->members_lock);
		if (!rootns->ns)
			ret = -EOPNOTSUPP;
		else if (!pidns_is_ancestor(rootns->pid_ns,
					    task_active_pid_ns(current)))
			ret = -EXDEV;
		else if (!fs_ready)
			ret = -ENOENT;
		else
			ret = kernel_clone(&args);
	}

	fdput(f);
	return ret;
}
