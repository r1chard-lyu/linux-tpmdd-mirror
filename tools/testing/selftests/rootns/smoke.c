// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Opinsys Oy
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include "kselftest_harness.h"
#include "../../../../include/uapi/linux/mount.h"
#include "../../../../include/uapi/linux/rootns.h"

#ifndef __NR_open_tree
#define __NR_open_tree -1
#endif
#ifndef __NR_move_mount
#define __NR_move_mount -1
#endif
#ifndef __NR_fsopen
#define __NR_fsopen -1
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig -1
#endif
#ifndef __NR_fsmount
#define __NR_fsmount -1
#endif

#define ROOTNS_ERRNO_NOSYS 38

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static int open_tree(int dfd, const char *path, unsigned int flags)
{
	errno = 0;
	return syscall(__NR_open_tree, dfd, (unsigned long)path, flags, 0, 0);
}

static int move_mount(int from_dfd, const char *from_path, int to_dfd,
		      const char *to_path, unsigned int flags)
{
	errno = 0;
	return syscall(__NR_move_mount, from_dfd, (unsigned long)from_path, to_dfd,
		       (unsigned long)to_path, flags);
}

static int fsopen(const char *fsname, unsigned int flags)
{
	errno = 0;
	return syscall(__NR_fsopen, (unsigned long)fsname, flags, 0, 0, 0);
}

static int fsconfig(int fsfd, unsigned int cmd, const char *key,
		    const char *value, int aux)
{
	errno = 0;
	return syscall(__NR_fsconfig, fsfd, cmd, (unsigned long)key,
		       (unsigned long)value, aux);
}

static int fsmount(int fsfd, unsigned int flags, unsigned int attr_flags)
{
	errno = 0;
	return syscall(__NR_fsmount, fsfd, flags, attr_flags, 0, 0);
}

#ifndef __NR_rootns_create
#if defined(__x86_64__) || defined(__i386)
#define __NR_rootns_create 472
#else
#define __NR_rootns_create -1
#endif
#endif
#ifndef __NR_rootns_wait
#if defined(__x86_64__) || defined(__i386)
#define __NR_rootns_wait 473
#else
#define __NR_rootns_wait -1
#endif
#endif
#ifndef __NR_rootns_kill
#if defined(__x86_64__) || defined(__i386)
#define __NR_rootns_kill 474
#else
#define __NR_rootns_kill -1
#endif
#endif
#ifndef __NR_rootns_enter
#if defined(__x86_64__) || defined(__i386)
#define __NR_rootns_enter 475
#else
#define __NR_rootns_enter -1
#endif
#endif

static bool rootns_syscalls_declared(void)
{
	return __NR_rootns_create >= 0 &&
	       __NR_rootns_wait >= 0 &&
	       __NR_rootns_kill >= 0 &&
	       __NR_rootns_enter >= 0;
}

static int rootns_create(unsigned int flags)
{
	errno = 0;
	return syscall(__NR_rootns_create, flags, 0, 0, 0, 0);
}

static int rootns_enter(int cfd)
{
	errno = 0;
	return syscall(__NR_rootns_enter, cfd, 0, 0, 0, 0);
}

static int rootns_wait(int cfd, int *status, unsigned int options, struct rusage *ru)
{
	errno = 0;
	return syscall(__NR_rootns_wait, cfd, status, options, ru, 0);
}

static int rootns_kill(int cfd, int sig)
{
	errno = 0;
	return syscall(__NR_rootns_kill, cfd, sig, 0, 0, 0);
}

static int wait_for_pid_exit(pid_t pid, int *status, unsigned int timeout_ms)
{
	const unsigned int step_ms = 10;
	unsigned int elapsed_ms = 0;
	int ret;

	while (elapsed_ms <= timeout_ms) {
		ret = waitpid(pid, status, WNOHANG);
		if (ret == pid)
			return 0;
		if (ret < 0)
			return -1;

		usleep(step_ms * 1000);
		elapsed_ms += step_ms;
	}

	errno = ETIMEDOUT;
	return -1;
}

static void kill_and_reap_pid(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;

	if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
		return;

	(void)waitpid(pid, &status, 0);
}

static int clone_exit(void *arg)
{
	return 0;
}

static int clone_with_flags(int flags)
{
	const size_t stack_size = 1024 * 1024;
	void *stack;
	pid_t pid;
	int status;
	int ret;

	stack = malloc(stack_size);
	if (!stack)
		return -ENOMEM;

	pid = clone(clone_exit, (char *)stack + stack_size,
		    SIGCHLD | flags, NULL);
	if (pid < 0) {
		ret = -errno;
	} else {
		if (waitpid(pid, &status, 0) < 0)
			ret = -errno;
		else if (!WIFEXITED(status) || WEXITSTATUS(status))
			ret = -EIO;
		else
			ret = 0;
	}

	free(stack);
	return ret;
}

static int send_fd(int sockfd, int fd)
{
	char marker = 'R';
	char control[CMSG_SPACE(sizeof(fd))];
	struct iovec iov = {
		.iov_base = &marker,
		.iov_len = sizeof(marker),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;

	memset(control, 0, sizeof(control));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	return sendmsg(sockfd, &msg, 0);
}

static int recv_fd(int sockfd)
{
	char marker;
	int fd;
	char control[CMSG_SPACE(sizeof(fd))];
	struct iovec iov = {
		.iov_base = &marker,
		.iov_len = sizeof(marker),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;

	memset(control, 0, sizeof(control));
	if (recvmsg(sockfd, &msg, 0) < 0)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg ||
	    cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len < CMSG_LEN(sizeof(fd))) {
		errno = EPROTO;
		return -1;
	}

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}

static int send_unshared_mntns_and_wait(int sockfd)
{
	ssize_t nread;
	char ch;
	int nsfd;
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret)
		return 1;

	nsfd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	if (nsfd < 0)
		return 2;

	ret = send_fd(sockfd, nsfd);
	close(nsfd);
	if (ret < 0)
		return 3;

	nread = read(sockfd, &ch, sizeof(ch));
	if (nread != sizeof(ch))
		return 4;

	return 0;
}

static int create_rootns_as_uid(uid_t uid, unsigned int flags, int *cfd)
{
	pid_t pid;
	int sv[2];
	int pipefd[2];
	int err = 0;
	int status;
	ssize_t nread;

	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -errno;

	if (pipe2(pipefd, O_CLOEXEC) < 0) {
		err = -errno;
		close(sv[0]);
		close(sv[1]);
		return err;
	}

	pid = fork();
	if (pid < 0) {
		err = -errno;
		close(pipefd[0]);
		close(pipefd[1]);
		close(sv[0]);
		close(sv[1]);
		return err;
	}

	if (pid == 0) {
		int child_fd = -1;

		close(pipefd[0]);
		close(sv[0]);

		if (setresuid(uid, uid, uid) < 0) {
			err = errno;
			goto out_child;
		}

		child_fd = rootns_create(flags);
		if (child_fd < 0) {
			err = errno;
			goto out_child;
		}

		if (send_fd(sv[1], child_fd) < 0) {
			err = errno;
			goto out_child;
		}

out_child:
		if (child_fd >= 0)
			close(child_fd);
		(void)write(pipefd[1], &err, sizeof(err));
		close(pipefd[1]);
		close(sv[1]);
		_exit(err ? 1 : 0);
	}

	close(pipefd[1]);
	close(sv[1]);

	nread = read(pipefd[0], &err, sizeof(err));
	close(pipefd[0]);
	if (nread != sizeof(err)) {
		if (nread < 0)
			err = errno;
		else
			err = EPROTO;
	}

	if (!err) {
		*cfd = recv_fd(sv[0]);
		if (*cfd < 0)
			err = errno;
	}
	close(sv[0]);

	if (waitpid(pid, &status, 0) != pid && !err)
		err = errno;
	if (!err && !WIFEXITED(status))
		err = ECHILD;
	if (!err && WEXITSTATUS(status))
		err = ECHILD;

	return err ? -err : 0;
}

static int mount_dir(int rootfd, const char *from, const char *to)
{
	int mfd;

	mfd = open_tree(AT_FDCWD, from, OPEN_TREE_CLONE);
	if (mfd < 0)
		return (errno == ENOENT) ? 0 : -1;

	if (move_mount(mfd, "", rootfd, to, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		close(mfd);
		return -1;
	}

	close(mfd);
	return 0;
}

static int mount_root(int cfd)
{
	static const struct {
		const char *host;
		const char *target;
	} mounts[] = {
		{ "/bin", "bin" },
		{ "/sbin", "sbin" },
		{ "/lib", "lib" },
		{ "/lib64", "lib64" },
		{ "/usr", "usr" },
		{ "/etc", "etc" },
		{ "/dev", "dev" },
	};
	static const char *const dirs[] = {
		"bin", "sbin", "lib", "lib64", "usr", "etc", "dev", "tmp", "proc"
	};
	int saved_errno;
	int fsfd;
	int rootfd;
	size_t i;
	int ret;

	fsfd = fsopen("tmpfs", 0);
	if (fsfd < 0) {
		perror("fsopen");
		return -1;
	}

	ret = fsconfig(fsfd, FSCONFIG_SET_ROOTNS, NULL, NULL, cfd);
	if (ret < 0) {
		perror("fsconfig(FSCONFIG_SET_ROOTNS)");
		goto err_rootfs;
	}

	ret = fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (ret < 0) {
		perror("fsconfig(FSCONFIG_CMD_CREATE)");
		goto err_rootfs;
	}

	rootfd = fsmount(fsfd, 0, 0);
	if (rootfd < 0) {
		perror("fsmount");
		goto err_rootfs;
	}

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		ret = mkdirat(rootfd, dirs[i], 0755);
		if (ret < 0 && errno != EEXIST) {
			perror("mkdirat");
			return -1;
		}
	}

	for (i = 0; i < ARRAY_SIZE(mounts); i++) {
		ret = mount_dir(rootfd, mounts[i].host, mounts[i].target);
		if (ret < 0)
			goto err_root;
	}

	ret = move_mount(rootfd, "", cfd, "/",
			 MOVE_MOUNT_F_EMPTY_PATH |
			 MOVE_MOUNT_T_ROOTNS_ROOT);
	if (ret < 0) {
		perror("move_mount");
		goto err_root;
	}

	close(rootfd);
	close(fsfd);
	return 0;

err_root:
	saved_errno = errno;
	close(rootfd);
	errno = saved_errno;

err_rootfs:
	close(fsfd);
	return -1;
}

static int mount_proc(int cfd, bool need_proc)
{
	const char *fstype = need_proc ? "proc" : "tmpfs";
	int saved_errno;
	int fsfd;
	int mfd;
	int ret;

	fsfd = fsopen(fstype, 0);
	if (fsfd < 0)
		return -1;

	ret = fsconfig(fsfd, FSCONFIG_SET_ROOTNS, NULL, NULL, cfd);
	if (ret < 0)
		goto err_out;

	ret = fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (ret < 0)
		goto err_out;

	mfd = fsmount(fsfd, 0, 0);
	if (mfd < 0)
		goto err_out;

	ret = move_mount(mfd, "", cfd, "proc",
			 MOVE_MOUNT_F_EMPTY_PATH |
			 MOVE_MOUNT_T_ROOTNS_ROOT);
	if (ret < 0) {
		saved_errno = errno;
		close(mfd);
		errno = saved_errno;
		goto err_out;
	}

	close(mfd);
	close(fsfd);
	return 0;

err_out:
	saved_errno = errno;
	close(fsfd);
	errno = saved_errno;
	return -1;
}

static int rootns_setup(bool need_proc, unsigned int flags)
{
	int cfd;
	int saved_errno;

	cfd = rootns_create(flags);
	if (cfd < 0) {
		saved_errno = errno;
		perror("rootns_create");
		errno = saved_errno;
		return -1;
	}

	if (mount_root(cfd) < 0)
		goto err_out;

	if (mount_proc(cfd, need_proc) < 0)
		goto err_out;

	return cfd;

err_out:
	saved_errno = errno;
	close(cfd);
	errno = saved_errno;
	return -1;
}

FIXTURE(rootns_fixture) {
	int alpha_cfd;
};

FIXTURE_SETUP(rootns_fixture) {
	if (!rootns_syscalls_declared())
		SKIP(return, "rootns syscalls are not declared for this architecture");

	self->alpha_cfd = rootns_setup(false, ROOTNS_ALL_NAMESPACES |
					      ROOTNS_KILL_ON_CLOSE |
					      ROOTNS_CLOSE_ON_EXEC);
	if (self->alpha_cfd < 0 && errno == ROOTNS_ERRNO_NOSYS)
		SKIP(return, "rootns syscalls are not available in this kernel");

	ASSERT_GT(self->alpha_cfd, 0);
}

FIXTURE_TEARDOWN(rootns_fixture) {
	if (self->alpha_cfd > 0)
		close(self->alpha_cfd);
}

TEST_F(rootns_fixture, setup_has_valid_rootns_fd) {
	ASSERT_GT(self->alpha_cfd, 0);
}

TEST_F(rootns_fixture, lifecycle_kill_terminates_all_members) {
	int pid1 = -1, pid2 = -1;
	int status;
	int ret;

	/* Spawn two rootns members. */
	pid1 = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid1, 0);
	if (pid1 == 0) {
		/*
		 * Drop the inherited control fd.
		 * Keep parent close and release behavior deterministic.
		 */
		close(self->alpha_cfd);
		while (1)
			pause();
	}
	ASSERT_GT(pid1, 0);

	pid2 = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid2, 0);
	if (pid2 == 0) {
		close(self->alpha_cfd);
		while (1)
			pause();
	}
	ASSERT_GT(pid2, 0);

	/* Kill all members with a non-ignorable signal. */
	ASSERT_EQ(rootns_kill(self->alpha_cfd, SIGKILL), 0);

	ret = wait_for_pid_exit(pid2, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid2);
		kill_and_reap_pid(pid1);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFSIGNALED(status));
	ASSERT_EQ(WTERMSIG(status), SIGKILL);

	ret = wait_for_pid_exit(pid1, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid1);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFSIGNALED(status));
	ASSERT_EQ(WTERMSIG(status), SIGKILL);
}

TEST_F(rootns_fixture, lifecycle_wait_reports_init_exit) {
	int pid;
	int status = 0;
	int ret;

	pid = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid, 0);
	if (pid == 0)
		exit(123);
	ASSERT_GT(pid, 0);

	/* rootns_wait must return init PID and exit status. */
	ret = rootns_wait(self->alpha_cfd, &status, 0, NULL);
	ASSERT_EQ(ret, pid);
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 123);
}

TEST_F(rootns_fixture, lifecycle_enter_dead_rootns_fails_esrch) {
	int pid;
	int status = 0;
	int ret;

	pid = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid, 0);
	if (pid == 0)
		_exit(0);
	ASSERT_GT(pid, 0);

	ret = rootns_wait(self->alpha_cfd, &status, 0, NULL);
	ASSERT_EQ(ret, pid);
	ASSERT_TRUE(WIFEXITED(status));

	ASSERT_EQ(rootns_enter(self->alpha_cfd), -1);
	ASSERT_EQ(errno, ESRCH);
}

TEST_F(rootns_fixture, policy_nested_namespaces_are_allowed) {
	int nsfd;
	int pid;
	int status = 0;
	int ret;

	nsfd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(nsfd, 0);

	pid = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int ret;

		close(self->alpha_cfd);

		ret = unshare(CLONE_NEWNS);
		if (ret)
			_exit(1);

		ret = clone_with_flags(CLONE_NEWNS);
		if (ret)
			_exit(2);

		ret = unshare(CLONE_NEWUSER);
		if (ret)
			_exit(3);

		ret = clone_with_flags(CLONE_NEWUSER);
		if (ret)
			_exit(4);

		ret = setns(nsfd, CLONE_NEWNS);
		if (ret != -1 || errno != EPERM)
			_exit(5);

		close(nsfd);
		_exit(0);
	}
	ASSERT_GT(pid, 0);

	close(nsfd);
	ret = wait_for_pid_exit(pid, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(rootns_fixture, policy_setns_same_rootns_namespace_is_allowed) {
	ssize_t nwritten;
	int status = 0;
	char ch;
	int nsfd;
	int pid1;
	int pid2;
	int sv[2];
	int ret;

	ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv), 0);

	pid1 = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid1, 0);
	if (pid1 == 0) {
		close(self->alpha_cfd);
		close(sv[0]);
		ret = send_unshared_mntns_and_wait(sv[1]);
		close(sv[1]);
		_exit(ret);
	}
	ASSERT_GT(pid1, 0);
	close(sv[1]);

	nsfd = recv_fd(sv[0]);
	ASSERT_GE(nsfd, 0);

	pid2 = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid2, 0);
	if (pid2 == 0) {
		close(self->alpha_cfd);
		close(sv[0]);

		ret = setns(nsfd, CLONE_NEWNS);
		close(nsfd);
		_exit(ret ? 1 : 0);
	}
	ASSERT_GT(pid2, 0);
	close(nsfd);

	ret = wait_for_pid_exit(pid2, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid2);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);

	ch = 'x';
	nwritten = write(sv[0], &ch, sizeof(ch));
	ASSERT_EQ(nwritten, sizeof(ch));
	close(sv[0]);

	ret = wait_for_pid_exit(pid1, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid1);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(policy_setns_cross_rootns_namespace_fails) {
	unsigned int flags = (ROOTNS_ALL_NAMESPACES & ~ROOTNS_USER) |
			     ROOTNS_KILL_ON_CLOSE | ROOTNS_CLOSE_ON_EXEC;
	ssize_t nwritten;
	int status = 0;
	int alpha_cfd;
	int beta_cfd;
	int alpha_pid;
	int beta_pid;
	char ch;
	int nsfd;
	int sv[2];
	int ret;

	if (!rootns_syscalls_declared())
		SKIP(return, "rootns syscalls are not declared for this architecture");

	alpha_cfd = rootns_setup(false, flags);
	if (alpha_cfd < 0 && errno == ROOTNS_ERRNO_NOSYS)
		SKIP(return, "rootns syscalls are not available in this kernel");
	ASSERT_GE(alpha_cfd, 0);

	beta_cfd = rootns_setup(false, flags);
	ASSERT_GE(beta_cfd, 0);

	ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv), 0);

	beta_pid = rootns_enter(beta_cfd);
	ASSERT_GE(beta_pid, 0);
	if (beta_pid == 0) {
		close(alpha_cfd);
		close(beta_cfd);
		close(sv[0]);
		ret = send_unshared_mntns_and_wait(sv[1]);
		close(sv[1]);
		_exit(ret);
	}
	ASSERT_GT(beta_pid, 0);
	close(sv[1]);

	nsfd = recv_fd(sv[0]);
	ASSERT_GE(nsfd, 0);

	alpha_pid = rootns_enter(alpha_cfd);
	ASSERT_GE(alpha_pid, 0);
	if (alpha_pid == 0) {
		close(alpha_cfd);
		close(beta_cfd);
		close(sv[0]);

		ret = setns(nsfd, CLONE_NEWNS);
		close(nsfd);
		if (ret != -1 || errno != EPERM)
			_exit(1);
		_exit(0);
	}
	ASSERT_GT(alpha_pid, 0);
	close(nsfd);

	ret = wait_for_pid_exit(alpha_pid, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(alpha_pid);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);

	ch = 'x';
	nwritten = write(sv[0], &ch, sizeof(ch));
	ASSERT_EQ(nwritten, sizeof(ch));
	close(sv[0]);

	ret = wait_for_pid_exit(beta_pid, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(beta_pid);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);

	close(alpha_cfd);
	close(beta_cfd);
}

TEST_F(rootns_fixture, mount_relative_target_is_resolved_from_rootns_root) {
	int pid;
	int status = 0;
	int ret;

	pid = rootns_enter(self->alpha_cfd);
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		struct statfs st;

		close(self->alpha_cfd);
		if (statfs("/proc", &st) < 0)
			_exit(1);
		if ((unsigned long)st.f_type != (unsigned long)TMPFS_MAGIC)
			_exit(2);
		_exit(0);
	}
	ASSERT_GT(pid, 0);

	ret = wait_for_pid_exit(pid, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
}

TEST(lifecycle_close_fd_kills_init) {
	int cfd;
	int pid;
	int status;
	int ret;

	if (!rootns_syscalls_declared())
		SKIP(return, "rootns syscalls are not declared for this architecture");

	cfd = rootns_setup(false, ROOTNS_ALL_NAMESPACES | ROOTNS_KILL_ON_CLOSE);
	if (cfd < 0 && errno == ROOTNS_ERRNO_NOSYS)
		SKIP(return, "rootns syscalls are not available in this kernel");

	ASSERT_GT(cfd, 0);

	pid = rootns_enter(cfd);
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		close(cfd);
		while (1)
			pause();
	}
	ASSERT_GT(pid, 0);

	/* Closing the fd must kill rootns init. */
	close(cfd);

	ret = wait_for_pid_exit(pid, &status, 5000);
	if (ret < 0) {
		kill_and_reap_pid(pid);
		ASSERT_EQ(ret, 0);
	}
	ASSERT_TRUE(WIFSIGNALED(status));
	ASSERT_EQ(WTERMSIG(status), SIGKILL);
}

TEST(mount_target_requires_capability) {
	int cfd;
	int fsfd;
	int rootfsfd;
	int mfd;
	int ret;

	if (!rootns_syscalls_declared())
		SKIP(return, "rootns syscalls are not declared for this architecture");

	ret = create_rootns_as_uid(1000, ROOTNS_ALL_NAMESPACES | ROOTNS_USER, &cfd);
	if (ret == -EPERM || ret == -EACCES)
		SKIP(return, "unprivileged ROOTNS_USER creation is unavailable");
	if (ret == -ROOTNS_ERRNO_NOSYS)
		SKIP(return, "rootns syscalls are not available in this kernel");
	ASSERT_EQ(ret, 0);

	fsfd = fsopen("tmpfs", 0);
	ASSERT_GE(fsfd, 0);
	ASSERT_EQ(fsconfig(fsfd, FSCONFIG_SET_ROOTNS, NULL, NULL, cfd), -1);
	ASSERT_EQ(errno, EPERM);
	close(fsfd);

	rootfsfd = fsopen("tmpfs", 0);
	ASSERT_GE(rootfsfd, 0);
	ASSERT_EQ(fsconfig(rootfsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0), 0);

	mfd = fsmount(rootfsfd, 0, 0);
	ASSERT_GE(mfd, 0);

	ASSERT_EQ(move_mount(mfd, "", cfd, "/",
			     MOVE_MOUNT_F_EMPTY_PATH |
			     MOVE_MOUNT_T_ROOTNS_ROOT), -1);
	ASSERT_EQ(errno, EPERM);

	close(mfd);
	close(rootfsfd);
	close(cfd);
}

TEST(mount_root_install_rejects_attached_source) {
	int cfd;

	if (!rootns_syscalls_declared())
		SKIP(return, "rootns syscalls are not declared for this architecture");

	cfd = rootns_create(ROOTNS_ALL_NAMESPACES |
			    ROOTNS_KILL_ON_CLOSE |
			    ROOTNS_CLOSE_ON_EXEC);
	if (cfd < 0 && errno == ROOTNS_ERRNO_NOSYS)
		SKIP(return, "rootns syscalls are not available in this kernel");
	ASSERT_GT(cfd, 0);

	/*
	 * Al Viro review point: cross-namespace root install must not accept
	 * attached sources that could confuse attach_recursive_mnt().
	 */
	ASSERT_EQ(move_mount(AT_FDCWD, "/", cfd, "/", MOVE_MOUNT_T_ROOTNS_ROOT), -1);
	ASSERT_EQ(errno, EINVAL);

	close(cfd);
}

TEST(mount_root_install_rejects_empty_to_path) {
	int cfd;
	int mfd;

	if (!rootns_syscalls_declared())
		SKIP(return, "rootns syscalls are not declared for this architecture");

	cfd = rootns_create(ROOTNS_ALL_NAMESPACES |
			    ROOTNS_KILL_ON_CLOSE |
			    ROOTNS_CLOSE_ON_EXEC);
	if (cfd < 0 && errno == ROOTNS_ERRNO_NOSYS)
		SKIP(return, "rootns syscalls are not available in this kernel");
	ASSERT_GT(cfd, 0);

	mfd = open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE);
	ASSERT_GE(mfd, 0);

	ASSERT_EQ(move_mount(mfd, "", cfd, "",
			     MOVE_MOUNT_F_EMPTY_PATH |
			     MOVE_MOUNT_T_ROOTNS_ROOT), -1);
	ASSERT_EQ(errno, EINVAL);

	close(mfd);
	close(cfd);
}

TEST_HARNESS_MAIN
