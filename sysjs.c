/*
 * File: sysjs.c
 * Implements: javascript vm (duktape) with system extensions (syscalls mainly)
 *
 * Copyright: Jens Låås, 2014
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <syscall.h>

#include <stdio.h>
#include "duktape.h"

struct {
	int fd;
	char *buf;
	off_t size;
} prg;

static int sys1_push_stat(duk_context *ctx, struct stat *stat)
{
	duk_push_object(ctx);
	duk_push_int(ctx, stat->st_dev);
	duk_put_prop_string(ctx, -2, "st_dev");
	duk_push_int(ctx, stat->st_ino);
	duk_put_prop_string(ctx, -2, "st_ino");
	duk_push_int(ctx, stat->st_mode);
	duk_put_prop_string(ctx, -2, "st_mode");
	duk_push_int(ctx, stat->st_nlink);
	duk_put_prop_string(ctx, -2, "st_nlink");
	duk_push_int(ctx, stat->st_uid);
	duk_put_prop_string(ctx, -2, "st_uid");
	duk_push_int(ctx, stat->st_gid);
	duk_put_prop_string(ctx, -2, "st_gid");
	duk_push_int(ctx, stat->st_rdev);
	duk_put_prop_string(ctx, -2, "st_rdev");
	duk_push_int(ctx, stat->st_size);
	duk_put_prop_string(ctx, -2, "st_size");
	duk_push_int(ctx, stat->st_blksize);
	duk_put_prop_string(ctx, -2, "st_blklsize");
	duk_push_int(ctx, stat->st_blocks);
	duk_put_prop_string(ctx, -2, "st_blocks");
	duk_push_int(ctx, stat->st_atime);
	duk_put_prop_string(ctx, -2, "st_atime");
	duk_push_int(ctx, stat->st_mtime);
	duk_put_prop_string(ctx, -2, "st_mtime");
	duk_push_int(ctx, stat->st_ctime);
	duk_put_prop_string(ctx, -2, "st_ctime");
	return 0;
}

static int sys1_accept(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	ssize_t rc;
	char buf[64];
	union {
		struct sockaddr dst;
		struct sockaddr_in dst4;
		struct sockaddr_in6 dst6;
		struct sockaddr_un dstun;
	} addr;
	socklen_t addrlen = sizeof(addr);
	
	memset(&addr, 0, sizeof(addr));

	rc = accept(fd, &addr.dst, &addrlen);

	duk_push_object(ctx);
	
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	duk_push_int(ctx, addr.dst.sa_family);
	duk_put_prop_string(ctx, -2, "family");
	if((addr.dst.sa_family == AF_INET) && inet_ntop(addr.dst.sa_family, &addr.dst4.sin_addr, buf, sizeof(buf))) {
		duk_push_string(ctx, buf);
		duk_put_prop_string(ctx, -2, "addr");
	}

	return 1;
}

static int sys1_bind(duk_context *ctx)
{
	int rc;
	int port = 0;
	int fd = duk_to_int(ctx, 0);
	union {
		struct sockaddr dst;
		struct sockaddr_in dst4;
		struct sockaddr_in6 dst6;
		struct sockaddr_un dstun;
	} addr;
	socklen_t addrlen = 0;

	memset(&addr, 0, sizeof(addr));

	duk_get_prop_string(ctx, 1, "port");
	if(duk_check_type(ctx, 2, DUK_TYPE_NUMBER)) {
		port = duk_to_int(ctx, 2);
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "in");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		addrlen = sizeof(addr.dst4);
		inet_aton(duk_to_string(ctx, 2), &addr.dst4.sin_addr);
		addr.dst4.sin_port = htons(port);
		addr.dst4.sin_family = AF_INET;
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "un");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		const char *path;
		addrlen = sizeof(addr.dstun);
		path = duk_to_string(ctx, 2);
		if(strlen(path) > sizeof(addr.dstun.sun_path)) {
			duk_pop(ctx);
			rc=-1;
			goto out;
		}
		memcpy(addr.dstun.sun_path, path, strlen(path));
		addr.dstun.sun_family = AF_LOCAL;
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "una");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		const char *path;
		addrlen = sizeof(addr.dstun);
		path = duk_to_string(ctx, 2);
		if(strlen(path) > (sizeof(addr.dstun.sun_path)-1)) {
			duk_pop(ctx);
			rc=-1;
			goto out;
		}
		memcpy(addr.dstun.sun_path+1, path, strlen(path));
		addr.dstun.sun_family = AF_LOCAL;
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "in6");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		addrlen = sizeof(addr.dst6);
		inet_pton(AF_INET6, duk_to_string(ctx, 2), &addr.dst6.sin6_addr);
		addr.dst6.sin6_port = htons(port);
		addr.dst6.sin6_family = AF_INET6;
	}
	duk_pop(ctx);

	rc = bind(fd, &addr.dst, addrlen);

out:	
	duk_push_number(ctx, rc);
	return 1;
}

static int sys1_chdir(duk_context *ctx)
{
	const char *path = duk_to_string(ctx, 0);
	int rc;

	rc = chdir(path);

	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_chmod(duk_context *ctx)
{
	const char *path = duk_to_string(ctx, 0);
	mode_t mode = duk_to_int(ctx, 1);
	int rc;

	rc = chmod(path, mode);

	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_clone(duk_context *ctx)
{
	int flags = duk_to_int(ctx, 0);
	pid_t pid;

	pid = syscall(SYS_clone, flags|SIGCHLD, 0);
	duk_push_int(ctx, pid);
	return 1;
}

static int sys1_close(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	
	int rc  = close(fd);
	
	duk_push_number(ctx, rc);
	return 1;
}

static int sys1_connect(duk_context *ctx)
{
	int rc;
	int port = 0;
	int fd = duk_to_int(ctx, 0);
	union {
		struct sockaddr dst;
		struct sockaddr_in dst4;
		struct sockaddr_in6 dst6;
		struct sockaddr_un dstun;
	} addr;
	socklen_t addrlen = 0;

	memset(&addr, 0, sizeof(addr));

	duk_get_prop_string(ctx, 1, "port");
	if(duk_check_type(ctx, 2, DUK_TYPE_NUMBER)) {
		port = duk_to_int(ctx, 2);
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "in");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		addrlen = sizeof(addr.dst4);
		inet_aton(duk_to_string(ctx, 2), &addr.dst4.sin_addr);
		addr.dst4.sin_port = htons(port);
		addr.dst4.sin_family = AF_INET;
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "un");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		const char *path;
		addrlen = sizeof(addr.dstun);
		path = duk_to_string(ctx, 2);
		if(strlen(path) > sizeof(addr.dstun.sun_path)) {
			duk_pop(ctx);
			rc=-1;
			goto out;
		}
		memcpy(addr.dstun.sun_path, path, strlen(path));
		addr.dstun.sun_family = AF_LOCAL;
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "una");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		const char *path;
		addrlen = sizeof(addr.dstun);
		path = duk_to_string(ctx, 2);
		if(strlen(path) > (sizeof(addr.dstun.sun_path)-1)) {
			duk_pop(ctx);
			rc=-1;
			goto out;
		}
		memcpy(addr.dstun.sun_path+1, path, strlen(path));
		addr.dstun.sun_family = AF_LOCAL;
	}
	duk_pop(ctx);

	duk_get_prop_string(ctx, 1, "in6");
	if(duk_check_type(ctx, 2, DUK_TYPE_STRING)) {
		addrlen = sizeof(addr.dst6);
		inet_pton(AF_INET6, duk_to_string(ctx, 2), &addr.dst6.sin6_addr);
		addr.dst6.sin6_port = htons(port);
		addr.dst6.sin6_family = AF_INET6;
	}
	duk_pop(ctx);

	rc = connect(fd, &addr.dst, addrlen);

out:	
	duk_push_number(ctx, rc);
	return 1;
}

static int sys1_dprint(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	const char *buf = duk_to_string(ctx, 1);
	int len;
	ssize_t rc;

	len = strlen(buf);

	rc = write(fd, buf, len);

	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_dup2(duk_context *ctx)
{
	int rc;

	int oldfd = duk_to_int(ctx, 0);
	int newfd = duk_to_int(ctx, 1);

	rc = dup2(oldfd, newfd);
	
	duk_push_number(ctx, rc);
	return 1;	
}

static int sys1_errno(duk_context *ctx)
{
	duk_push_int(ctx, errno);
	return 1;
}

static int sys1_exit(duk_context *ctx)
{
	int code = duk_to_int(ctx, 0);

	exit(code);

	return 1;
}

static int sys1__exit(duk_context *ctx)
{
	int code = duk_to_int(ctx, 0);

	_exit(code);

	return 1;
}

static int sys1_fchmod(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	mode_t mode = duk_to_int(ctx, 1);
	int rc;

	rc = fchmod(fd, mode);

	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_fork(duk_context *ctx)
{
	duk_push_number(ctx, fork());
	return 1;
}

static int sys1_fstat(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	struct stat stat;
	int rc;
	
	rc = fstat(fd, &stat);
	sys1_push_stat(ctx, &stat);
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	return 1;
}

static int sys1_getpid(duk_context *ctx)
{
	pid_t rc;

	rc = getpid();
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_getppid(duk_context *ctx)
{
	pid_t rc;

	rc = getppid();
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_kill(duk_context *ctx)
{
	int pid = duk_to_int(ctx, 0);
	int sig = duk_to_int(ctx, 1);
	int rc;
	
	rc = kill(pid, sig);
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_listen(duk_context *ctx)
{
	int rc;

	int fd = duk_to_int(ctx, 0);
	int backlog = duk_to_int(ctx, 1);

	rc = listen(fd, backlog);
	
	duk_push_number(ctx, rc);
	return 1;	
}

static int sys1_lseek(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	off_t offset = duk_to_int(ctx, 1);
	int whence = duk_to_int(ctx, 2);
	off_t rc;

	rc = lseek(fd, offset, whence);

	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_lstat(duk_context *ctx)
{
	const char *path = duk_to_string(ctx, 0);
	struct stat stat;
	int rc;
	
	rc = lstat(path, &stat);
	sys1_push_stat(ctx, &stat);
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	return 1;
}

static int sys1_open(duk_context *ctx)
{
	int fd;
	
	const char *path = duk_to_string(ctx, 0);
	uint32_t flags = duk_to_uint32(ctx, 1);
	int mode = duk_to_int(ctx, 2);

	fd = open(path, flags, mode);
	
	duk_push_number(ctx, fd);
	return 1;
}

static int sys1_pipe(duk_context *ctx)
{
	int rc;
	int fd[2];
	
	rc = pipe(fd);

	duk_push_object(ctx);
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	duk_push_int(ctx, fd[0]);
	duk_put_prop_index(ctx, -2, 0);
	duk_push_int(ctx, fd[1]);
	duk_put_prop_index(ctx, -2, 1);
	return 1;
}

static int sys1_poll(duk_context *ctx)
{
	int nfds = duk_to_int(ctx, 1);
	int timeout = duk_to_int(ctx, 2);
	int i, rc;
	struct pollfd *fds;

	fds = malloc(sizeof(struct pollfd)*nfds);
	memset(fds, 0, sizeof(struct pollfd)*nfds);
	
	for(i=0;i<nfds;i++) {
		duk_get_prop_index(ctx, 0, i);
		duk_get_prop_string(ctx, 3, "fd");	
		fds[i].fd = duk_to_int(ctx, 4);
		duk_get_prop_string(ctx, 3, "events");	
		fds[i].events = duk_to_int(ctx, 5);
		duk_pop_n(ctx, 3);
	}

	rc = poll(fds, nfds, timeout);

	duk_push_object(ctx);
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	duk_push_array(ctx);
	for(i=0;i<nfds;i++) {
		duk_push_object(ctx);
		duk_push_int(ctx, fds[i].fd);
		duk_put_prop_string(ctx, -2, "fd");
		duk_push_int(ctx, fds[i].revents);
		duk_put_prop_string(ctx, -2, "revents");
		duk_put_prop_index(ctx, -2, i);
	}
	duk_put_prop_string(ctx, -2, "fds");

	return 1;
}

static int sys1_read(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	int len = duk_to_int(ctx, 1);
	ssize_t rc;
	char *buf;
	
	duk_push_object(ctx);
	
	buf = duk_push_fixed_buffer(ctx, len);
	duk_put_prop_string(ctx, -2, "buffer");

	rc = read(fd, buf, len);

	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	return 1;
}

static int sys1_rename(duk_context *ctx)
{
	const char *oldpath = duk_to_string(ctx, 0);
	const char *newpath = duk_to_string(ctx, 1);
	int rc;

	rc = rename(oldpath, newpath);

	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_setsid(duk_context *ctx)
{
	duk_push_number(ctx, setsid());
	return 1;
}

static int sys1_setsockopt(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	int level = duk_to_int(ctx, 1);
	int optname = duk_to_int(ctx, 2);
	int optval;
	int rc;

	if(optname == SO_BINDTODEVICE) {
		const char *optstr;
		optstr = duk_to_string(ctx, 3);
		rc = setsockopt(fd, level, optname, optstr, strlen(optstr));
		goto done;
	}

	optval = duk_to_int(ctx, 3);
	rc = setsockopt(fd, level, optname, (void*)&optval, sizeof(optval));
done:
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_sleep(duk_context *ctx)
{
	int rc;

	int seconds = duk_to_int(ctx, 0);

	rc = sleep(seconds);
	
	duk_push_number(ctx, rc);
	return 1;
}

static int sys1_socket(duk_context *ctx)
{
	int fd;

	int domain = duk_to_int(ctx, 0);
	int type = duk_to_int(ctx, 1);
	int protocol = duk_to_int(ctx, 2);

	fd = socket(domain, type, protocol);
	
	duk_push_number(ctx, fd);
	return 1;	
}

static int sys1_stat(duk_context *ctx)
{
	const char *path = duk_to_string(ctx, 0);
	struct stat buf;
	int rc;
	
	rc = stat(path, &buf);
	sys1_push_stat(ctx, &buf);
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	return 1;
}

static int sys1_strerror(duk_context *ctx)
{
	int num = duk_to_int(ctx, 0);
	duk_push_string(ctx, strerror(num));
	return 1;
}

static int sys1_umask(duk_context *ctx)
{
	mode_t mask = duk_to_int(ctx, 0);
	mode_t rc;

	rc = umask(mask);
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_unlink(duk_context *ctx)
{
	const char *pathname = duk_to_string(ctx, 0);
	int rc;

	rc = unlink(pathname);
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_unshare(duk_context *ctx)
{
	int flags = duk_to_int(ctx, 0);
	int rc;

	rc = unshare(flags);
	duk_push_int(ctx, rc);
	return 1;
}

static int sys1_waitpid(duk_context *ctx)
{
	int rc;
	pid_t pid = duk_to_int(ctx, 0);
	int status = 0;
	int options = duk_to_int(ctx, 1);

	rc = waitpid(pid, &status, options);

	duk_push_object(ctx);
	duk_push_int(ctx, rc);
	duk_put_prop_string(ctx, -2, "rc");
	duk_push_int(ctx, status);
	duk_put_prop_string(ctx, -2, "status");
	duk_push_int(ctx, WIFEXITED(status));
	duk_put_prop_string(ctx, -2, "exited");
	duk_push_int(ctx, WEXITSTATUS(status));
	duk_put_prop_string(ctx, -2, "exitstatus");
	duk_push_int(ctx, WIFSIGNALED(status));
	duk_put_prop_string(ctx, -2, "signaled");
	duk_push_int(ctx, WTERMSIG(status));
	duk_put_prop_string(ctx, -2, "signal");
	return 1;
}

static int sys1_write(duk_context *ctx)
{
	int fd = duk_to_int(ctx, 0);
	size_t bufsize;
	void *buf = duk_to_buffer(ctx, 1, &bufsize);
	int len = duk_to_int(ctx, 2);
	ssize_t rc;
	
	rc = write(fd, buf, len);

	duk_push_int(ctx, rc);
	return 1;
}

const duk_function_list_entry sys1_funcs[] = {
	{ "accept", sys1_accept, 1 /* fd */ },
	{ "bind", sys1_bind, 2 /* fd, obj { in, in6, un, una, port } */ },
	{ "chdir", sys1_chdir, 1 },
	{ "chmod", sys1_chmod, 2 },
	{ "clone", sys1_clone, 1 },
	{ "close", sys1_close, 1 /* fd */ },
	{ "connect", sys1_connect, 2 /* fd, obj { in, in6, un, una, port } */ },
	{ "dprint", sys1_dprint, 2 /* fd, string */ },
//      { "dprintf", sys1_dprintf, DUK_VARARGS },
	{ "dup2", sys1_dup2, 2 },
	{ "errno", sys1_errno, 0 },
//	{ "execve", sys1_execve, 3 },
	{ "exit", sys1_exit, 1 },
	{ "_exit", sys1__exit, 1 },
	{ "fchmod", sys1_fchmod, 2 },
//	{ "fcntl", sys1_fcntl, 3 },
	{ "fork", sys1_fork, 1 },
	{ "fstat", sys1_fstat, 1 },
	{ "getpid", sys1_getpid, 0 },
	{ "getppid", sys1_getppid, 0 },
//	{ "gmtime", sys1_gmtime, 1 },
	{ "kill", sys1_kill, 2 },
	{ "listen", sys1_listen, 2 /* fd, backlog */ },
//	{ "localtime", sys1_localtime, 1 },
	{ "lseek", sys1_lseek, 3 },
	{ "lstat", sys1_lstat, 1 },
//	{ "mmap", sys1_mmap, 6 },
//	{ "mount", sys1_mount, 5 },
	{ "open", sys1_open, 3 /* filename, flags, mode */ },
	{ "pipe", sys1_pipe, 0 },
	{ "poll", sys1_poll, 3 },
	{ "read", sys1_read, 2 /* fd, count */ },
	{ "rename", sys1_rename, 2 },
        { "setsid", sys1_setsid, 0 },
	{ "setsockopt", sys1_setsockopt, 4 },
	{ "sleep", sys1_sleep, 1 },
	{ "socket", sys1_socket, 3 /* domain, type, protocol */ },
	{ "stat", sys1_stat, 1 },
	{ "strerror", sys1_strerror, 1 },
//	{ "tcgetattr", sys1_umount , 3 },
//	{ "tcsetattr", sys1_umount , 3 },
	{ "umask", sys1_umask , 1 },
//	{ "umount", sys1_umount , 1 },
//	{ "umount2", sys1_umount2 , 2 },
	{ "unlink", sys1_unlink , 1 },
	{ "unshare", sys1_unshare, 1 },
	{ "waitpid", sys1_waitpid, 2 },
	{ "write", sys1_write, 3 /* fd, buffer, count */ },
	{ NULL, NULL, 0 }
	};

const duk_number_list_entry sys1_consts[] = {
	{ "CLONE_FILES", (double) CLONE_FILES },
	{ "CLONE_FS", (double) CLONE_FS },
	{ "CLONE_NEWIPC", (double) CLONE_NEWIPC },
	{ "CLONE_NEWNET", (double) CLONE_NEWNET },
	{ "CLONE_NEWNS", (double) CLONE_NEWNS },
	{ "CLONE_NEWUTS", (double) CLONE_NEWUTS },
	{ "CLONE_SYSVSEM", (double) CLONE_SYSVSEM },
	{ "CLONE_NEWPID", (double) CLONE_NEWPID },
	{ "O_RDONLY", (double) O_RDONLY },
	{ "O_WRONLY,", (double) O_WRONLY, },
	{ "O_RDWR", (double) O_RDWR },
	{ "O_APPEND", (double) O_APPEND },
	{ "O_ASYNC", (double) O_ASYNC },
	{ "O_CLOEXEC", (double) O_CLOEXEC },
	{ "O_CREAT", (double) O_CREAT },
	{ "O_DIRECT", (double) O_DIRECT },
	{ "O_EXCL", (double) O_EXCL },
	{ "O_LARGEFILE", (double) O_LARGEFILE },
	{ "O_NOATIME", (double) O_NOATIME },
	{ "O_NOCTTY", (double) O_NOCTTY },
	{ "O_NOFOLLOW", (double) O_NOFOLLOW },
	{ "O_NONBLOCK", (double) O_NONBLOCK },
	{ "O_SYNC", (double) O_SYNC },
	{ "O_TRUNC", (double) O_TRUNC },

	{ "SOCK_STREAM", (double) SOCK_STREAM },
	{ "SOCK_DGRAM", (double) SOCK_DGRAM },
	{ "SOCK_SEQPACKET", (double) SOCK_SEQPACKET },
	{ "SOCK_RAW", (double) SOCK_RAW },
	{ "SOCK_RDM", (double) SOCK_RDM },
	{ "SOCK_NONBLOCK", (double) SOCK_NONBLOCK },
	{ "SOCK_CLOEXEC", (double) SOCK_CLOEXEC },
	{ "SO_ACCEPTCONN", (double) SO_ACCEPTCONN },
	{ "SO_BINDTODEVICE", (double) SO_BINDTODEVICE },
	{ "SO_BROADCAST", (double) SO_BROADCAST },
	{ "SO_DEBUG", (double) SO_DEBUG },
	{ "SO_DOMAIN", (double) SO_DOMAIN },
	{ "SO_ERROR", (double) SO_ERROR },
	{ "SO_DONTROUTE", (double) SO_DONTROUTE },
	{ "SO_KEEPALIVE", (double) SO_KEEPALIVE },
	{ "SO_LINGER", (double) SO_LINGER },
	{ "SO_MARK", (double) SO_MARK },
	{ "SO_OOBINLINE", (double) SO_OOBINLINE },
	{ "SO_PASSCRED", (double) SO_PASSCRED },
	{ "SO_PEERCRED", (double) SO_PEERCRED },
	{ "SO_PRIORITY", (double) SO_PRIORITY },
	{ "SO_PROTOCOL", (double) SO_PROTOCOL },
	{ "SO_RCVBUF", (double) SO_RCVBUF },
	{ "SO_RCVBUFFORCE", (double) SO_RCVBUFFORCE },
	{ "SO_RCVLOWAT", (double) SO_RCVLOWAT },
	{ "SO_SNDLOWAT", (double) SO_SNDLOWAT },
	{ "SO_RCVTIMEO", (double) SO_RCVTIMEO },
	{ "SO_SNDTIMEO", (double) SO_SNDTIMEO },
	{ "SO_REUSEADDR", (double) SO_REUSEADDR },
	{ "SO_SNDBUF", (double) SO_SNDBUF },
	{ "SO_SNDBUFFORCE", (double) SO_SNDBUFFORCE },
	{ "SO_TIMESTAMP", (double) SO_TIMESTAMP },
	{ "SO_TYPE", (double) SO_TYPE },
	{ "SOL_SOCKET", (double) SOL_SOCKET },
	{ "SOL_IP", (double) SOL_IP },
	{ "SOL_IPV6", (double) SOL_IPV6 },
	{ "SOL_RAW", (double) SOL_RAW },
	{ "SOL_PACKET", (double) SOL_PACKET },
	{ "AF_UNIX", (double) AF_UNIX },
	{ "AF_INET", (double) AF_INET },
	{ "AF_INET6", (double) AF_INET6 },
	{ "IPPROTO_UDP", (double) IPPROTO_UDP },
	{ "IPPROTO_TCP", (double) IPPROTO_TCP },
	{ "IPPROTO_IP", (double) IPPROTO_IP },
	{ "INADDR_ANY", (double) INADDR_ANY },
	{ "INADDR_LOOPBACK", (double) INADDR_LOOPBACK },

	{ "WNOHANG", (double) WNOHANG },
	{ "WUNTRACED", (double) WUNTRACED },
	{ "WCONTINUED", (double) WCONTINUED },

	{ "POLLIN", (double) POLLIN },
	{ "POLLOUT", (double) POLLOUT },
	{ "POLLHUP", (double) POLLHUP },
	{ "POLLERR", (double) POLLERR },
	{ "POLLPRI", (double) POLLPRI },
	{ "POLLNVAL", (double) POLLNVAL },
	{ "SEEK_SET", (double) SEEK_SET },
	{ "SEEK_CUR", (double) SEEK_CUR },
	{ "SEEK_END", (double) SEEK_END },
//	{ "SEEK_DATA", (double) SEEK_DATA },
//	{ "SEEK_HOLE", (double) SEEK_HOLE },
	
	{ "SIGHUP", (double) SIGHUP },
	{ "SIGINT", (double) SIGINT },
	{ "SIGQUIT", (double) SIGQUIT },
	{ "SIGILL", (double) SIGILL },
	{ "SIGTRAP", (double) SIGTRAP },
	{ "SIGABRT", (double) SIGABRT },
	{ "SIGIOT", (double) SIGIOT },
	{ "SIGBUS", (double) SIGBUS },
	{ "SIGFPE", (double) SIGFPE },
	{ "SIGKILL", (double) SIGKILL },
	{ "SIGUSR1", (double) SIGUSR1 },
	{ "SIGSEGV", (double) SIGSEGV },
	{ "SIGUSR2", (double) SIGUSR2 },
	{ "SIGPIPE", (double) SIGPIPE },
	{ "SIGALRM", (double) SIGALRM },
	{ "SIGTERM", (double) SIGTERM },
	{ "SIGSTKFLT", (double) SIGSTKFLT },
	{ "SIGCHLD", (double) SIGCHLD },
	{ "SIGCONT", (double) SIGCONT },
	{ "SIGSTOP", (double) SIGSTOP },
	{ "SIGTSTP", (double) SIGTSTP },
	{ "SIGTTIN", (double) SIGTTIN },
	{ "SIGTTOU", (double) SIGTTOU },
	{ "SIGURG", (double) SIGURG },
	{ "SIGXCPU", (double) SIGXCPU },
	{ "SIGXFSZ", (double) SIGXFSZ },
	{ "SIGVTALRM", (double) SIGVTALRM },
	{ "SIGPROF", (double) SIGPROF },
	{ "SIGWINCH", (double) SIGWINCH },
	{ "SIGIO", (double) SIGIO },
	{ "SIGPOLL", (double) SIGPOLL },
	{ "SIGPWR", (double) SIGPWR },
	{ "SIGSYS", (double) SIGSYS },
	
//	{ "", (double) },

	{ NULL, 0.0 }
};

int wrapped_compile_execute(duk_context *ctx) {
	int nargs = 1;
	duk_compile(ctx, 0);
	close(prg.fd);
	munmap(prg.buf, prg.size);
	
	duk_push_global_object(ctx);  /* 'this' binding */
	
	// push any arguments on stack (nargs of them)
	duk_push_int(ctx, 1234);

	duk_call_method(ctx, nargs);
	duk_pop(ctx);
	return 0;
}

static int get_stack_raw(duk_context *ctx) {
	if (!duk_is_object(ctx, -1)) {
		return 1;
	}
	if (!duk_has_prop_string(ctx, -1, "stack")) {
		return 1;
	}

	/* XXX: should check here that object is an Error instance too,
	 * i.e. 'stack' is special.
	 */

	duk_get_prop_string(ctx, -1, "stack");  /* caller coerces */
	duk_remove(ctx, -2);
	return 1;
}

/* Print error to stderr and pop error. */
static void print_error(duk_context *ctx, FILE *f) {
	/* Print error objects with a stack trace specially.
	 * Note that getting the stack trace may throw an error
	 * so this also needs to be safe call wrapped.
	 */
	(void) duk_safe_call(ctx, get_stack_raw, 1 /*nargs*/, 1 /*nrets*/);
	fprintf(f, "%s\n", duk_safe_to_string(ctx, -1));
	fflush(f);
	duk_pop(ctx);
}

int main(int argc, char *argv[]) {
	int i;
	duk_context *ctx = duk_create_heap_default();

	/* Initialize an object with a set of function properties, and set it to
	 * global object 'MyModule'.
	 */
	
	duk_push_global_object(ctx);
	duk_push_object(ctx);  /* -> [ ... global obj ] */
	duk_put_function_list(ctx, -1, sys1_funcs);
	duk_put_number_list(ctx, -1, sys1_consts);

	for(i=1;i<argc;i++) {
		duk_push_string(ctx, argv[i]);
		duk_put_prop_index(ctx, -2, i-1);
	}
	duk_push_number(ctx, argc-1);
	duk_put_prop_string(ctx, -2, "argc");

	duk_put_prop_string(ctx, -2, "Sys1");  /* -> [ ... global ] */

	duk_pop(ctx);

	{
		int rc;
		
		// read file argv[1]
		prg.fd = open(argv[1], O_RDONLY);

		prg.size = lseek(prg.fd, 0, SEEK_END);
		prg.buf = mmap((void*)0, prg.size, PROT_READ, MAP_PRIVATE, prg.fd, 0);
	
		if(*(prg.buf) == '#') {
			while(*(prg.buf) != '\n') {
				prg.buf++;
				prg.size--;
			}
		}
		
		// push file
		duk_push_lstring(ctx, prg.buf, prg.size);
		duk_push_string(ctx, argv[1]);
		
		// execute file (compile + call)
		rc = duk_safe_call(ctx, wrapped_compile_execute, 2 /*nargs*/, 1 /*nret*/);
		if (rc != DUK_EXEC_SUCCESS) {
			print_error(ctx, stderr);
			exit(1);
		}
		duk_pop(ctx);  /* pop eval result */
		
		duk_destroy_heap(ctx);
	}
	return 0;
}
