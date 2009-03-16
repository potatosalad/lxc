/*
 * lxc: linux Container library
 *
 * (C) Copyright 2008 Proxmox Server Solutions GmbH
 *
 * Authors:
 * Dietmar Maurer <dietmar at proxmox.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * This daemon is started by lxc-start command inside the container.
 *
 * Main purpose is to listen on a socket an execute commands inside
 * a container, or execute a shell and proxy the pty stream.
 *
 * It can also open a pty and set the CONSOLE=xyz for init. That way
 * we can log the output from init (or use a fifo if there is no pty
 * available).
 *
 * Further possibility would be to provide additional services like
 * syslog (useful for application containers).
 */

#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/mount.h>

#include <lxc/lxc.h>

#define LOG_FIFO "/var/log/init.fifo"

static struct lxc_list *workers;

struct worker {
	pid_t pid;
	int waitfd;
	int status;
	int done;
};

static void add_worker(pid_t pid)
{
	struct lxc_list *l = malloc(sizeof(*l));
	struct worker *w = malloc(sizeof(*w));

	w->pid = pid;

	lxc_list_add_elem(l, w);
	lxc_list_add(workers, l);
}

static int signal_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	struct lxc_list *iterator;
	struct signalfd_siginfo si;
	size_t nread;
	pid_t pid;
	int status;

	nread = read(fd, &si, sizeof(si));
	if (nread != sizeof(si))
		return 0;

	if (si.ssi_signo != SIGCHLD)
		return 0;

	pid = si.ssi_pid;
	status = si.ssi_status;

	lxc_list_for_each(iterator, workers) {
		struct worker *w = iterator->elem;

		if (pid != w->pid)
			continue;

		if (w->waitfd > 0) {
			write(w->waitfd, &status, sizeof(int));
			close(w->waitfd);
			lxc_list_del(iterator);
			free(iterator);
			free(w);
		} else {
			w->done = 1;
			w->status = status;
		}
	}

	return 0;
}


/* Set a signal handler */
static void setsig(struct sigaction *sa, int sig, void (*fun)(int), int flags)
{
	sa->sa_handler = fun;
	sa->sa_flags = flags;
	sigemptyset(&sa->sa_mask);
	sigaction(sig, sa, NULL);
}

void term_handler()
{
	printf("\ninit logger finished\n");
	exit(0);
}

static int proxy_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	char buf[1024];
	int n_read;
	int outfd = (int)data;

	n_read = read(fd, buf, sizeof(buf));
	if (n_read <= 0) {
		printf("proxy connection closed\n");
		lxc_mainloop_del_handler(descr, fd);
		close(outfd);
		close(fd);
		return 0;
	}
	safe_write(outfd, buf, n_read);

	return 0;
}

static int fork_bash(int fd, struct lxc_epoll_descr *descr)
{
	char *arg[] = {"-bash", NULL};
	char *env[] = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin:",
		       "HISTFILE=/dev/null",
		       "USER=root", "HOME=/root", "LOGNAME=root",
		       "TERM=xterm", /* fixme: */
		       NULL};
	int master;
	int sync[2];
	pid_t pid = -1;

	if (pipe(sync) !=  0) {
		lxc_log_syserror("create pipe failed");
		write(fd, &pid, sizeof(pid_t));
		close(fd);
		return -1;
	}

	pid = forkpty(&master, NULL, NULL, NULL);

	if (pid == -1) {
		lxc_log_syserror("forkpty failed - pty enabled?");
		close(sync[0]);
		close(sync[1]);
		write(fd, &pid, sizeof(pid_t));
		close(fd);
		return -1;
	}

	if (!pid) {
		close(sync[1]);
		close(fd);

		int n_read = safe_read(sync[0], (void *)&pid, sizeof(pid_t));
		close(sync[0]);

		if (n_read != sizeof(pid_t)) {
			printf("sync failed\n");
			exit(1);
		}

		chdir("/root");

		execve("/bin/bash", arg, env);
		execve("/bin/sh", arg, env);
		printf("exec failed: unable to exec bash");
		exit(1);
	}

	printf("fork sucessful\n");

	add_worker(pid);

	write(fd, &pid, sizeof(pid_t));

	close(sync[0]);
	write(sync[1], &pid, sizeof(pid_t));
	close(sync[1]);

	if (lxc_mainloop_add_handler(descr, master, proxy_handler, (void *)fd)) {
		lxc_log_error("failed to add proxy handler");
	}

	if (lxc_mainloop_add_handler(descr, fd, proxy_handler, (void *)master)) {
		lxc_log_error("failed to add proxy handler");
	}

	return pid;
}

static int fork_cmd(int fd, struct lxc_epoll_descr *descr, char *argv[])
{
	pid_t pid = fork();

	if (pid == -1) {
		lxc_log_syserror("fork failed");
		write(fd, &pid, sizeof(pid_t));
		close(fd);
		return -1;
	}

	if (!pid) {
		pid_t cpid = getpid();
		write(fd, &cpid, sizeof(pid_t));

		close(0);
		dup(fd);

		close(1);
		dup(fd);

		close(2);
		dup(fd);

		close(fd);

		chdir("/");

		setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:", 1);
		setenv("USER", "root", 1);
		setenv("HOME", "/", 1);

		execvp(argv[0], argv);
		printf("exec failed: unable to exec %s\n", argv[0]);
		exit(1);
	}

	printf("fork sucessful %d\n", pid);

	add_worker(pid);

	close(fd);

	return pid;
}

/* for debugging only */
static int open_socket(void)
{
	/* open command socket */
	struct sockaddr_un addr;
	char *cmdsock = "/tmp/testsock";

	unlink(cmdsock);

	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		lxc_log_syserror("faild to create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, cmdsock, sizeof(addr.sun_path) - 1);

	if (bind(sock, (struct sockaddr *) &addr,
		 sizeof(struct sockaddr_un)) == -1) {
		lxc_log_syserror("command socket bind failed");
		return -1;
	}

	return sock;
}

static int exec_handler(int cmdsock, void *data, struct lxc_epoll_descr *descr)
{
	struct sockaddr_un peer;
	socklen_t addrlen = sizeof(struct sockaddr_un);
	int fd = accept(cmdsock, (struct sockaddr *) &peer, &addrlen);
	int n_read;

	if (fd == -1) {
		lxc_log_syserror("accept failed");
		return 0;
	}

	printf("got connection %d\n", fd);

	int cmdlen;
	if ((n_read = safe_read(fd, (void *)&cmdlen, sizeof(int)))
	    != sizeof(int)) {
		printf("unable to read command len\n");
		return 0;
	}

	char *msg = malloc(cmdlen);
	if ((n_read = safe_read(fd, msg, cmdlen)) != cmdlen) {
		free(msg);
		printf("unable to read command data %d\n", n_read);
		return 0;
	}

	char *cmd;
	char **argv;
	argv = lxc_unpack_command(msg, cmdlen, &cmd);

	printf("got command %s\n", cmd);

	pid_t pid = -1;

	if (!strcmp(cmd, "enter")) {

		fork_bash(fd, descr);

	} else if (!strcmp(cmd, "exec")) {

		fork_cmd(fd, descr, argv);

	} else if (!strcmp(cmd, "kill")) {

		pid_t wpid = atoi(argv[0]);
		int signum = atoi(argv[1]);

		int res = kill(wpid, signum);

		write(fd, &res, sizeof (int));
		close(fd);

	} else if (!strcmp(cmd, "wait")) {

		pid_t wpid = atoi(argv[0]);
		struct lxc_list *iterator;
		int found = 0;

		lxc_list_for_each(iterator, workers) {
			struct worker *w = iterator->elem;

			if (wpid == w->pid) {
				if (w->done) {
					write(fd, &w->status, sizeof(int));
					close(fd);
				} else {
					w->waitfd = fd;
				}
				found = 1;
				break;
			}
		}

		if (!found) {
			int res = -1;
			printf("no such command %d\n", wpid);
			write(fd, &res, sizeof (int));
			close(fd);
		}

	} else {
		write(fd, &pid, sizeof(pid_t));
		printf("unknown command %s\n", cmd);
	}

	free(cmd);
	int i = 0;
	while (argv[i])
		free(argv[i++]);

	printf("end connection\n");

	return 0;
}

static int open_log_fifo(struct lxc_epoll_descr *descr);

static int log_handler_fifo(int fd, void *data, struct lxc_epoll_descr *descr)
{
	char buf[1024];
	int n_read;

	if ((n_read = read(fd, buf, sizeof(buf))) <= 0) {
		lxc_mainloop_del_handler(descr, fd);
		close(fd);
		open_log_fifo(descr);
		return 0;
	}

	full_write(STDOUT_FILENO, buf, n_read);

	return 0;
}

static int log_handler_pty(int fd, void *data, struct lxc_epoll_descr *descr)
{
	char buf[1024];
	int n_read;

	if ((n_read = read(fd, buf, sizeof(buf))) <= 0) {
		lxc_mainloop_del_handler(descr, fd);
		close(fd);
		printf("logger finished\n");
		return 0;
	}

	full_write(STDOUT_FILENO, buf, n_read);

	return 0;
}

static int open_log_fifo(struct lxc_epoll_descr *descr)
{
	mkfifo(LOG_FIFO, 0600);

	int fd;
	if ((fd = open(LOG_FIFO, O_RDONLY|O_NONBLOCK)) < 0) {
		lxc_log_syserror("failed to open fifo");
		return -1;
	}

	if (lxc_mainloop_add_handler(descr, fd, log_handler_fifo, NULL)) {
		lxc_log_error("failed to add fifo log handler");
		return -1;
	}

	return 0;
}

static int open_log_pty(struct lxc_epoll_descr *descr, char **console)
{
	int master, slave;
	char ttyname[256];

	if (openpty(&master, &slave, ttyname, NULL, NULL) == -1) {
		lxc_log_syserror("can't open console pty");
		return -1;
	}

	printf("TEST console = %s\n", ttyname);

	if (console)
		*console = ttyname;

	return master;
}

static int
setup_signal_fd(sigset_t *oldmask)
{
	sigset_t mask;
	int fd;

	if (sigprocmask(SIG_BLOCK, NULL, &mask)) {
		lxc_log_syserror("failed to get mask signal");
		return -1;
	}

	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, oldmask)) {
		lxc_log_syserror("failed to set mask signal");
		return -1;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		lxc_log_syserror("failed to create the signal fd");
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC)) {
		lxc_log_syserror("failed to set sigfd to close-on-exec");
		close(fd);
		return -1;
	}

	return fd;
}

int
main(int argc, char * argv[])
{
	sigset_t oldmask;
	struct sigaction sa;
	struct lxc_list l;
	int sync[2];

	if (getpid() != 1) {
		lxc_log_error("got wrong pid for init, pid = '%d'", getpid());
	}

	unlink("/var/log/init.log");

	close(1);
	if (open("/var/log/init.log", O_CREAT|O_WRONLY|O_TRUNC, 0644) != 1) {
		lxc_log_syserror("open init.log failed");
		exit(-1);
	}

	close(2);
	dup(1);

	close(0);
	open("/dev/null", O_RDONLY);

	/* use unbuffered IO for stdout/stderr */
	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	setvbuf(stderr, (char *)NULL, _IONBF, 0);

	char *sockstr = getenv("SOCK");
	if (!sockstr || atoi(sockstr) < 0) {
		lxc_log_syserror("no command socket specified");
		exit(1);
	}

	char *flagsstr = getenv("FLAGS");
	int flags = 0;

	if (flagsstr)
		flags = atol(flagsstr);

	if ((flags & LXC_MOUNT_SYSFS) &&
	    mount("sysfs", "/sys", "sysfs", 0, NULL)) {
		fprintf(stderr, "failed to mount '/sys'\n");
		exit(1);
	}

	if ((flags & LXC_MOUNT_PROC) &&
	    mount("proc", "/proc", "proc", 0, NULL)) {
		fprintf(stderr, "failed to mount '/proc'\n");
		exit(1);
	}


	if (pipe(sync) != 0) {
		lxc_log_syserror("unable to create sync pipe");
		exit(-1);
	}

	int pid = fork();

	if (pid == -1) {
		lxc_log_syserror("unable to fork cinit");
		exit(-1);
	}

	if (pid == 0) {
		struct lxc_epoll_descr descr;
		char *console;
		int ret = -1;

		close(sync[0]); /* close reading end */

		printf("starting init logger\n");

		workers = &l;
		lxc_list_init(workers);

		setsig(&sa, SIGTERM, term_handler, SA_RESTART);
		setsig(&sa, SIGPIPE, SIG_IGN, SA_RESTART);

		int sigfd = setup_signal_fd(&oldmask);
		if (sigfd < 0) {
			lxc_log_error("failed to set signal fd handler");
			goto out;
		}

		int sock = atoi(sockstr);
		/* FIXME: testing */
		/*int sock = open_socket ();
		  if (sock == -1) {
		  exit (-1);
		  }*/

		if (listen(sock, 10) != 0) {
			lxc_log_syserror ("listen failed");
			goto out;
		}

		if (lxc_mainloop_open(8, &descr)) {
			lxc_log_error("failed to create mainloop");
			close(sock);
			goto out;
		}

		if (lxc_mainloop_add_handler(&descr, sigfd, signal_handler, NULL)) {
			lxc_log_error("failed to add signal handler");
			goto out_mainloop_open;
		}

		if (lxc_mainloop_add_handler(&descr, sock, exec_handler, NULL)) {
			lxc_log_error("failed to add exec handler");
			goto out_mainloop_open;
		}

		int logfd;

		logfd = open_log_pty(&descr, &console);

		if (logfd != -1) {
			if (lxc_mainloop_add_handler(&descr, logfd,
						     log_handler_pty, NULL)) {
				lxc_log_error("failed to add log handler");
				/* do nothing on error */
			}
		} else if  (open_log_fifo(&descr) != -1) {
			console = LOG_FIFO;
			lxc_log_info("using fifo for init logger");
		} else {
			console = "";
		}

		write(sync[1], console, strlen(console) + 1);
		close(sync[1]);

		ret = lxc_mainloop(&descr);
	  out:
		printf("stopping init logger\n");
		exit(ret);

	  out_mainloop_open:
		lxc_mainloop_close(&descr);
		goto out;
	}

	/* normal init */

	close(sync[1]);
	char readbuf[256];
	int n_read;
	char *envp[] = {"HOME=/", "TERM=linux", NULL, NULL};

	char **initargv = argv + 1;

	/* sync */
	n_read = safe_read(sync[0], readbuf, sizeof (readbuf));
	if (n_read > 0 && readbuf[n_read] == 0)
		if (!asprintf(&envp[2], "CONSOLE=%s", readbuf)) {
			lxc_log_syserror("failed to allocate memory");
			exit(-1);
		}


	execve(initargv[0], initargv, envp);

	lxc_log_syserror("failed to exec init");

	exit(-1);
}
