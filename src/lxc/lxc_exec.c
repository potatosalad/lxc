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
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#include <lxc/lxc.h>

static char *cmdsock;

void usage(char *cmd)
{
	fprintf(stderr, "%s -n <name> -- <command>\n", basename(cmd));
	_exit(1);
}

static int proxy_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	char buf[1024];
	int n_read;
	int outfd = (int)data;

	if ((n_read = read(fd, buf, sizeof(buf))) <= 0) {
		lxc_mainloop_del_handler(descr, fd);
		close (fd);
		return 1;
	}
	write(outfd, buf, n_read);

	return 0;
}

static int signal_handler(int fd, void *data, struct lxc_epoll_descr *descr)
{
	int cmdid = (int)data;

	lxc_exec_kill(cmdsock, cmdid, SIGTERM);

	/* simply end main loop */
	return 1;
}

static int mainloop(int fd, int sigfd, int cmdid)
{
	struct lxc_epoll_descr descr;
	int ret = -1;


	if (lxc_mainloop_open(1, &descr)) {
		lxc_log_error("failed to create mainloop");
		return -1;
	}

	if (lxc_mainloop_add_handler(&descr, sigfd, signal_handler,
				     (void *)cmdid)) {
		lxc_log_error("failed to add signale handler");
		return -1;
	}

	if (lxc_mainloop_add_handler(&descr, 0, proxy_handler, (void *)fd)) {
		lxc_log_error("failed to add proxy handler");
		return -1;
	}

	if (lxc_mainloop_add_handler(&descr, fd, proxy_handler, (void *)1)) {
		lxc_log_error("failed to add proxy handler");
		return -1;
	}

	ret = lxc_mainloop(&descr);

	return ret;
}

static int setup_signal_fd(sigset_t *oldmask)
{
	sigset_t mask;
	int fd;

	if (sigprocmask(SIG_BLOCK, NULL, &mask)) {
		lxc_log_syserror("failed to get mask signal");
		return -1;
	}

	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGPIPE);

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

int main(int argc, char *argv[])
{
	char *name = NULL;
	sigset_t oldmask;
	int opt, waitres, cmdid, cmdfd, sigfd;

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		}
	}

	if (!name || !argv[optind] || !strlen(argv[optind]) ||
	    strcmp("--", argv[optind-1]))
		usage(argv[0]);


	sigfd = setup_signal_fd(&oldmask);
	if (sigfd < 0) {
		lxc_log_error("failed to set signal fd handler");
		return -1;
	}

	if (!asprintf(&cmdsock, LXCPATH "/%s/cmdsock", name)) {
		lxc_log_syserror("failed to allocate memory");
		return 1;
	}

	cmdfd = lxc_exec_cmd(cmdsock, "exec", argv + optind, &cmdid);
	if (cmdid <= 0) {
		lxc_log_error("exec failed");
		return 1;
	}

	/* fprintf (stderr, "entering container %s\n", name); */

	mainloop(cmdfd, sigfd, cmdid);

	close(cmdfd);

	waitres = lxc_exec_wait (cmdsock, cmdid);

	return waitres;
}
