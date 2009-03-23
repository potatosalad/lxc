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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <lxc.h>

int lxc_exec_launch(const char *exec, int sock)
{
	char *envp[3] = { };

	char *argv[] = {
		"[lxc-cinit]",
		NULL,
	};

	pid_t pid;

	pid = fork();

	if (!pid) {
		if (asprintf(&envp[0], "SOCK=%d\n", sock) < 0) {
			lxc_log_syserror("failed to allocate memory");
			goto out;
		}

		if (asprintf(&envp[1], "FLAGS=%ul\n", LXC_START_INITLOG) < 0) {
			lxc_log_error("failed to allocate memory");
			goto out;
		}

		execve(exec, argv, envp);
		lxc_log_syserror("failed to exec '%s'", exec);
	out:
		exit(1);
	}

	if (pid < 0) {
		lxc_log_syserror("failed to fork");
		return -1;
	}

	close(sock);

	return 0;
}

int lxc_exec_open(const char *name)
{
	struct sockaddr_un addr = { };
	int sock = -1;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		lxc_log_syserror("faild to create socket");
		goto out;
	}

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
		 LXCPATH "/%s/cmdsock", name);
	unlink (addr.sun_path);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		lxc_log_syserror ("command socket bind failed");
		goto out_close;
	}
out:
	return sock;

out_close:
	close(sock);
	sock = -1;
	goto out;
}

int lxc_exec_close(int sock)
{
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);

	if (getsockname(sock, (struct sockaddr *)&addr, &len)) {
		lxc_log_syserror("failed to getsockname");
		return -1;
	}

	close(sock);
	unlink(addr.sun_path);
	return 0;
}

int lxc_exec_cmd(char *cmdsock, char *cmd, char *argv[], int *res)
{
	struct sockaddr_un addr;
	int msglen = 0;
	int n_read, sock;
	pid_t cmdid = 0;
	char *msg;

	msg = lxc_pack_command(cmd, argv, &msglen);
	if (!msg) {
		lxc_log_syserror("failed to pack command");
		return -1;
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("faild to create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, cmdsock, sizeof(addr.sun_path) - 1);

	if (connect(sock, (struct sockaddr *) &addr,
		    sizeof(struct sockaddr_un)) == -1) {
		perror("command socket bind failed");
		return -1;
	}

	if (safe_write(sock, msg, msglen) != msglen)  {
		fprintf(stderr, "write failed\n");
		return 1;
	}

	n_read = read(sock, &cmdid, sizeof(cmdid));
	if (n_read != sizeof(cmdid)) {
		fprintf(stderr, "exter failed\n");
		return 1;
	}

	printf("CMDID = %d\n", cmdid);

	if (res)
		*res = cmdid;

	return sock;
}

int lxc_exec_wait(char *cmdsock, int cmdid)
{
	char pidstr[24];
	char *arg[] = {NULL, NULL};
	int res, fd;

	sprintf(pidstr, "%d", cmdid);
	arg[0] = pidstr;

	fd = lxc_exec_cmd(cmdsock, "wait", arg, &res);
	close(fd);

	return res;
}

int lxc_exec_kill(char *cmdsock, int cmdid, int signum)
{
	char pidstr[24];
	char sigstr[24];
	char *arg[] = {NULL, NULL, NULL};
	int res, fd;

	sprintf(pidstr, "%d", cmdid);
	arg[0] = pidstr;
	sprintf(sigstr, "%d", signum);
	arg[1] = sigstr;

	fd = lxc_exec_cmd(cmdsock, "kill", arg, &res);
	close(fd);

	return res;
}

/*
  binary message format:

  int len;
  str cmd
  str args[];
 */
char *lxc_pack_command(char *cmd, char *argv[], int *cmdlen)
{
	int ind = 0;
	int len = 1 + strlen(cmd);
	int arglen;
	char *data, *p;

	while (argv[ind]) {
		int arglen = strlen(argv[ind]);
		if (arglen > 255) {
			return NULL;
		}
		len += arglen + 1;
		ind++;
	}

	data = malloc(len + sizeof(int));
	if (!data)
		return NULL;

	*((int *)data) = len;
	p = data + sizeof(int);

	arglen = strlen(cmd);
	*p++ = arglen;
	strncpy(p, cmd, arglen);
	p += arglen;

	ind = 0;
	while (argv[ind]) {
		int arglen = strlen(argv[ind]);
		*p++ = arglen;
		strncpy(p, argv[ind], arglen);
		p += arglen;
		ind++;
	}

	if (cmdlen)
		*cmdlen = len + sizeof(int);

	return data;
}

char **lxc_unpack_command(char *data, int len, char **cmd)
{
	char *p = data;
	char *argv[255];
	int argc = 0;
	int size;
	int arglen = *p++;
	char **av;

	*cmd = strndup(p, arglen);
	p += arglen;

	while ((p - data) < len) {
		arglen = *p++;
		argv[argc] = strndup(p, arglen);
		argc++;
		p += arglen;
	}
	argv[argc] = NULL;

	size = sizeof(void *) * (argc + 1);
	av = malloc(size);
	if (!av)
		return NULL;
	memcpy(av, argv, size);

	return av;
}
