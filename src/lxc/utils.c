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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>

#include <lxc/lxc.h>

ssize_t
safe_read (int fd, char *buf, size_t count)
{
	ssize_t n;

	do {
		n = read (fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

ssize_t
safe_write (int fd, char *buf, size_t count)
{
	ssize_t n;

	do {
		n = write (fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

int
full_write(int fd, char *buf, size_t len)
{
	size_t n;
	size_t total;

	total = 0;

	while (len > 0) {
	        n = safe_write(fd, buf, len);

		if (n < 0)
		        break;

		buf += n;
		total += n;
		len -= n;
	}

	return total;
}

/*
  binary message format:

  int len;
  str cmd
  str args[];
 */
char *
pack_command (char *cmd, char *argv[], int *cmdlen)
{
	int ind = 0;
	int len = 1 + strlen (cmd);
	while (argv[ind]) {
		int arglen = strlen (argv[ind]);
		if (arglen > 255) {
			return NULL;
		}
		len += arglen + 1;
		ind ++;
	}

	char *data = malloc (len + sizeof (int));
	*((int *)data) = len;
	char *p = data + sizeof (int);

	int arglen = strlen (cmd);
	*p++ = arglen;
	strncpy (p, cmd, arglen);
	p += arglen;

	ind = 0;
	while (argv[ind]) {
		int arglen = strlen (argv[ind]);
		*p++ = arglen;
		strncpy (p, argv[ind], arglen);
		p += arglen;
		ind++;
	}

	if (cmdlen) *cmdlen = len + sizeof (int);
	return data;
}

char **
unpack_command (char *data, int len, char **cmd)
{
	char *p = data;
	char *argv[255];
	int argc = 0;

	int arglen = *p++;
	*cmd = strndup (p, arglen);
	p += arglen;

	while ((p - data) < len) {
		arglen = *p++;
		argv[argc] = strndup (p, arglen);
		argc++;
		p += arglen;
	}
	argv[argc] = NULL;

	int size = sizeof (void *) * (argc + 1);
	char **av = malloc (size);
	memcpy (av, argv, size);

	return av;
}

int
lxc_exec_cmd (char *cmdsock, char *cmd, char *argv[], int *res)
{
	struct sockaddr_un addr;
	int msglen = 0;
	char *msg = pack_command (cmd, argv, &msglen);

	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror ("faild to create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, cmdsock, sizeof(addr.sun_path) - 1);

	if (connect(sock, (struct sockaddr *) &addr,
		    sizeof(struct sockaddr_un)) == -1) {
		perror ("command socket bind failed");
		return -1;
	}

	int n_read;
	pid_t cmdid = 0;

	if (safe_write (sock, msg, msglen) != msglen)  {
		fprintf (stderr, "write failed\n");
		return 1;
	}

	if ((n_read = read (sock, &cmdid, sizeof (cmdid))) != sizeof (cmdid)) {
		fprintf (stderr, "exter failed\n");
		return 1;
	}

	printf ("CMDID = %d\n", cmdid);

	if (res) *res = cmdid;

	return sock;
}

int
lxc_exec_wait (char *cmdsock, int cmdid)
{
	char pidstr[24];
	char *arg[] = {NULL, NULL};
	sprintf (pidstr, "%d", cmdid);
	arg[0] = pidstr;

	int res;
	int fd = lxc_exec_cmd (cmdsock, "wait", arg, &res);
	close (fd);

	return res;
}

int
lxc_exec_kill (char *cmdsock, int cmdid, int signum)
{
	char pidstr[24];
	char sigstr[24];
	char *arg[] = {NULL, NULL, NULL};
	sprintf (pidstr, "%d", cmdid);
	arg[0] = pidstr;
	sprintf (sigstr, "%d", signum);
	arg[1] = sigstr;

	int res;
	int fd = lxc_exec_cmd (cmdsock, "kill", arg, &res);
	close (fd);

	return res;
}

// code from the snprintf(3) manual page
char *
strdup_printf (const char *fmt, ...) {
	/* Guess we need no more than 64 bytes. */
	int n, size = 64;
	char *p, *np;
	va_list ap;

	if ((p = malloc (size)) == NULL)
		return NULL;

	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			return p;
		/* Else try again with more space. */
		if (n > -1)    /* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else           /* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((np = realloc (p, size)) == NULL) {
			free(p);
			return NULL;
		} else {
			p = np;
		}
	}
}
