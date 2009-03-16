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
#include <sys/socket.h>
#include <sys/un.h>
#include <stdarg.h>

#include <lxc/lxc.h>

ssize_t safe_read(int fd, char *buf, size_t count)
{
	ssize_t n;

	do {
		n = read(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

ssize_t safe_write(int fd, char *buf, size_t count)
{
	ssize_t n;

	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

int full_write(int fd, char *buf, size_t len)
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
