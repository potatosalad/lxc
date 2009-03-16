/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
#ifndef _utils_h
#define _utils_h

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#else
extern int signalfd (int fd, const sigset_t *mask, int flags);

struct signalfd_siginfo {
	uint32_t ssi_signo;   /* Signal number */
	int32_t  ssi_errno;   /* Error number (unused) */
	int32_t  ssi_code;    /* Signal code */
	uint32_t ssi_pid;     /* PID of sender */
	uint32_t ssi_uid;     /* Real UID of sender */
	int32_t  ssi_fd;      /* File descriptor (SIGIO) */
	uint32_t ssi_tid;     /* Kernel timer ID (POSIX timers) */
	uint32_t ssi_band;    /* Band event (SIGIO) */
	uint32_t ssi_overrun; /* POSIX timer overrun count */
	uint32_t ssi_trapno;  /* Trap number that caused signal */
	int32_t  ssi_status;  /* Exit status or signal (SIGCHLD) */
	int32_t  ssi_int;     /* Integer sent by sigqueue(2) */
	uint64_t ssi_ptr;     /* Pointer sent by sigqueue(2) */
	uint64_t ssi_utime;   /* User CPU time consumed (SIGCHLD) */
	uint64_t ssi_stime;   /* System CPU time consumed (SIGCHLD) */
	uint64_t ssi_addr;    /* Address that generated signal
				 (for hardware-generated signals) */
	uint8_t  pad[48];      /* Pad size to 128 bytes (allow for
				  additional fields in the future) */
};

#endif


#define LXC_TTY_HANDLER(s) \
	static struct sigaction lxc_tty_sa_##s;				\
	static void tty_##s##_handler(int sig, siginfo_t *info, void *ctx) \
	{								\
		if (lxc_tty_sa_##s.sa_handler == SIG_DFL ||		\
		    lxc_tty_sa_##s.sa_handler == SIG_IGN)		\
			return;						\
		(*lxc_tty_sa_##s.sa_sigaction)(sig, info, ctx);	\
	}

#define LXC_TTY_ADD_HANDLER(s) \
	do { \
		struct sigaction sa; \
		sa.sa_sigaction = tty_##s##_handler; \
		sa.sa_flags = SA_SIGINFO; \
		sigfillset(&sa.sa_mask); \
		/* No error expected with sigaction. */ \
		sigaction(s, &sa, &lxc_tty_sa_##s); \
	} while (0)

#define LXC_TTY_DEL_HANDLER(s) \
	do { \
		sigaction(s, &lxc_tty_sa_##s, NULL); \
	} while (0)

ssize_t safe_read(int fd, char *buf, size_t count);

ssize_t safe_write(int fd, char *buf, size_t count);

int full_write(int fd, char *buf, size_t len);

char *strdup_printf(const char *fmt, ...);
#endif
