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
int lxc_exec_cmd(char *cmdsock, char *cmd, char *argv[], int *res);

int lxc_exec_wait(char *cmdsock, int cmdid);

int lxc_exec_kill(char *cmdsock, int cmdid, int signum);

char *lxc_pack_command(char *cmd, char *argv[], int *cmdlen);

char **lxc_unpack_command(char *data, int len, char **cmd);
