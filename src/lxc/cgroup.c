/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <mntent.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "config.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>
#include <lxc/start.h>

lxc_log_define(lxc_cgroup, lxc);

#define MTAB "/proc/mounts"

enum {
	CGROUP_NS_CGROUP = 1,
	CGROUP_CLONE_CHILDREN,
};

/* Check if a mount is a cgroup hierarchy for any subsystem.
 * Return the first subsystem found (or NULL if none).
 */
static char *mount_has_subsystem(const struct mntent *mntent)
{
	FILE *f;
	char *c, *ret;
	char line[MAXPATHLEN];

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return 0;

	/* skip the first line, which contains column headings */
	if (!fgets(line, MAXPATHLEN, f))
		return 0;

	while (fgets(line, MAXPATHLEN, f)) {
		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';

		ret = hasmntopt(mntent, line);
		if (ret)
			break;
	}

	fclose(f);
	return ret;
}

/*
 * get_init_cgroup: get the cgroup init is in.
 *  dsg: preallocated buffer to put the output in
 *  subsystem: the exact cgroup subsystem to look up
 *  mntent: a mntent (from getmntent) whose mntopts contains the
 *          subsystem to look up.
 *
 * subsystem and mntent can both be NULL, in which case we return
 * the first entry in /proc/1/cgroup.
 *
 * Returns a pointer to the answer, which may be "".
 */
static char *get_init_cgroup(const char *subsystem, struct mntent *mntent,
			     char *dsg)
{
	FILE *f;
	char *c, *c2;
	char line[MAXPATHLEN];

	*dsg = '\0';
	f = fopen("/proc/1/cgroup", "r");
	if (!f)
		return dsg;

	while (fgets(line, MAXPATHLEN, f)) {
		c = index(line, ':');
		if (!c)
			continue;
		c++;
		c2 = index(c, ':');
		if (!c2)
			continue;
		*c2 = '\0';
		c2++;
		if (!subsystem && !mntent)
			goto good;
		if (subsystem && strcmp(c, subsystem) != 0)
			continue;
		if (mntent && !hasmntopt(mntent, c))
			continue;
good:
		DEBUG("get_init_cgroup: found init cgroup for subsys %s at %s\n",
			subsystem, c2);
		strncpy(dsg, c2, MAXPATHLEN);
		c = &dsg[strlen(dsg)-1];
		if (*c == '\n')
			*c = '\0';
		goto found;
	}

found:
	fclose(f);
	return dsg;
}

static int get_cgroup_flags(struct mntent *mntent)
{
	int flags = 0;


	if (hasmntopt(mntent, "ns"))
		flags |= CGROUP_NS_CGROUP;

	if (hasmntopt(mntent, "clone_children"))
		flags |= CGROUP_CLONE_CHILDREN;

	DEBUG("cgroup %s has flags 0x%x", mntent->mnt_dir, flags);
	return flags;
}

static int get_cgroup_mount(const char *subsystem, char *mnt)
{
	struct mntent *mntent;
	char initcgroup[MAXPATHLEN];
	FILE *file = NULL;
	int ret, flags, err = -1;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;

		if (subsystem) {
			if (!hasmntopt(mntent, subsystem))
				continue;
		}
		else {
			if (!mount_has_subsystem(mntent))
				continue;
		}

		flags = get_cgroup_flags(mntent);
		ret = snprintf(mnt, MAXPATHLEN, "%s%s%s", mntent->mnt_dir,
			       get_init_cgroup(subsystem, NULL, initcgroup),
		               (flags & CGROUP_NS_CGROUP) ? "" : "/lxc");
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;

		DEBUG("using cgroup mounted at '%s'", mnt);
		err = 0;
		goto out;
	};

fail:
	DEBUG("Failed to find cgroup for %s\n",
	      subsystem ? subsystem : "(NULL)");
out:
	endmntent(file);
	return err;
}

int lxc_ns_is_mounted(void)
{
	static char        buf[MAXPATHLEN];

	return (get_cgroup_mount("ns", buf) == 0);
}

static int cgroup_rename_nsgroup(const char *mnt, const char *name, pid_t pid)
{
	char oldname[MAXPATHLEN];
	char newname[MAXPATHLEN];
	int ret;

	ret = snprintf(oldname, MAXPATHLEN, "%s/%d", mnt, pid);
	if (ret >= MAXPATHLEN)
		return -1;

	ret = snprintf(newname, MAXPATHLEN, "%s/%s", mnt, name);
	if (ret >= MAXPATHLEN)
		return -1;

	if (rename(oldname, newname)) {
		SYSERROR("failed to rename cgroup %s->%s", oldname, newname);
		return -1;
	}

	DEBUG("'%s' renamed to '%s'", oldname, newname);

	return 0;
}

static int cgroup_enable_clone_children(const char *path)
{
	FILE *f;
	int ret = 0;

	f = fopen(path, "w");
	if (!f) {
		SYSERROR("failed to open '%s'", path);
		return -1;
	}

	if (fprintf(f, "1") < 1) {
		ERROR("failed to write flag to '%s'", path);
		ret = -1;
	}

	fclose(f);

	return ret;
}

static int lxc_one_cgroup_attach(const char *name,
				 struct mntent *mntent, pid_t pid)
{
	FILE *f;
	char tasks[MAXPATHLEN], initcgroup[MAXPATHLEN];
	char *cgmnt = mntent->mnt_dir;
	int flags, ret = 0;

	flags = get_cgroup_flags(mntent);

	snprintf(tasks, MAXPATHLEN, "%s%s%s/%s/tasks", cgmnt,
	         get_init_cgroup(NULL, mntent, initcgroup),
	         (flags & CGROUP_NS_CGROUP) ? "" : "/lxc",
	         name);

	f = fopen(tasks, "w");
	if (!f) {
		SYSERROR("failed to open '%s'", tasks);
		return -1;
	}

	if (fprintf(f, "%d", pid) <= 0) {
		SYSERROR("failed to write pid '%d' to '%s'", pid, tasks);
		ret = -1;
	}

	fclose(f);

	return ret;
}

/*
 * for each mounted cgroup, attach a pid to the cgroup for the container
 */
int lxc_cgroup_attach(const char *name, pid_t pid)
{
	struct mntent *mntent;
	FILE *file = NULL;
	int err = -1;
	int found = 0;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		DEBUG("checking '%s' (%s)", mntent->mnt_dir, mntent->mnt_type);

		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;

		INFO("[%d] found cgroup mounted at '%s',opts='%s'",
		     ++found, mntent->mnt_dir, mntent->mnt_opts);

		err = lxc_one_cgroup_attach(name, mntent, pid);
		if (err)
			goto out;
	};

	if (!found)
		ERROR("No cgroup mounted on the system");

out:
	endmntent(file);
	return err;
}

/*
 * rename cgname, which is under cgparent, to a new name starting
 * with 'cgparent/dead'.  That way cgname can be reused.  Return
 * 0 on success, -1 on failure.
 */
int try_to_move_cgname(char *cgparent, char *cgname)
{
	char *newdir, *name;

	/* tempnam problems don't matter here - cgroupfs will prevent
	 * duplicates if we race, and we'll just fail at that (unlikely)
	 * point
	 */

	name   = &strrchr(cgname,'/')[1];
	newdir = tempnam(cgparent, "dead");
	sprintf(newdir, "%s-%s", newdir, name);
	if (!newdir)
		return -1;
	if (rename(cgname, newdir))
		return -1;
	WARN("non-empty cgroup %s renamed to %s, please manually inspect it\n",
		cgname, newdir);

	return 0;
}

/*
 * create a cgroup for the container in a particular subsystem.
 */
static int lxc_one_cgroup_create(const char *name,
				 struct mntent *mntent, pid_t pid)
{
	char cginit[MAXPATHLEN], cgname[MAXPATHLEN], cgparent[MAXPATHLEN];
	char clonechild[MAXPATHLEN];
	char initcgroup[MAXPATHLEN];
	int flags, ret;

	/* cgparent is the parent dir, /sys/fs/cgroup/<cgroup>/<init-cgroup>/lxc */
	/* (remember get_init_cgroup() returns a path starting with '/') */
	/* cgname is the full name,    /sys/fs/cgroup/</cgroup>/<init-cgroup>/lxc/name */
	ret = snprintf(cginit, MAXPATHLEN, "%s%s", mntent->mnt_dir,
		get_init_cgroup(NULL, mntent, initcgroup));
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("Failed creating pathname for init's cgroup (%d)\n", ret);
		return -1;
	}

	ret = snprintf(cgparent, MAXPATHLEN, "%s/lxc", cginit);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("Failed creating pathname for cgroup parent (%d)\n", ret);
		return -1;
	}
	ret = snprintf(cgname, MAXPATHLEN, "%s/%s", cgparent, name);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("Failed creating pathname for cgroup (%d)\n", ret);
		return -1;
	}

	flags = get_cgroup_flags(mntent);

	/* Do we have the deprecated ns_cgroup subsystem? */
	if (flags & CGROUP_NS_CGROUP) {
		WARN("using deprecated ns_cgroup");
		return cgroup_rename_nsgroup(cginit, name, pid);
	}

	ret = snprintf(clonechild, MAXPATHLEN, "%s/cgroup.clone_children",
		       cginit);
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("Failed creating pathname for clone_children (%d)\n", ret);
		return -1;
	}

	/* we check if the kernel has clone_children, at this point if there
	 * no clone_children neither ns_cgroup, that means the cgroup is mounted
	 * without the ns_cgroup and it has not the compatibility flag
	 */
	if (access(clonechild, F_OK)) {
		ERROR("no ns_cgroup option specified");
		return -1;
	}

	/* enable the clone_children flag of the cgroup */
	if (cgroup_enable_clone_children(clonechild)) {
		SYSERROR("failed to enable 'clone_children flag");
		return -1;
	}

	/* if /sys/fs/cgroup/<cgroup>/<init-cgroup>/lxc does not exist, create it */
	if (access(cgparent, F_OK) && mkdir(cgparent, 0755)) {
		SYSERROR("failed to create '%s' directory", cgparent);
		return -1;
	}

	/*
	 * There is a previous cgroup.  Try to delete it.  If that fails
	 * (i.e. it is not empty) try to move it out of the way.
	 */
	if (!access(cgname, F_OK) && rmdir(cgname)) {
		if (try_to_move_cgname(cgparent, cgname)) {
			SYSERROR("failed to remove previous cgroup '%s'", cgname);
			return -1;
		}
	}

	/* Let's create the cgroup */
	if (mkdir(cgname, 0755)) {
		SYSERROR("failed to create '%s' directory", cgname);
		return -1;
	}

	INFO("created cgroup '%s'", cgname);

	return 0;
}

/*
 * for each mounted cgroup, create a cgroup for the container and attach a pid
 */
int lxc_cgroup_create(const char *name, pid_t pid)
{
	struct mntent *mntent;
	FILE *file = NULL;
	int err = -1;
	int found = 0;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		DEBUG("checking '%s' (%s)", mntent->mnt_dir, mntent->mnt_type);

		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;

		INFO("[%d] found cgroup mounted at '%s',opts='%s'",
		     ++found, mntent->mnt_dir, mntent->mnt_opts);

		err = lxc_one_cgroup_create(name, mntent, pid);
		if (err)
			goto out;

		err = lxc_one_cgroup_attach(name, mntent, pid);
		if (err)
			goto out;
	};

	if (!found)
		ERROR("No cgroup mounted on the system");

out:
	endmntent(file);
	return err;
}

int recursive_rmdir(char *dirname)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int ret;
	char pathname[MAXPATHLEN];

	dir = opendir(dirname);
	if (!dir) {
		WARN("failed to open directory: %m");
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		ret = stat(pathname, &mystat);
		if (ret)
			continue;
		if (S_ISDIR(mystat.st_mode))
			recursive_rmdir(pathname);
	}

	ret = rmdir(dirname);

	if (closedir(dir))
		ERROR("failed to close directory");
	return ret;


}

int lxc_one_cgroup_destroy(struct mntent *mntent, const char *name)
{
	char cgname[MAXPATHLEN], initcgroup[MAXPATHLEN];
	char *cgmnt = mntent->mnt_dir;
	int flags = get_cgroup_flags(mntent);

	snprintf(cgname, MAXPATHLEN, "%s%s%s/%s", cgmnt,
		get_init_cgroup(NULL, mntent, initcgroup),
		(flags & CGROUP_NS_CGROUP) ? "" : "/lxc", name);
	DEBUG("destroying %s\n", cgname);
	if (recursive_rmdir(cgname)) {
		SYSERROR("failed to remove cgroup '%s'", cgname);
		return -1;
	}

	DEBUG("'%s' unlinked", cgname);

	return 0;
}

/*
 * for each mounted cgroup, destroy the cgroup for the container
 */
int lxc_cgroup_destroy(const char *name)
{
	struct mntent *mntent;
	FILE *file = NULL;
	int err = -1;

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((mntent = getmntent(file))) {
		if (strcmp(mntent->mnt_type, "cgroup"))
			continue;
		if (!mount_has_subsystem(mntent))
			continue;

		err = lxc_one_cgroup_destroy(mntent, name);
		if (err)
			break;
	}

	endmntent(file);
	return err;
}
/*
 * lxc_cgroup_path_get: put into *path the pathname for
 * %subsystem and cgroup %name.  If %subsystem is NULL, then
 * the first mounted cgroup will be used (for nr_tasks)
 */
int lxc_cgroup_path_get(char **path, const char *subsystem, const char *name)
{
	static char        buf[MAXPATHLEN];
	static char        retbuf[MAXPATHLEN];

	/* lxc_cgroup_set passes a state object for the subsystem,
	 * so trim it to just the subsystem part */
	if (subsystem) {
		snprintf(retbuf, MAXPATHLEN, "%s", subsystem);
		char *s = index(retbuf, '.');
		if (s)
			*s = '\0';
		DEBUG("%s: called for subsys %s name %s\n", __func__, retbuf, name);
	}
	if (get_cgroup_mount(subsystem ? retbuf : NULL, buf)) {
		ERROR("cgroup is not mounted");
		return -1;
	}

	snprintf(retbuf, MAXPATHLEN, "%s/%s", buf, name);

	DEBUG("%s: returning %s for subsystem %s", __func__, retbuf, subsystem);

	*path = retbuf;
	return 0;
}

int lxc_cgroup_set(const char *name, const char *filename, const char *value)
{
	int fd, ret;
	char *dirpath;
	char path[MAXPATHLEN];

	ret = lxc_cgroup_path_get(&dirpath, filename, name);
	if (ret)
		return -1;

	snprintf(path, MAXPATHLEN, "%s/%s", dirpath, filename);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	ret = write(fd, value, strlen(value));
	if (ret < 0) {
		ERROR("write %s : %s", path, strerror(errno));
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

int lxc_cgroup_get(const char *name, const char *filename,
		   char *value, size_t len)
{
	int fd, ret = -1;
	char *dirpath;
	char path[MAXPATHLEN];

	ret = lxc_cgroup_path_get(&dirpath, filename, name);
	if (ret)
		return -1;

	snprintf(path, MAXPATHLEN, "%s/%s", dirpath, filename);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	ret = read(fd, value, len);
	if (ret < 0)
		ERROR("read %s : %s", path, strerror(errno));

	close(fd);
	return ret;
}

int lxc_cgroup_nrtasks(const char *name)
{
	char *dpath;
	char path[MAXPATHLEN];
	int pid, ret, count = 0;
	FILE *file;

	ret = lxc_cgroup_path_get(&dpath, NULL, name);
	if (ret)
		return -1;

	snprintf(path, MAXPATHLEN, "%s/tasks", dpath);

	file = fopen(path, "r");
	if (!file) {
		SYSERROR("fopen '%s' failed", path);
		return -1;
	}

	while (fscanf(file, "%d", &pid) != EOF)
		count++;

	fclose(file);

	return count;
}
