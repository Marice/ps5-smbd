/* The shares: data and mnt, and each drive under mnt (ext0, ext1, usb0 ... usb7) that holds a file system of its
 * own, as a share of its own (docs/decision-log.md D16).
 *
 * Windows asks a share's root how much room there is, whichever folder in it a copy goes to: under mnt that
 * was /mnt's own small file system, so a copy to \\<console>\mnt\ext1 was refused for want of room. As
 * \\<console>\ext1 the drive is the root and the room is its own.
 *
 * The table only grows: a handle keeps its share's index, so an entry stays when its drive goes; whether a
 * drive is there is checked when a client connects to it or lists the shares. The SMB loop is the only user. */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "smbd.h"

#if defined(_EE)
/* The PS2: each memory card a share named after its device, and no drives to look for */
struct share smbd_shares[SMBD_MAX_SHARES] = {{"mc0", "mc0:/"}, {"mc1", "mc1:/"}};
#else
#ifdef SMBD_HOST
#define DATA_ROOT SMBD_DATA
#define MNT_ROOT SMBD_MNT
#else
#define DATA_ROOT "/data"
#define MNT_ROOT "/mnt"
#endif

struct share smbd_shares[SMBD_MAX_SHARES] = {{"data", DATA_ROOT}, {"mnt", MNT_ROOT}};
#endif
int smbd_share_count = 2;

/* "ext" or "usb" and a number: the drives the console mounts under /mnt (not its own mounts there, such as
   sandbox or pfs). */
static int is_drive_name(const char *name)
{
	const char *n;

	if (strncmp(name, "ext", 3) && strncmp(name, "usb", 3))
		return 0;
	n = name + 3;
	if (!*n || strlen(n) > 2)
		return 0;
	for (; *n; n++) {
		if (!isdigit((unsigned char)*n))
			return 0;
	}
	return 1;
}

/* A drive is there when its folder holds another file system than mnt itself; an empty mount point (no stick
   in usb3) is part of mnt's. The host build has no such mounts and takes the folder alone. */
static int drive_mounted(const char *root)
{
#ifdef _EE
	(void)root;
	return 1; /* only the memory cards, whose shares are always there */
#endif
	struct stat st;
#ifndef SMBD_HOST
	struct stat parent;

	if (stat(MNT_ROOT, &parent) < 0)
		return 0;
#endif
	if (stat(root, &st) < 0 || !S_ISDIR(st.st_mode))
		return 0;
#ifndef SMBD_HOST
	if (st.st_dev == parent.st_dev)
		return 0;
#endif
	return 1;
}

void shares_refresh(void)
{
#ifndef _EE
	DIR *d = opendir(MNT_ROOT);
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d)) && smbd_share_count < SMBD_MAX_SHARES) {
		struct share *s;
		int known = 0;

		if (!is_drive_name(e->d_name))
			continue;
		for (int i = 2; i < smbd_share_count; i++)
			known = known || !strcmp(smbd_shares[i].name, e->d_name);
		if (known)
			continue;
		s = &smbd_shares[smbd_share_count];
		snprintf(s->name, sizeof(s->name), "%s", e->d_name);
		if ((size_t)snprintf(s->root, sizeof(s->root), "%s/%s", MNT_ROOT, e->d_name) >= sizeof(s->root) ||
		    !drive_mounted(s->root))
			continue; /* not taken: the slot is reused for the next name */
		smbd_log("share \"%s\" for %s", s->name, s->root);
		smbd_share_count++;
	}
	closedir(d);
#endif
}

int share_available(int i)
{
	if (i < 0 || i >= smbd_share_count)
		return 0;
	return i < 2 || drive_mounted(smbd_shares[i].root);
}

int share_device(int i, unsigned long long *device)
{
	struct stat st;

	if (!share_available(i) || stat(smbd_shares[i].root, &st) < 0)
		return 0;
	*device = (unsigned long long)st.st_dev;
	return 1;
}

int share_find(const char *name)
{
	shares_refresh();
	for (int i = 0; i < smbd_share_count; i++) {
		if (!strcasecmp(name, smbd_shares[i].name))
			return share_available(i) ? i : -1;
	}
	return -1;
}
