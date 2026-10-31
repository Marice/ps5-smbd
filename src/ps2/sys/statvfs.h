/* The PS2's C library has no statvfs(); src/ps2.c answers it for the memory cards. */
#pragma once

struct statvfs {
	unsigned long f_bsize;
	unsigned long f_frsize;
	unsigned long f_blocks;
	unsigned long f_bfree;
	unsigned long f_bavail;
};

int statvfs(const char *path, struct statvfs *buf);
