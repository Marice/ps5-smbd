/* The PS2 (EE) side of the server: the IOP modules, the network up by DHCP, and what the PS2's C library
   lacks. The memory cards are the shares, named after their devices (\\<ip>\mc0, \mc1); no discovery and
   no srvsvc. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <kernel.h>
#include <debug.h>
#include <iopcontrol.h>
#include <iopheap.h>
#include <loadfile.h>
#include <sbv_patches.h>
#include <sifrpc.h>
#include <libmc.h>
#include <netman.h>
#include <ps2ip.h>

#include "smbd.h"
#include "sys/statvfs.h"

/* the IOP modules, embedded (Makefile: bin2c) */
#define IRX(name) extern unsigned char name##_irx[]; extern unsigned int size_##name##_irx
IRX(IOMANX);
IRX(FILEXIO);
IRX(SIO2MAN);
IRX(MCMAN);
IRX(MCSERV);
#undef IRX
extern unsigned char DEV9_irx[];
extern unsigned int size_DEV9_irx;
extern unsigned char NETMAN_irx[];
extern unsigned int size_NETMAN_irx;
extern unsigned char SMAP_irx[];
extern unsigned int size_SMAP_irx;

static void wake(s32 alarm_id, u16 time, void *common)
{
	(void)alarm_id;
	(void)time;
	iWakeupThread(*(int *)common);
}

/* Polls check() once a second for up to 30 seconds. */
static int wait_for(int (*check)(void))
{
	int thread = GetThreadId();

	for (int i = 0; !check(); i++) {
		if (i >= 30)
			return -1;
		SetAlarm(1000 * 16, wake, &thread);
		SleepThread();
	}
	return 0;
}

static int link_up(void)
{
	return NetManIoctl(NETMAN_NETIF_IOCTL_GET_LINK_STATUS, NULL, 0, NULL, 0) == NETMAN_NETIF_ETH_LINK_STATE_UP;
}

static int dhcp_bound(void)
{
	t_ip_info info;

	return ps2ip_getconfig("sm0", &info) >= 0 && info.dhcp_enabled && info.dhcp_status == DHCP_STATE_BOUND;
}

static void say(const char *fmt, const char *arg)
{
	scr_printf(fmt, arg);
	printf(fmt, arg);
}

/* A fixed address (make ps2 PS2_IP=a.b.c.d PS2_GW=...), or DHCP when none is given. PCSX2's DEV9 sends the
   PS2's frames out of a host interface with pcap, so the host's own DHCP server on it never sees them. */
static void dotted(const char *text, struct ip4_addr *out)
{
	unsigned int a = 0, b = 0, c = 0, d = 0;

	sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d);
	IP4_ADDR(out, a, b, c, d);
}

static int static_address(struct ip4_addr *ip, struct ip4_addr *mask, struct ip4_addr *gw)
{
#ifdef SMBD_PS2_IP
	dotted(SMBD_PS2_IP, ip);
	dotted(SMBD_PS2_NETMASK, mask);
	dotted(SMBD_PS2_GW, gw);
	return 1;
#else
	(void)ip;
	(void)mask;
	(void)gw;
	return 0;
#endif
}

int ps2_init(void)
{
	struct ip4_addr ip, mask, gw;
	t_ip_info info;
	int fixed;

	sceSifInitRpc(0);
	while (!SifIopReset("", 0))
		;
	while (!SifIopSync())
		;
	sceSifInitRpc(0);
	SifLoadFileInit();
	SifInitIopHeap();
	sbv_patch_enable_lmb();

	init_scr();
	say("%s\n", "ps2-smbd, libsmb2 " SMBD_VERSION);

	/* ps2sdk's own file and memory card modules: the C library reaches the cards through fileXio */
	SifExecModuleBuffer(IOMANX_irx, size_IOMANX_irx, 0, NULL, NULL);
	SifExecModuleBuffer(FILEXIO_irx, size_FILEXIO_irx, 0, NULL, NULL);
	SifExecModuleBuffer(SIO2MAN_irx, size_SIO2MAN_irx, 0, NULL, NULL);
	SifExecModuleBuffer(MCMAN_irx, size_MCMAN_irx, 0, NULL, NULL);
	SifExecModuleBuffer(MCSERV_irx, size_MCSERV_irx, 0, NULL, NULL);
	if (mcInit(MC_TYPE_XMC) < 0)
		say("%s\n", "memory cards: mcInit failed");

	SifExecModuleBuffer(DEV9_irx, size_DEV9_irx, 0, NULL, NULL);
	SifExecModuleBuffer(NETMAN_irx, size_NETMAN_irx, 0, NULL, NULL);
	SifExecModuleBuffer(SMAP_irx, size_SMAP_irx, 0, NULL, NULL);
	NetManInit();

	ip4_addr_set_zero(&ip);
	ip4_addr_set_zero(&mask);
	ip4_addr_set_zero(&gw);
	fixed = static_address(&ip, &mask, &gw);
	ps2ipInit(&ip, &mask, &gw);
	if (!fixed && ps2ip_getconfig("sm0", &info) >= 0) {
		info.dhcp_enabled = 1;
		ps2ip_setconfig(&info);
	}
	say("%s\n", "waiting for the network link...");
	if (wait_for(link_up) < 0) {
		say("%s\n", "no network link");
		return -1;
	}
	if (!fixed) {
		say("%s\n", "waiting for a DHCP lease...");
		if (wait_for(dhcp_bound) < 0) {
			say("%s\n", "no DHCP lease");
			return -1;
		}
	}
	ps2ip_getconfig("sm0", &info);
	{
		struct ip4_addr *a = (struct ip4_addr *)&info.ipaddr;
		char ip[16];

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", ip4_addr1(a), ip4_addr2(a), ip4_addr3(a), ip4_addr4(a));
		say("serving \\\\%s\\mc0 and \\mc1, login " SMBD_USER " / " SMBD_PASSWORD "\n", ip);
	}
#ifdef SMBD_PS2_SELFTEST
	{
		void ps2_selftest(void);

		ps2_selftest();
	}
#endif
	return 0;
}

#ifdef SMBD_PS2_SELFTEST
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

/* What the C library makes of the memory card paths (make ps2 with -DSMBD_PS2_SELFTEST). */
void ps2_selftest(void)
{
	static const char *paths[] = {"mc0:", "mc0:/", "mc0:/."};
	struct stat st;
	int type = 0, free_clusters = 0, format = 0, ret = 0;

	for (int port = 0; port < 2; port++) {
		mcGetInfo(port, 0, &type, &free_clusters, &format);
		mcSync(0, NULL, &ret);
		printf("SELFTEST mcGetInfo(%d) ret %d type %d free %d format %d\n", port, ret, type, free_clusters, format);
		if (ret == -2 && type == MC_TYPE_PS2) {
			/* only in this test build: PCSX2's fresh card images are unformatted */
			mcFormat(port, 0);
			mcSync(0, NULL, &ret);
			printf("SELFTEST mcFormat(%d) = %d\n", port, ret);
		}
	}

	for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		DIR *d;
		int r = stat(paths[i], &st);

		printf("SELFTEST stat(%s) = %d errno %d mode %o\n", paths[i], r, r ? errno : 0, r ? 0 : st.st_mode);
		d = opendir(paths[i]);
		printf("SELFTEST opendir(%s) = %p errno %d\n", paths[i], (void *)d, d ? 0 : errno);
		if (d) {
			struct dirent *e;
			int n = 0;

			while ((e = readdir(d)) && n++ < 8)
				printf("SELFTEST   %s\n", e->d_name);
			closedir(d);
		}
	}
	{
		int fd = open("mc0:/smbtest.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);

		printf("SELFTEST open(mc0:/smbtest.txt, w) = %d errno %d\n", fd, fd < 0 ? errno : 0);
		if (fd >= 0) {
			printf("SELFTEST write = %d\n", (int)write(fd, "hi\n", 3));
			close(fd);
			printf("SELFTEST stat after = %d\n", stat("mc0:/smbtest.txt", &st));
		}
	}
	{
		static const char *names[] = {"mc0:/x2.bin", "mc0:/smbtest.txt", "mc0:/ps2test.bin", "mc0:/win2016"};

		for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			int r = stat(names[i], &st);
			int fd = open(names[i], O_RDONLY);
			char buf[8];

			printf("SELFTEST stat(%s) = %d errno %d mode %o size %ld\n", names[i], r, r ? errno : 0,
			       r ? 0 : st.st_mode, r ? 0L : (long)st.st_size);
			printf("SELFTEST   open(O_RDONLY) = %d errno %d", fd, fd < 0 ? errno : 0);
			if (fd >= 0) {
				printf(" read %d", (int)read(fd, buf, sizeof(buf)));
				close(fd);
			}
			printf("\n");
		}
		printf("SELFTEST rename(x3.bin, r3.bin) = %d errno %d\n", rename("mc0:/x3.bin", "mc0:/r3.bin"), errno);
		printf("SELFTEST rename(r3.bin, x3.bin) = %d errno %d\n", rename("mc0:/r3.bin", "mc0:/x3.bin"), errno);
		/* the empty folders the C library's unlink() left of x2.bin, q.bin and p.bin */
		printf("SELFTEST rmdir(x2.bin) = %d errno %d\n", rmdir("mc0:/x2.bin"), errno);
		printf("SELFTEST rmdir(q.bin) = %d errno %d\n", rmdir("mc0:/q.bin"), errno);
		printf("SELFTEST rmdir(p.bin) = %d errno %d\n", rmdir("mc0:/p.bin"), errno);
		{
			int fd = open("mc0:/del.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd >= 0) {
				write(fd, "x", 1);
				close(fd);
			}
		}
		printf("SELFTEST unlink(del.bin) = %d errno %d\n", unlink("mc0:/del.bin"), errno);
		printf("SELFTEST stat(del.bin) after = %d errno %d\n", stat("mc0:/del.bin", &st), errno);
	}
	{
		int __real_stat(const char *path, struct stat *st);
		int r = __real_stat("mc0:/nope.bin", &st);

		printf("SELFTEST real stat(missing) = %d mode %o\n", r, st.st_mode);
		r = stat("mc0:/nope.bin", &st);
		printf("SELFTEST stat(missing) = %d errno %d\n", r, r ? errno : 0);
		r = stat("mc0:/x1.bin", &st);
		printf("SELFTEST stat(x1.bin) = %d errno %d mode %o size %ld\n", r, r ? errno : 0, r ? 0 : st.st_mode, r ? 0L : (long)st.st_size);
	}
	{
		static const struct { const char *name; int flags; } opens[] = {
			{"mc0:/x1.bin", O_RDWR | O_CREAT | O_EXCL},
			{"mc0:/x2.bin", O_RDWR | O_CREAT},
			{"mc0:/x3.bin", O_WRONLY | O_CREAT | O_EXCL},
		};

		for (unsigned i = 0; i < sizeof(opens) / sizeof(opens[0]); i++) {
			int fd = open(opens[i].name, opens[i].flags, 0644);

			printf("SELFTEST open(%s, %#x) = %d errno %d\n", opens[i].name, opens[i].flags, fd, fd < 0 ? errno : 0);
			if (fd >= 0) {
				int r = fchmod(fd, 0644);

				printf("SELFTEST   fchmod = %d errno %d\n", r, r ? errno : 0);
				r = fstat(fd, &st);
				printf("SELFTEST   fstat = %d errno %d size %ld\n", r, r ? errno : 0, r ? 0L : (long)st.st_size);
				printf("SELFTEST   pwrite = %d\n", (int)pwrite(fd, "abc", 3, 0));
				close(fd);
			}
		}
	}
}
#endif

/* ---- what the C library lacks --------------------------------------------------------------------------- */

/* "mc0:/a/b" -> port 0 and "/a/b"; -1 for a path not on a memory card */
static int mc_path(const char *path, const char **rest)
{
	if (strncmp(path, "mc", 2) != 0 || (path[2] != '0' && path[2] != '1') || path[3] != ':')
		return -1;
	*rest = path[4] ? path + 4 : "/";
	return path[2] - '0';
}

static int mc_errno(int ret)
{
	switch (ret) {
	case -3: return ENOSPC;
	case -4: return ENOENT;
	case -5: return EACCES;
	case -6: return ENOTEMPTY;
	default: return EIO;
	}
}

/* On a memory card the C library's unlink() leaves an empty directory in the file's place, and rmdir()
   and rename() are not there at all (ENOSYS): use libmc. Linked with -Wl,--wrap=unlink,--wrap=rmdir,
   --wrap=rename. */
static int mc_delete(const char *path)
{
	const char *rest;
	int port = mc_path(path, &rest), ret;

	mcDelete(port, 0, rest);
	mcSync(0, NULL, &ret);
	if (ret < 0) {
		errno = mc_errno(ret);
		return -1;
	}
	return 0;
}

int __real_unlink(const char *path);
int __wrap_unlink(const char *path)
{
	const char *rest;

	return mc_path(path, &rest) < 0 ? __real_unlink(path) : mc_delete(path);
}

int __real_rmdir(const char *path);
int __wrap_rmdir(const char *path)
{
	const char *rest;

	return mc_path(path, &rest) < 0 ? __real_rmdir(path) : mc_delete(path);
}

/* the card renames within a folder only: the new name has no path */
int __real_rename(const char *from, const char *to);
int __wrap_rename(const char *from, const char *to)
{
	const char *rest_from, *rest_to, *slash_from, *slash_to;
	int port = mc_path(from, &rest_from), ret;

	if (port < 0)
		return __real_rename(from, to);
	if (mc_path(to, &rest_to) != port) {
		errno = EXDEV;
		return -1;
	}
	slash_from = strrchr(rest_from, '/');
	slash_to = strrchr(rest_to, '/');
	if (!slash_from || !slash_to || slash_from - rest_from != slash_to - rest_to ||
	    strncmp(rest_from, rest_to, (size_t)(slash_from - rest_from)) != 0) {
		errno = EXDEV;
		return -1;
	}
	mcRename(port, 0, rest_from, slash_to + 1);
	mcSync(0, NULL, &ret);
	if (ret < 0) {
		errno = mc_errno(ret);
		return -1;
	}
	return 0;
}

/* On a memory card, stat() of a file that does not exist succeeds (st_mode without a file type); the
   server would then open a missing file without O_CREAT. Linked with -Wl,--wrap=stat. */
int __real_stat(const char *path, struct stat *st);
int __wrap_stat(const char *path, struct stat *st)
{
	int r = __real_stat(path, st);

	if (r == 0 && (st->st_mode & S_IFMT) == 0) {
		errno = ENOENT;
		return -1;
	}
	return r;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	if (lseek(fd, offset, SEEK_SET) < 0)
		return -1;
	return read(fd, buf, count);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	if (lseek(fd, offset, SEEK_SET) < 0)
		return -1;
	return write(fd, buf, count);
}

/* A memory card's free space, in its 1 KiB clusters. The size is taken to be that of a standard 8 MB card. */
int statvfs(const char *path, struct statvfs *buf)
{
	int type, free_clusters, format, ret;
	int port;

	if (strncmp(path, "mc0:", 4) == 0)
		port = 0;
	else if (strncmp(path, "mc1:", 4) == 0)
		port = 1;
	else
		return -1;
	if (mcGetInfo(port, 0, &type, &free_clusters, &format) < 0)
		return -1;
	mcSync(0, NULL, &ret);
	if (ret < -1 || type != MC_TYPE_PS2)
		return -1;
	buf->f_bsize = buf->f_frsize = 1024;
	buf->f_blocks = 8192;
	buf->f_bfree = buf->f_bavail = (unsigned long)free_clusters;
	return 0;
}

/* ---- no discovery and no srvsvc on the PS2 -------------------------------------------------------------- */

char smbd_name[16] = "PS2";

void names_set(const char *console_name)
{
	if (console_name && *console_name)
		snprintf(smbd_name, sizeof(smbd_name), "%s", console_name);
}

const char *names_label(void)
{
	return "ps2";
}

void names_start(void)
{
}

void wsd_start(void)
{
}

int rpc_init(void)
{
	return -1;
}

int rpc_is_pipe(const char *name)
{
	(void)name;
	return 0;
}

void *rpc_pipe_open(void)
{
	return NULL;
}

void rpc_pipe_close(void *pipe)
{
	(void)pipe;
}

int rpc_pipe_write(void *pipe, const uint8_t *buf, size_t len)
{
	(void)pipe;
	(void)buf;
	(void)len;
	return -1;
}

size_t rpc_pipe_read(void *pipe, uint8_t *buf, size_t max, int *more)
{
	(void)pipe;
	(void)buf;
	(void)max;
	*more = 0;
	return 0;
}
