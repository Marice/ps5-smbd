/* ps5-smbd: the PS5's /data and /mnt as SMB shares (\\<ps5>\data, \\<ps5>\mnt), login ps5 / ps5.
 *
 * libsmb2's server does the protocol (negotiate, NTLM, signing, the poll loop); fs.c answers the requests.
 * The host build (make host) is the same program on Linux, on another port, for the tests. */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "smbd.h"

#ifndef SMBD_PORT
#define SMBD_PORT 445
#endif
#ifndef SMBD_TRACE_FILE
#define SMBD_TRACE_FILE "/data/ps5-smbd/smbd.log"
#endif
#ifndef SMBD_SOCKET_BUFFER
#define SMBD_SOCKET_BUFFER (4 << 20)
#endif
#ifndef SMBD_MAX_CLIENTS
#define SMBD_MAX_CLIENTS 8
#endif

#ifdef SMBD_HOST
/* The host build shares two test folders instead (make host: SMBD_DATA / SMBD_MNT). */
const struct share smbd_shares[] = {{"data", SMBD_DATA}, {"mnt", SMBD_MNT}};
#else
const struct share smbd_shares[] = {{"data", "/data"}, {"mnt", "/mnt"}};
#endif
const int smbd_share_count = sizeof(smbd_shares) / sizeof(smbd_shares[0]);

/* opened in main() before the other threads start, which log too */
static FILE *g_trace_log;

void smbd_log(const char *fmt, ...)
{
	char line[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	/* stdout of a payload goes to the kernel log (klogsrv shows it) */
	printf("[ps5-smbd] %s\n", line);
	fflush(stdout);
	/* with tracing on, a file too: a payload started by a payload manager may not reach the kernel log */
	if (smbd_trace && g_trace_log) {
		fprintf(g_trace_log, "%ld %s\n", (long)time(NULL), line);
		fflush(g_trace_log);
	}
}

static void on_error(struct smb2_context *smb2, const char *text)
{
	(void)smb2;
	if (text && *text)
		smbd_log("client error: %s", text);
}

/* Larger socket buffers than the console's defaults: an upload is limited by how much the receiving side may
   have in flight (docs/decision-log.md D14, D15). FreeBSD refuses a size above its limit (ENOBUFS) rather
   than cutting it down, so halve until one is taken. Not on the host: Linux stops growing a buffer by
   itself once a size is set. */
static void set_socket_buffers(int fd)
{
#ifdef SMBD_HOST
	(void)fd;
#else
	int before = 0, size = SMBD_SOCKET_BUFFER, granted = 0, err = 0;
	socklen_t len = sizeof(before);

	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &before, &len);
	for (; size > before; size /= 2) {
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0) {
			setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
			break;
		}
		err = errno;
	}
	len = sizeof(granted);
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &granted, &len);
	if (smbd_trace)
		smbd_log("client socket receive buffer: %d by default, %d now%s%s", before, granted,
		         err ? ", larger refused: " : "", err ? strerror(err) : "");
#endif
}

static void on_new_client(struct smb2_context *smb2, void *cb_data)
{
	(void)cb_data;
	/* Up to SMB 3.0.2: libsmb2 6.3's server encodes the SMB 3.1.1 negotiate contexts wrongly (its own
	   client refuses the reply: "Unknown negotiate context type 0x0000"). 3.0.2 signs (AES-CMAC) and
	   every Windows since 8.1 speaks it. */
	smb2_set_version(smb2, SMB2_VERSION_0302);
	smb2_register_error_callback(smb2, on_error);
	set_socket_buffers(smb2_get_fd(smb2));
}

#ifndef SMBD_HOST
/* The process's name in the console's process list (and PayLoader's Running screen), instead of "payload". */
int sceKernelSetProcessName(const char *name);
/* The console's name as set in Settings > System; parameter 6 on the PS4 and the PS5 (OpenOrbis'
   SystemService.h; RommPS and SharpProspero read it so on the PS5). */
int sceSystemServiceParamGetString(int param_id, char *buf, size_t size);
#define SYSTEM_SERVICE_PARAM_ID_SYSTEM_NAME 6
#endif

#ifndef SMBD_HOST
#include <fcntl.h>
#include <ucontext.h>
#include <unistd.h>

/* A crash leaves one line in the log, whether tracing is on or not: the signal, the faulting address and the
   instruction, as offsets from main() so `nm ps5-smbd.elf` places them, and the stack words that look like
   return addresses into this program (the build has no frame pointers to walk). */
int main(void);

static void on_crash(int sig, siginfo_t *si, void *ctx)
{
	const mcontext_t *mc = &((ucontext_t *)ctx)->uc_mcontext;
	const uintptr_t base = (uintptr_t)&main;
	const uintptr_t *sp = (const uintptr_t *)mc->mc_rsp;
	char line[1024];
	int n, fd;

	n = snprintf(line, sizeof(line), "%ld CRASH signal %d at %p: rip main%+ld, rsp %p; stack", (long)time(NULL),
	             sig, si->si_addr, (long)(mc->mc_rip - base), (void *)mc->mc_rsp);
	for (int i = 0; i < 64 && n < (int)sizeof(line) - 24; i++) {
		long off = (long)(sp[i] - base);

		if (off > -0x400000 && off < 0x400000)
			n += snprintf(line + n, sizeof(line) - (size_t)n, " main%+ld", off);
	}
	n += snprintf(line + n, sizeof(line) - (size_t)n, "\n");
	fd = open(SMBD_TRACE_FILE, O_WRONLY | O_APPEND | O_CREAT, 0666);
	if (fd >= 0) {
		write(fd, line, (size_t)n);
		close(fd);
	}
	write(1, line, (size_t)n);
	_exit(128 + sig);
}

static void catch_crashes(void)
{
	struct sigaction sa;
	static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = on_crash;
	sa.sa_flags = SA_SIGINFO;
	for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
		sigaction(sigs[i], &sa, NULL);
}
#endif

/* The name to go by: the console's own, PS5 when it can't be read. */
static void pick_name(void)
{
	char name[128] = "";

#ifdef SMBD_HOST
	snprintf(name, sizeof(name), "%s", getenv("SMBD_NAME") ? getenv("SMBD_NAME") : "PS5-HOST");
#else
	if (sceSystemServiceParamGetString(SYSTEM_SERVICE_PARAM_ID_SYSTEM_NAME, name, sizeof(name)) != 0)
		name[0] = 0;
	name[sizeof(name) - 1] = 0;
	for (const char *c = name; *c; c++) {
		if ((unsigned char)*c < 0x20) {
			name[0] = 0; /* not a name */
			break;
		}
	}
#endif
	names_set(name);
	smbd_log("console name \"%s\": \\\\%s, %s.local", name, smbd_name, names_label());
}

int main(void)
{
	static struct smb2_server server;
	int err;

#ifndef SMBD_HOST
	sceKernelSetProcessName("ps5-smbd.elf");
	catch_crashes();
#endif
	signal(SIGPIPE, SIG_IGN);
	{
		FILE *f = fopen("/data/ps5-smbd/trace", "r"); /* the switch: its presence, not its content */

		smbd_trace = getenv("SMBD_TRACE") != NULL || f != NULL;
		if (f)
			fclose(f);
		if (smbd_trace)
			g_trace_log = fopen(SMBD_TRACE_FILE, "a");
	}
	pick_name();
	if (rpc_init() < 0)
		smbd_log("srvsvc off: \\\\<console> will not list the shares");
	names_start();
	wsd_start();
	memset(&server, 0, sizeof(server));
	server.handlers = &smbd_handlers;
	server.port = SMBD_PORT;
	/* A known password gives NTLM a session key, so the session can be signed: Windows 11 requires
	   signing, and refuses guest sessions (docs/decision-log.md D1). */
	server.signing_enabled = 1;
	server.allow_anonymous = 0;
	snprintf(server.hostname, sizeof(server.hostname), "%s", smbd_name);
	snprintf(server.domain, sizeof(server.domain), "WORKGROUP");
	for (int i = 0; i < 16; i++)
		server.guid[i] = (uint8_t)(time(NULL) >> (i % 4 * 8)) ^ (uint8_t)(i * 37);

	smbd_log("starting on port %d: \\\\%s\\%s and \\%s, login %s", SMBD_PORT, smbd_name, smbd_shares[0].name,
	         smbd_shares[1].name, SMBD_USER);
	err = smb2_serve_port(&server, SMBD_MAX_CLIENTS, on_new_client, NULL);
	smbd_log("stopped (%d): is another SMB server already on port %d?", err, SMBD_PORT);
	return err ? 1 : 0;
}
