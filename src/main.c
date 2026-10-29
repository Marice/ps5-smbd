/* ps5-smbd: the PS5's /data and /mnt as SMB shares (\\<ps5>\data, \\<ps5>\mnt), login ps5 / ps5.
 *
 * libsmb2's server does the protocol (negotiate, NTLM, signing, the poll loop); fs.c answers the requests.
 * The host build (make host) is the same program on Linux, on another port, for the tests. */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smbd.h"

#ifndef SMBD_PORT
#define SMBD_PORT 445
#endif
#ifndef SMBD_TRACE_FILE
#define SMBD_TRACE_FILE "/data/ps5-smbd/smbd.log"
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
	if (smbd_trace) {
		static FILE *log;

		if (!log)
			log = fopen(SMBD_TRACE_FILE, "a");
		if (log) {
			fprintf(log, "%ld %s\n", (long)time(NULL), line);
			fflush(log);
		}
	}
}

static void on_error(struct smb2_context *smb2, const char *text)
{
	(void)smb2;
	if (text && *text)
		smbd_log("client error: %s", text);
}

static void on_new_client(struct smb2_context *smb2, void *cb_data)
{
	(void)cb_data;
	/* Up to SMB 3.0.2: libsmb2 6.3's server encodes the SMB 3.1.1 negotiate contexts wrongly (its own
	   client refuses the reply: "Unknown negotiate context type 0x0000"). 3.0.2 signs (AES-CMAC) and
	   every Windows since 8.1 speaks it. */
	smb2_set_version(smb2, SMB2_VERSION_0302);
	smb2_register_error_callback(smb2, on_error);
}

#ifndef SMBD_HOST
/* The process's name in the console's process list (and PayLoader's Running screen), instead of "payload". */
int sceKernelSetProcessName(const char *name);
/* The console's name as set in Settings > System; parameter 6 on the PS4 and the PS5 (OpenOrbis'
   SystemService.h; RommPS and SharpProspero read it so on the PS5). */
int sceSystemServiceParamGetString(int param_id, char *buf, size_t size);
#define SYSTEM_SERVICE_PARAM_ID_SYSTEM_NAME 6
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
#endif
	signal(SIGPIPE, SIG_IGN);
	{
		FILE *f = fopen("/data/ps5-smbd/trace", "r"); /* the switch: its presence, not its content */

		smbd_trace = getenv("SMBD_TRACE") != NULL || f != NULL;
		if (f)
			fclose(f);
	}
	pick_name();
	if (rpc_init() < 0)
		smbd_log("srvsvc off: \\\\<console> will not list the shares");
	names_start();
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
