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

int main(void)
{
	static struct smb2_server server;
	int err;

	signal(SIGPIPE, SIG_IGN);
	memset(&server, 0, sizeof(server));
	server.handlers = &smbd_handlers;
	server.port = SMBD_PORT;
	/* A known password gives NTLM a session key, so the session can be signed: Windows 11 requires
	   signing, and refuses guest sessions (docs/decision-log.md D1). */
	server.signing_enabled = 1;
	server.allow_anonymous = 0;
	snprintf(server.hostname, sizeof(server.hostname), "PS5");
	snprintf(server.domain, sizeof(server.domain), "WORKGROUP");
	for (int i = 0; i < 16; i++)
		server.guid[i] = (uint8_t)(time(NULL) >> (i % 4 * 8)) ^ (uint8_t)(i * 37);

	smbd_log("starting on port %d: \\\\<this console>\\%s and \\%s, login %s", SMBD_PORT, smbd_shares[0].name,
	         smbd_shares[1].name, SMBD_USER);
	err = smb2_serve_port(&server, SMBD_MAX_CLIENTS, on_new_client, NULL);
	smbd_log("stopped (%d): is another SMB server already on port %d?", err, SMBD_PORT);
	return err ? 1 : 0;
}
