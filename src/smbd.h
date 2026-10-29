#pragma once

#include <stdint.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#define SMBD_USER     "ps5"
#define SMBD_PASSWORD "ps5"

/* The shares: name, folder. IPC$ is answered too (clients always ask for it), but holds nothing. */
struct share {
	const char *name;
	const char *root;
};

extern const struct share smbd_shares[];
extern const int smbd_share_count;

/* The request handlers, on the console's own file system (fs.c). */
extern struct smb2_server_request_handlers smbd_handlers;

void smbd_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
