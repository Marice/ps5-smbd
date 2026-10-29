#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h> /* libsmb2's headers use time_t without it */

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

extern int smbd_trace;

/* The console's name on the network (names.c): NetBIOS form, also the SMB and srvsvc server name. */
extern char smbd_name[16];
void names_set(const char *console_name);
const char *names_label(void);
void names_start(void);

/* The srvsvc pipe on IPC$ (rpc.c), which lists the shares. */
int rpc_init(void);
int rpc_is_pipe(const char *name);
void *rpc_pipe_open(void);
void rpc_pipe_close(void *pipe);
int rpc_pipe_write(void *pipe, const uint8_t *buf, size_t len);
size_t rpc_pipe_read(void *pipe, uint8_t *buf, size_t max, int *more);

void smbd_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
