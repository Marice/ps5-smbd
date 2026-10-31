#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h> /* libsmb2's headers use time_t without it */

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#define SMBD_USER     "ps5"
#define SMBD_PASSWORD "ps5"

/* The shares (shares.c): name, folder. data and mnt come first; after them each drive under mnt that is
   mounted, added when first seen and kept (an index stays valid), so check share_available(). IPC$ is
   answered too (clients always ask for it), but holds nothing. */
#define SMBD_MAX_SHARES 16
struct share {
	char name[16];
	char root[256];
};

extern struct share smbd_shares[SMBD_MAX_SHARES];
extern int smbd_share_count;
void shares_refresh(void);
int share_available(int index);
/* 1 and the device a share's folder is on, or 0 when the share is not there now (a device may be 0) */
int share_device(int index, unsigned long long *device);
int share_find(const char *name); /* an available share's index, or -1 */

/* The request handlers, on the console's own file system (fs.c). */
extern struct smb2_server_request_handlers smbd_handlers;

extern int smbd_trace;

/* The console's name on the network (names.c): NetBIOS form, also the SMB and srvsvc server name. */
extern char smbd_name[16];
void names_set(const char *console_name);
const char *names_label(void);
void names_start(void);
struct in_addr;
int names_address(struct in_addr peer, struct in_addr *out);

/* WS-Discovery (wsd.c): the console in Windows' Network view. */
void wsd_start(void);

/* The srvsvc pipe on IPC$ (rpc.c), which lists the shares. */
int rpc_init(void);
int rpc_is_pipe(const char *name);
void *rpc_pipe_open(void);
void rpc_pipe_close(void *pipe);
int rpc_pipe_write(void *pipe, const uint8_t *buf, size_t len);
size_t rpc_pipe_read(void *pipe, uint8_t *buf, size_t max, int *more);

void smbd_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#ifdef _EE
/* The PS2 (ps2.c): IOP modules, memory cards and the network up; < 0 if there is no network. */
int ps2_init(void);
#endif
