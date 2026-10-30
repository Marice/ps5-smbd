/* The SMB requests, answered on the console's own file system.
 *
 * libsmb2's server turns every handler error into STATUS_NOT_IMPLEMENTED, so a handler that has a real
 * answer to give ("no such file", "access denied") queues its own error reply and returns 1 (reply()).
 * Windows chains requests (create, query info, close in one packet); a later request in the chain names the
 * file just created by the file id with every bit set (RELATED_FID).
 *
 * Paths come in relative to the share, with backslashes; they are joined under the share's folder after
 * every ".." and absolute part has been refused, so nothing outside /data and /mnt is reachable. */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "smbd.h"

/* The request header's tree id: libsmb2 6.3 has no public call for it on the server side. The library is
   built from this exact pinned version (tools/build-libsmb2.sh), so its private header matches. */
#include "libsmb2-private.h"

/* every request in the kernel log: SMBD_TRACE in the environment, or a file named trace next to /data/ps5-smbd */
int smbd_trace;

#define MAX_HANDLES 256
#define MAX_TREES 16
#define MAX_NOTIFIES 32
#ifndef SMB2_STATUS_NOTIFY_CLEANUP
#define SMB2_STATUS_NOTIFY_CLEANUP 0x0000010B
#endif
#define TREE_IPC (-1)
#define FILE_MODE 0777 /* as everything else on the console's homebrew side: a title won't start otherwise */

/* create_action values (MS-SMB2 2.2.14) */
#define ACTION_SUPERSEDED 0
#define ACTION_OPENED 1
#define ACTION_CREATED 2
#define ACTION_OVERWRITTEN 3

/* access mask bits that need the file open for writing */
#define WANTS_WRITE (0x00000002 | 0x00000004 | 0x00000100 | 0x40000000 | 0x10000000 | 0x02000000)

struct handle {
	int used;
	uint32_t generation;
	int share;
	int is_dir;
	int fd;
	void *pipe; /* a named pipe on IPC$ (rpc.c) instead of a file */
	int delete_on_close;
	char path[PATH_MAX];
	/* directory listing state */
	DIR *dir;
	int listed_dots;
	int listing_started;
	char pattern[256];
	struct dirent *pushback; /* an entry read but not sent: the client's buffer was full */
	char pushback_name[256];
	int has_pushback;
};

struct tree {
	uint32_t id;
	int share; /* index into smbd_shares, or TREE_IPC */
};

/* A change notify left pending: the reply is owed when the client cancels it or closes the folder. */
struct notify {
	int used;
	uint64_t message_id;
	uint64_t async_id; /* given with the interim reply; how the client names it in a cancel */
	int handle;
};

struct conn {
	struct handle handles[MAX_HANDLES];
	struct notify notifies[MAX_NOTIFIES];
	struct tree trees[MAX_TREES];
	uint32_t next_tree;
	uint32_t generation;
	smb2_file_id last_created; /* for related (chained) requests */
	int have_last_created;
	void *scratch;             /* the last reply buffer handed to libsmb2, which doesn't free it */
	char (*names)[256];        /* directory entry names, alive until the next request */
};

/* ---- connection state ---------------------------------------------------------------------------------- */

static struct conn *conn_of(struct smb2_context *smb2)
{
	struct conn *c = smb2_get_opaque(smb2);

	if (!c) {
		c = calloc(1, sizeof(*c));
		if (!c)
			return NULL;
		c->next_tree = 1;
		for (int i = 0; i < MAX_HANDLES; i++)
			c->handles[i].fd = -1;
		smb2_set_opaque(smb2, c);
	}
	/* whatever the previous reply needed is encoded by now */
	free(c->scratch);
	c->scratch = NULL;
	free(c->names);
	c->names = NULL;
	return c;
}

static void handle_free(struct handle *h)
{
	if (h->pipe)
		rpc_pipe_close(h->pipe);
	if (h->fd >= 0)
		close(h->fd);
	if (h->dir)
		closedir(h->dir);
	memset(h, 0, sizeof(*h));
	h->fd = -1;
}

static int destruction(struct smb2_server *srvr, struct smb2_context *smb2)
{
	struct conn *c = smb2_get_opaque(smb2);

	(void)srvr;
	if (!c)
		return 0;
	for (int i = 0; i < MAX_HANDLES; i++) {
		if (c->handles[i].used)
			handle_free(&c->handles[i]);
	}
	free(c->scratch);
	free(c->names);
	free(c);
	smb2_set_opaque(smb2, NULL);
	smbd_log("client gone");
	return 0;
}

static int request_share(struct conn *c, struct smb2_context *smb2)
{
	uint32_t id = smb2->hdr.sync.tree_id;

	for (int i = 0; i < MAX_TREES; i++) {
		if (c->trees[i].id && c->trees[i].id == id)
			return c->trees[i].share;
	}
	return -2;
}

/* The file id: handle index and a generation, so a stale id from a closed handle is refused. */
static void make_fid(smb2_file_id fid, int index, uint32_t generation)
{
	memset(fid, 0, SMB2_FD_SIZE);
	memcpy(fid, &index, sizeof(index));
	memcpy(fid + 4, &generation, sizeof(generation));
	memcpy(fid + 8, &index, sizeof(index));
	memcpy(fid + 12, &generation, sizeof(generation));
}

static struct handle *find_handle(struct conn *c, const smb2_file_id fid_in)
{
	smb2_file_id fid;
	int index;
	uint32_t generation;
	int related = 1;

	for (int i = 0; i < SMB2_FD_SIZE; i++) {
		if (fid_in[i] != 0xFF)
			related = 0;
	}
	if (related) {
		if (!c->have_last_created)
			return NULL;
		memcpy(fid, c->last_created, SMB2_FD_SIZE);
	} else {
		memcpy(fid, fid_in, SMB2_FD_SIZE);
	}
	memcpy(&index, fid, sizeof(index));
	memcpy(&generation, fid + 4, sizeof(generation));
	if (index < 0 || index >= MAX_HANDLES || !c->handles[index].used || c->handles[index].generation != generation)
		return NULL;
	return &c->handles[index];
}

/* ---- replies -------------------------------------------------------------------------------------------- */

/* A reply of status only to the request with that message id (a pending one, answered later). */
static void reply_to(struct smb2_context *smb2, uint8_t command, uint32_t status, uint64_t message_id)
{
	struct smb2_error_reply err;
	struct smb2_pdu *pdu;

	memset(&err, 0, sizeof(err));
	pdu = smb2_cmd_error_reply_async(smb2, &err, command, (int)status, NULL, NULL);
	if (pdu) {
		smb2_set_pdu_message_id(smb2, pdu, message_id);
		smb2_queue_pdu(smb2, pdu);
	}
}

/* An error reply with a real status; the handler then returns this function's 1. */
static int reply(struct smb2_context *smb2, uint8_t command, uint32_t status)
{
	struct smb2_error_reply err;
	struct smb2_pdu *pdu;

	if (smbd_trace)
		smbd_log("command %u -> status %08x", command, status);
	memset(&err, 0, sizeof(err));
	pdu = smb2_cmd_error_reply_async(smb2, &err, command, (int)status, NULL, NULL);
	if (pdu) {
		/* a reply carries its request's message id (libsmb2 does the same for its own replies) */
		smb2_set_pdu_message_id(smb2, pdu, smb2->message_id);
		smb2_queue_pdu(smb2, pdu);
	}
	return 1;
}

static uint32_t status_of(int err)
{
	switch (err) {
	case ENOENT: return SMB2_STATUS_OBJECT_NAME_NOT_FOUND;
	case ENOTDIR: return SMB2_STATUS_OBJECT_PATH_NOT_FOUND;
	case EACCES:
	case EPERM: return SMB2_STATUS_ACCESS_DENIED;
	case EEXIST: return SMB2_STATUS_OBJECT_NAME_COLLISION;
	case ENOTEMPTY: return SMB2_STATUS_DIRECTORY_NOT_EMPTY;
	case EISDIR: return SMB2_STATUS_FILE_IS_A_DIRECTORY;
	case ENOSPC: return SMB2_STATUS_DISK_FULL;
	case EROFS: return SMB2_STATUS_MEDIA_WRITE_PROTECTED;
	case ENAMETOOLONG: return SMB2_STATUS_NAME_TOO_LONG;
	case EXDEV: return SMB2_STATUS_NOT_SAME_DEVICE;
	case EMFILE:
	case ENFILE: return SMB2_STATUS_TOO_MANY_OPENED_FILES;
	case EBUSY: return SMB2_STATUS_SHARING_VIOLATION;
	case EINVAL: return SMB2_STATUS_INVALID_PARAMETER;
	default: return SMB2_STATUS_INTERNAL_ERROR;
	}
}

/* ---- paths and attributes ------------------------------------------------------------------------------- */

/* share root + the client's relative path; -1 for anything that would leave the share. */
static int join_path(int share, const char *name, char *out, size_t size)
{
	char rel[PATH_MAX];
	size_t n = 0;
	const char *p = name ? name : "";

	while (*p == '\\' || *p == '/')
		p++;
	for (; *p && n + 1 < sizeof(rel); p++)
		rel[n++] = *p == '\\' ? '/' : *p;
	rel[n] = 0;
	while (n && rel[n - 1] == '/')
		rel[--n] = 0;
	/* no "..", no "." parts, no streams (name:stream) */
	for (char *part = rel; *part;) {
		char *end = strchr(part, '/');
		size_t len = end ? (size_t)(end - part) : strlen(part);

		if ((len == 2 && part[0] == '.' && part[1] == '.') || (len == 1 && part[0] == '.') || len == 0)
			return -1;
		if (memchr(part, ':', len))
			return -1;
		if (!end)
			break;
		part = end + 1;
	}
	if ((size_t)snprintf(out, size, "%s%s%s", smbd_shares[share].root, rel[0] ? "/" : "", rel) >= size)
		return -1;
	return 0;
}

static uint64_t nt_time(time_t sec, long nsec)
{
	return ((uint64_t)sec + 11644473600ull) * 10000000ull + (uint64_t)nsec / 100;
}

static struct smb2_timeval tv_of(time_t sec, long nsec)
{
	struct smb2_timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = nsec / 1000;
	return tv;
}

#if defined(__FreeBSD__) || defined(__PROSPERO__)
#define MTIME(st) (st)->st_mtim
#define ATIME(st) (st)->st_atim
#define CTIME(st) (st)->st_ctim
#define BTIME(st) (st)->st_birthtim
#else
#define MTIME(st) (st)->st_mtim
#define ATIME(st) (st)->st_atim
#define CTIME(st) (st)->st_ctim
#define BTIME(st) (st)->st_mtim
#endif

static uint32_t attributes_of(const struct stat *st, const char *name)
{
	uint32_t a = S_ISDIR(st->st_mode) ? SMB2_FILE_ATTRIBUTE_DIRECTORY : SMB2_FILE_ATTRIBUTE_ARCHIVE;
	const char *base = name ? strrchr(name, '/') : NULL;

	base = base ? base + 1 : name;
	if (base && base[0] == '.' && strcmp(base, ".") && strcmp(base, ".."))
		a |= SMB2_FILE_ATTRIBUTE_HIDDEN;
	return a;
}

static uint64_t allocation_of(const struct stat *st)
{
	return S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_blocks * 512;
}

/* ---- session and trees ---------------------------------------------------------------------------------- */

static int authorize(struct smb2_server *srvr, struct smb2_context *smb2, const char *user, const char *domain,
                     const char *workstation)
{
	(void)srvr;
	if (!user || strcasecmp(user, SMBD_USER)) {
		smbd_log("login refused: user \"%s\" from %s", user ? user : "", workstation ? workstation : "?");
		return -1;
	}
	smb2_set_user(smb2, user);
	smb2_set_password(smb2, SMBD_PASSWORD);
	smbd_log("login: %s%s%s from %s", domain && *domain ? domain : "", domain && *domain ? "\\" : "", user,
	         workstation ? workstation : "?");
	return 0;
}

static int session_up(struct smb2_server *srvr, struct smb2_context *smb2)
{
	(void)srvr;
	smbd_log("session up, dialect %04x", smb2_get_dialect(smb2));
	return 0;
}

static int logoff(struct smb2_server *srvr, struct smb2_context *smb2)
{
	(void)srvr;
	(void)smb2;
	return 0;
}

static int tree_connect(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_tree_connect_request *req,
                        struct smb2_tree_connect_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	const char *path;
	const char *name;
	int share = -2;
	int slot = -1;
	struct smb2_pdu *pdu;
	uint32_t id;

	(void)srvr;
	if (!c)
		return reply(smb2, SMB2_TREE_CONNECT, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	path = req->path ? smb2_utf16_to_utf8(req->path, req->path_length / 2) : NULL;
	if (!path)
		return reply(smb2, SMB2_TREE_CONNECT, SMB2_STATUS_BAD_NETWORK_NAME);
	name = strrchr(path, '\\');
	name = name ? name + 1 : path;
	if (!strcasecmp(name, "IPC$"))
		share = TREE_IPC;
	for (int i = 0; i < smbd_share_count; i++) {
		if (!strcasecmp(name, smbd_shares[i].name))
			share = i;
	}
	for (int i = 0; i < MAX_TREES; i++) {
		if (!c->trees[i].id) {
			slot = i;
			break;
		}
	}
	if (share == -2 || slot < 0) {
		smbd_log("no share \"%s\"", name);
		free((void *)path);
		return reply(smb2, SMB2_TREE_CONNECT, slot < 0 ? SMB2_STATUS_INSUFFICIENT_RESOURCES
		                                               : SMB2_STATUS_BAD_NETWORK_NAME);
	}
	free((void *)path);
	id = c->next_tree++;
	c->trees[slot].id = id;
	c->trees[slot].share = share;
	rep->share_type = share == TREE_IPC ? SMB2_SHARE_TYPE_PIPE : SMB2_SHARE_TYPE_DISK;
	rep->share_flags = 0;
	rep->capabilities = 0;
	rep->maximal_access = 0x001F01FF; /* everything */
	pdu = smb2_cmd_tree_connect_reply_async(smb2, rep, id, NULL, NULL);
	if (!pdu)
		return reply(smb2, SMB2_TREE_CONNECT, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	smb2_set_pdu_message_id(smb2, pdu, smb2->message_id);
	smb2_queue_pdu(smb2, pdu);
	smbd_log("share \"%s\" connected (tree %u)", share == TREE_IPC ? "IPC$" : smbd_shares[share].name, id);
	return 1;
}

static int tree_disconnect(struct smb2_server *srvr, struct smb2_context *smb2, const uint32_t tree_id)
{
	struct conn *c = conn_of(smb2);

	(void)srvr;
	if (!c)
		return 0;
	for (int i = 0; i < MAX_TREES; i++) {
		if (c->trees[i].id == tree_id)
			c->trees[i].id = 0;
	}
	return 0;
}

/* ---- files ---------------------------------------------------------------------------------------------- */

static void fill_open_reply(struct smb2_create_reply *rep, const struct stat *st, const char *path)
{
	rep->creation_time = nt_time(BTIME(st).tv_sec, BTIME(st).tv_nsec);
	rep->last_access_time = nt_time(ATIME(st).tv_sec, ATIME(st).tv_nsec);
	rep->last_write_time = nt_time(MTIME(st).tv_sec, MTIME(st).tv_nsec);
	rep->change_time = nt_time(CTIME(st).tv_sec, CTIME(st).tv_nsec);
	rep->allocation_size = allocation_of(st);
	rep->end_of_file = S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_size;
	rep->file_attributes = attributes_of(st, path);
}

static int open_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_create_request *req,
                     struct smb2_create_reply *rep);

/* A named pipe on IPC$: only srvsvc, which lists the shares (rpc.c). */
static int open_pipe(struct conn *c, struct smb2_context *smb2, struct smb2_create_request *req,
                     struct smb2_create_reply *rep)
{
	struct handle *h = NULL;
	int index = -1;

	if (!rpc_is_pipe(req->name)) {
		smbd_log("pipe \"%s\" not served", req->name ? req->name : "");
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_NAME_NOT_FOUND);
	}
	for (int i = 0; i < MAX_HANDLES; i++) {
		if (!c->handles[i].used) {
			index = i;
			break;
		}
	}
	if (index < 0)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_TOO_MANY_OPENED_FILES);
	h = &c->handles[index];
	memset(h, 0, sizeof(*h));
	h->fd = -1;
	h->pipe = rpc_pipe_open();
	if (!h->pipe)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	h->used = 1;
	h->generation = ++c->generation;
	h->share = TREE_IPC;
	snprintf(h->path, sizeof(h->path), "\\PIPE\\srvsvc");
	memset(rep, 0, sizeof(*rep));
	rep->create_action = ACTION_OPENED;
	rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
	make_fid(rep->file_id, index, h->generation);
	memcpy(c->last_created, rep->file_id, SMB2_FD_SIZE);
	c->have_last_created = 1;
	if (smbd_trace)
		smbd_log("open pipe srvsvc: handle %d", index);
	return 0;
}

/* The request (and its name) belongs to libsmb2, which frees it once a reply to it is queued: nothing may
   look at req after reply(). */
static int create(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_create_request *req,
                  struct smb2_create_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	return open_file(srvr, smb2, req, rep);
}

static int open_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_create_request *req,
                     struct smb2_create_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	char path[PATH_MAX];
	struct stat st;
	int share, exists, want_dir, no_dir, index = -1, action = ACTION_OPENED;
	uint32_t disp = req->create_disposition;
	struct handle *h;

	(void)srvr;
	if (!c)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	/* until this create succeeds, related requests after it in a compound have no file (they fail with
	   FILE_CLOSED) rather than an earlier create's, which a CLOSE would then close */
	c->have_last_created = 0;
	share = request_share(c, smb2);
	if (share == TREE_IPC)
		return open_pipe(c, smb2, req, rep);
	if (share < 0)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_NETWORK_NAME_DELETED);
	if (join_path(share, req->name, path, sizeof(path)))
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_NAME_INVALID);
	for (int i = 0; i < MAX_HANDLES; i++) {
		if (!c->handles[i].used) {
			index = i;
			break;
		}
	}
	if (index < 0)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_TOO_MANY_OPENED_FILES);

	exists = stat(path, &st) == 0;
	if (!exists && errno == ENOTDIR)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_PATH_NOT_FOUND);
	want_dir = (req->create_options & SMB2_FILE_DIRECTORY_FILE) != 0;
	no_dir = (req->create_options & SMB2_FILE_NON_DIRECTORY_FILE) != 0;

	if (exists && disp == SMB2_FILE_CREATE)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_NAME_COLLISION);
	if (!exists && (disp == SMB2_FILE_OPEN || disp == SMB2_FILE_OVERWRITE)) {
		/* a missing parent folder is a different answer from a missing file */
		char parent[PATH_MAX];
		char *slash;
		struct stat pst;

		snprintf(parent, sizeof(parent), "%s", path);
		slash = strrchr(parent, '/');
		if (slash)
			*slash = 0;
		return reply(smb2, SMB2_CREATE, stat(parent, &pst) == 0 ? SMB2_STATUS_OBJECT_NAME_NOT_FOUND
		                                                         : SMB2_STATUS_OBJECT_PATH_NOT_FOUND);
	}
	if (exists && S_ISDIR(st.st_mode) && no_dir)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_FILE_IS_A_DIRECTORY);
	if (exists && !S_ISDIR(st.st_mode) && want_dir)
		return reply(smb2, SMB2_CREATE, SMB2_STATUS_NOT_A_DIRECTORY);

	h = &c->handles[index];
	memset(h, 0, sizeof(*h));
	h->fd = -1;
	if ((exists && S_ISDIR(st.st_mode)) || (!exists && want_dir)) {
		if (!exists) {
			if (mkdir(path, FILE_MODE) < 0)
				return reply(smb2, SMB2_CREATE, status_of(errno));
			chmod(path, FILE_MODE);
			action = ACTION_CREATED;
			if (stat(path, &st) < 0)
				return reply(smb2, SMB2_CREATE, status_of(errno));
		}
		h->is_dir = 1;
	} else {
		int flags = O_RDONLY;
		int fd;

		if ((req->desired_access & WANTS_WRITE) || disp != SMB2_FILE_OPEN)
			flags = O_RDWR;
		if (!exists)
			flags |= O_CREAT | O_EXCL;
		else if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF || disp == SMB2_FILE_SUPERSEDE)
			flags |= O_TRUNC;
		fd = open(path, flags, FILE_MODE);
		if (fd < 0 && (errno == EACCES || errno == EROFS) && !(flags & (O_CREAT | O_TRUNC)) &&
		    !(req->desired_access & WANTS_WRITE))
			fd = open(path, O_RDONLY);
		if (fd < 0)
			return reply(smb2, SMB2_CREATE, status_of(errno));
		if (!exists)
			fchmod(fd, FILE_MODE);
		if (fstat(fd, &st) < 0) {
			int e = errno;
			close(fd);
			return reply(smb2, SMB2_CREATE, status_of(e));
		}
		h->fd = fd;
		action = !exists ? ACTION_CREATED
		         : disp == SMB2_FILE_SUPERSEDE ? ACTION_SUPERSEDED
		         : (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF) ? ACTION_OVERWRITTEN
		                                                                            : ACTION_OPENED;
	}
	h->used = 1;
	h->generation = ++c->generation;
	h->share = share;
	h->delete_on_close = (req->create_options & SMB2_FILE_DELETE_ON_CLOSE) != 0;
	snprintf(h->path, sizeof(h->path), "%s", path);

	memset(rep, 0, sizeof(*rep));
	rep->create_action = (uint32_t)action;
	fill_open_reply(rep, &st, path);
	make_fid(rep->file_id, index, h->generation);
	memcpy(c->last_created, rep->file_id, SMB2_FD_SIZE);
	c->have_last_created = 1;
	if (smbd_trace)
		smbd_log("open %s (disposition %u, options %08x, access %08x): handle %d", path, disp, req->create_options,
		         req->desired_access, index);
	return 0;
}

static int close_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_close_request *req,
                      struct smb2_close_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;
	struct stat st;

	(void)srvr;
	if (!h)
		return reply(smb2, SMB2_CLOSE, SMB2_STATUS_FILE_CLOSED);
	/* a change notify still waiting on this folder ends now, before the close reply (MS-SMB2 3.3.5.10) */
	for (int i = 0; i < MAX_NOTIFIES; i++) {
		if (c->notifies[i].used && &c->handles[c->notifies[i].handle] == h) {
			reply_to(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_NOTIFY_CLEANUP, c->notifies[i].message_id);
			c->notifies[i].used = 0;
		}
	}
	memset(rep, 0, sizeof(*rep));
	if ((req->flags & SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB) && stat(h->path, &st) == 0) {
		rep->flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
		rep->creation_time = nt_time(BTIME(&st).tv_sec, BTIME(&st).tv_nsec);
		rep->last_access_time = nt_time(ATIME(&st).tv_sec, ATIME(&st).tv_nsec);
		rep->last_write_time = nt_time(MTIME(&st).tv_sec, MTIME(&st).tv_nsec);
		rep->change_time = nt_time(CTIME(&st).tv_sec, CTIME(&st).tv_nsec);
		rep->allocation_size = allocation_of(&st);
		rep->end_of_file = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
		rep->file_attributes = attributes_of(&st, h->path);
	}
	if (h->delete_on_close) {
		if (h->fd >= 0) {
			close(h->fd);
			h->fd = -1;
		}
		if ((h->is_dir ? rmdir(h->path) : unlink(h->path)) < 0)
			smbd_log("delete of %s failed: %s", h->path, strerror(errno));
	}
	if (smbd_trace)
		smbd_log("close %s (handle %d)", h->path, (int)(h - c->handles));
	handle_free(h);
	return 0;
}

static int flush_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_flush_request *req)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;

	(void)srvr;
	if (!h)
		return reply(smb2, SMB2_FLUSH, SMB2_STATUS_FILE_CLOSED);
	if (h->fd >= 0)
		fsync(h->fd);
	return 0;
}

static int read_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_read_request *req,
                     struct smb2_read_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;
	uint8_t *buf;
	ssize_t n;

	(void)srvr;
	if (!h)
		return reply(smb2, SMB2_READ, SMB2_STATUS_FILE_CLOSED);
	if (h->pipe) {
		int more = 0;
		size_t got;

		buf = malloc(req->length ? req->length : 1);
		if (!buf)
			return reply(smb2, SMB2_READ, SMB2_STATUS_INSUFFICIENT_RESOURCES);
		got = rpc_pipe_read(h->pipe, buf, req->length, &more);
		if (!got) {
			free(buf);
			return reply(smb2, SMB2_READ, SMB2_STATUS_PIPE_EMPTY);
		}
		if (more)
			smbd_log("pipe read of %u left more behind", req->length);
		memset(rep, 0, sizeof(*rep));
		rep->data = buf;
		rep->data_length = (uint32_t)got;
		return 0;
	}
	if (h->fd < 0)
		return reply(smb2, SMB2_READ, SMB2_STATUS_INVALID_DEVICE_REQUEST);
	if (!req->length)
		return reply(smb2, SMB2_READ, SMB2_STATUS_END_OF_FILE);
	buf = malloc(req->length);
	if (!buf)
		return reply(smb2, SMB2_READ, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	n = pread(h->fd, buf, req->length, (off_t)req->offset);
	if (n <= 0) {
		int e = errno;
		free(buf);
		return reply(smb2, SMB2_READ, n == 0 ? SMB2_STATUS_END_OF_FILE : status_of(e));
	}
	memset(rep, 0, sizeof(*rep));
	if (smbd_trace)
		smbd_log("read %s: %zd at %llu", h->path, n, (unsigned long long)req->offset);
	rep->data = buf; /* libsmb2 frees it with the reply */
	rep->data_length = (uint32_t)n;
	rep->data_remaining = 0;
	return 0;
}

static int write_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_write_request *req,
                      struct smb2_write_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;
	size_t done = 0;

	(void)srvr;
	if (!h)
		return reply(smb2, SMB2_WRITE, SMB2_STATUS_FILE_CLOSED);
	if (h->pipe) {
		if (rpc_pipe_write(h->pipe, req->buf, req->length) < 0)
			return reply(smb2, SMB2_WRITE, SMB2_STATUS_INVALID_PARAMETER);
		memset(rep, 0, sizeof(*rep));
		rep->count = req->length;
		return 0;
	}
	if (h->fd < 0)
		return reply(smb2, SMB2_WRITE, SMB2_STATUS_INVALID_DEVICE_REQUEST);
	while (done < req->length) {
		ssize_t n = pwrite(h->fd, req->buf + done, req->length - done, (off_t)(req->offset + done));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return reply(smb2, SMB2_WRITE, status_of(errno));
		}
		done += (size_t)n;
	}
	if (smbd_trace)
		smbd_log("write %s: %zu at %llu", h->path, done, (unsigned long long)req->offset);
	memset(rep, 0, sizeof(*rep));
	rep->count = (uint32_t)done;
	return 0;
}

static int lock_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_lock_request *req)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	(void)srvr;
	(void)smb2;
	(void)req;
	return 0; /* granted: byte-range locks are not enforced */
}

/* The only requests left pending are change notifies: a cancel ends the one it names (cancel itself has no
   reply). It names it by the async id of the interim reply, or by message id when it was sent before that
   reply arrived (MS-SMB2 3.3.5.16). Ending every pending notify instead had Explorer re-ask for them all. */
static int cancel(struct smb2_server *srvr, struct smb2_context *smb2)
{
	struct conn *c = smb2_get_opaque(smb2);
	int by_async = (smb2->hdr.flags & SMB2_FLAGS_ASYNC_COMMAND) != 0;
	int found = 0;

	(void)srvr;
	if (!c)
		return 1;
	for (int i = 0; i < MAX_NOTIFIES; i++) {
		struct notify *n = &c->notifies[i];

		if (!n->used)
			continue;
		if (by_async ? n->async_id != smb2->hdr.async.async_id : n->message_id != smb2->hdr.message_id)
			continue;
		reply_to(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_CANCELLED, n->message_id);
		n->used = 0;
		found = 1;
	}
	if (smbd_trace || !found)
		smbd_log("cancel of %s %llu: %s", by_async ? "async id" : "message",
		         (unsigned long long)(by_async ? smb2->hdr.async.async_id : smb2->hdr.message_id),
		         found ? "notify ended" : "nothing pending by that id");
	/* libsmb2 keeps every request until its reply, and a cancel gets none: without this each one stayed
	   on the wait queue until the client went. Nothing reads the current request after this handler
	   (libsmb2 moves on to the next one). */
	if (smb2->pdu && smb2->pdu->header.command == SMB2_CANCEL) {
		smb2_free_pdu(smb2, smb2->pdu);
		smb2->pdu = NULL;
	}
	return 1;
}

static int echo(struct smb2_server *srvr, struct smb2_context *smb2)
{
	(void)srvr;
	(void)smb2;
	if (smbd_trace)
		smbd_log("echo");
	return 0;
}

/* A DCE/RPC request written to the pipe and its answer read back, in one ioctl (how Windows calls srvsvc).
   libsmb2 copies an ioctl's output only in passthrough mode, so the reply is built here with it on. */
static int pipe_transceive(struct smb2_context *smb2, struct smb2_ioctl_request *req, struct smb2_ioctl_reply *rep)
{
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;
	uint32_t max = req->max_output_response ? req->max_output_response : 4280;
	uint8_t *out;
	size_t got;
	int more = 0, was;
	struct smb2_pdu *pdu;

	if (!h || !h->pipe)
		return reply(smb2, SMB2_IOCTL, SMB2_STATUS_INVALID_HANDLE);
	if (rpc_pipe_write(h->pipe, req->input, req->input_count) < 0)
		return reply(smb2, SMB2_IOCTL, SMB2_STATUS_INVALID_PARAMETER);
	out = malloc(max);
	if (!out)
		return reply(smb2, SMB2_IOCTL, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	got = rpc_pipe_read(h->pipe, out, max, &more);
	if (more)
		smbd_log("pipe answer longer than the %u bytes asked for", max);
	memset(rep, 0, sizeof(*rep));
	rep->ctl_code = req->ctl_code;
	memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);
	rep->output_count = (uint32_t)got;
	rep->output = out;
	was = smb2->passthrough;
	smb2->passthrough = 1;
	pdu = smb2_cmd_ioctl_reply_async(smb2, rep, NULL, NULL);
	smb2->passthrough = was;
	free(out);
	if (!pdu)
		return reply(smb2, SMB2_IOCTL, SMB2_STATUS_INTERNAL_ERROR);
	if (smbd_trace)
		smbd_log("pipe transceive: %u bytes in, %zu out", req->input_count, got);
	/* queued, the request is freed: req is not looked at again */
	smb2_set_pdu_message_id(smb2, pdu, smb2->message_id);
	smb2_queue_pdu(smb2, pdu);
	return 1;
}

static int ioctl_file(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_ioctl_request *req,
                      struct smb2_ioctl_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	(void)srvr;
	(void)rep;
	/* libsmb2 answers FSCTL_VALIDATE_NEGOTIATE_INFO itself before calling us (if it doesn't, the client
	   gives up on that check); copy-chunk, DFS and the rest: not here. */
	if (req->ctl_code == SMB2_FSCTL_PIPE_TRANSCEIVE)
		return pipe_transceive(smb2, req, rep);
	if (req->ctl_code == SMB2_FSCTL_DFS_GET_REFERRALS || req->ctl_code == SMB2_FSCTL_DFS_GET_REFERRALS_EX)
		return reply(smb2, SMB2_IOCTL, SMB2_STATUS_NOT_FOUND);
	smbd_log("ioctl %08x not answered (input %u bytes)", req->ctl_code, req->input_count);
	return reply(smb2, SMB2_IOCTL, SMB2_STATUS_NOT_SUPPORTED);
}

/* ---- directories ---------------------------------------------------------------------------------------- */

/* Windows' wildcards: * and ?, and the DOS ones < > " (MS-FSA 2.1.4.4), case-insensitive (ASCII).
   Iterative, backtracking only to the last star: a pattern of many stars against a long name would take
   exponential time recursively, and the client chooses both. */
static int same_char(char p, char n)
{
	return p == n || (isalpha((unsigned char)p) && tolower((unsigned char)p) == tolower((unsigned char)n));
}

static int match(const char *pat, const char *name)
{
	const char *star = NULL, *resume = NULL;

	while (*name) {
		char p = *pat;

		if (p == '*' || p == '<') {
			star = ++pat;
			resume = name;
			continue;
		}
		if (p && (p == '?' || p == '>' || (p == '"' && *name == '.') || same_char(p, *name))) {
			pat++;
			name++;
			continue;
		}
		if (!star)
			return 0;
		pat = star;
		name = ++resume;
	}
	/* at the end of the name, stars match nothing and > and " match the end */
	while (*pat == '*' || *pat == '<' || *pat == '>' || *pat == '"')
		pat++;
	return !*pat;
}

#define PAD8(n) (((n) + 7) & ~(size_t)7)
#define ENTRY_STRIDE PAD8(sizeof(struct smb2_fileidbothdirectoryinformation))

/* How much room an entry takes on the wire: the fixed part and the name in UTF-16, padded. 0 for a name
   that is not UTF-8, which libsmb2 cannot encode (it would then send no reply at all). */
static size_t wire_size(uint8_t info_class, const char *name)
{
	struct smb2_utf16 *u = smb2_utf8_to_utf16(name);
	size_t n;

	if (!u)
		return 0;
	n = (size_t)u->len * 2;
	free(u);
	return PAD8((info_class == SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION ? 80 : 104) + n);
}

/* A handle's path as the client names it: within the share, with backslashes ("\\" for the root). A
   byte that keeps it from being UTF-8 becomes '_', since libsmb2 could not encode the reply otherwise. */
static void share_relative(const struct handle *h, char *out, size_t size)
{
	const char *root = h->share >= 0 && h->share < smbd_share_count ? smbd_shares[h->share].root : "";
	const char *rel = strncmp(h->path, root, strlen(root)) == 0 ? h->path + strlen(root) : h->path;
	size_t n = 0;
	struct smb2_utf16 *u;

	if (*rel != '/')
		out[n++] = '\\';
	for (; *rel && n + 1 < size; rel++)
		out[n++] = *rel == '/' ? '\\' : *rel;
	out[n] = 0;
	u = smb2_utf8_to_utf16(out);
	if (u) {
		free(u);
		return;
	}
	for (char *c = out; *c; c++) {
		if ((unsigned char)*c >= 0x80)
			*c = '_';
	}
}

static void fill_entry(struct smb2_fileidbothdirectoryinformation *e, const struct stat *st, const char *name,
                       uint32_t index)
{
	memset(e, 0, sizeof(*e));
	e->file_index = index;
	e->creation_time = tv_of(BTIME(st).tv_sec, BTIME(st).tv_nsec);
	e->last_access_time = tv_of(ATIME(st).tv_sec, ATIME(st).tv_nsec);
	e->last_write_time = tv_of(MTIME(st).tv_sec, MTIME(st).tv_nsec);
	e->change_time = tv_of(CTIME(st).tv_sec, CTIME(st).tv_nsec);
	e->end_of_file = S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_size;
	e->allocation_size = allocation_of(st);
	e->file_attributes = attributes_of(st, name);
	e->file_id = (uint64_t)st->st_ino;
	e->name = name;
}

static int query_directory(struct smb2_server *srvr, struct smb2_context *smb2,
                           struct smb2_query_directory_request *req, struct smb2_query_directory_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;
	size_t room = req->output_buffer_length, used = 0;
	int max_entries = (req->flags & SMB2_RETURN_SINGLE_ENTRY) ? 1 : 512;
	int count = 0, first_call;
	uint8_t *out;

	(void)srvr;
	if (!h)
		return reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_FILE_CLOSED);
	if (!h->is_dir)
		return reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_INVALID_PARAMETER);
	if (req->file_information_class != SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION &&
	    req->file_information_class != SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION) {
		smbd_log("listing: class %u not answered", req->file_information_class);
		return reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_INVALID_INFO_CLASS);
	}

	if ((req->flags & (SMB2_RESTART_SCANS | SMB2_REOPEN)) || !h->dir) {
		if (h->dir)
			closedir(h->dir);
		h->dir = opendir(h->path);
		if (!h->dir)
			return reply(smb2, SMB2_QUERY_DIRECTORY, status_of(errno));
		h->listed_dots = 0;
		h->listing_started = 0;
		h->has_pushback = 0;
		snprintf(h->pattern, sizeof(h->pattern), "%s", req->name && req->name[0] ? req->name : "*");
	}
	first_call = !h->listing_started;
	h->listing_started = 1;

	out = calloc((size_t)max_entries, ENTRY_STRIDE);
	c->names = calloc((size_t)max_entries, sizeof(*c->names));
	if (!out || !c->names) {
		free(out);
		return reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	}
	while (count < max_entries) {
		char name[256];
		char full[PATH_MAX];
		struct stat st;
		size_t need;

		if (h->has_pushback) {
			snprintf(name, sizeof(name), "%s", h->pushback_name);
			h->has_pushback = 0;
		} else if (h->listed_dots < 2) {
			snprintf(name, sizeof(name), "%s", h->listed_dots ? ".." : ".");
			h->listed_dots++;
		} else {
			struct dirent *d = readdir(h->dir);

			if (!d)
				break;
			if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
				continue;
			snprintf(name, sizeof(name), "%s", d->d_name);
		}
		if (!match(h->pattern, name))
			continue;
		snprintf(full, sizeof(full), "%s/%s", h->path, name);
		if (stat(full, &st) < 0 && lstat(full, &st) < 0)
			continue;
		need = wire_size(req->file_information_class, name);
		if (!need) {
			smbd_log("listing %s: a name that is not UTF-8 left out", h->path);
			continue;
		}
		if (used + need > room) {
			/* send it next time */
			snprintf(h->pushback_name, sizeof(h->pushback_name), "%s", name);
			h->has_pushback = 1;
			if (!count) {
				free(out);
				return reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_INFO_LENGTH_MISMATCH);
			}
			break;
		}
		snprintf(c->names[count], sizeof(c->names[count]), "%s", name);
		fill_entry((struct smb2_fileidbothdirectoryinformation *)(out + (size_t)count * ENTRY_STRIDE), &st,
		           c->names[count], (uint32_t)count);
		used += need;
		count++;
	}
	if (!count) {
		free(out);
		/* nothing matched at all is "no such file" (how a client checks a name exists); the end of a
		   listing is "no more files" */
		return reply(smb2, SMB2_QUERY_DIRECTORY,
		             first_call ? SMB2_STATUS_NO_SUCH_FILE : SMB2_STATUS_NO_MORE_FILES);
	}
	if (smbd_trace)
		smbd_log("listing %s (%s, class %u): %d entries", h->path, h->pattern, req->file_information_class, count);
	c->scratch = out;
	memset(rep, 0, sizeof(*rep));
	rep->output_buffer = out;
	rep->output_buffer_length = (uint32_t)((size_t)count * ENTRY_STRIDE);
	return 0;
}

/* No change notifications are sent; like a Windows server that has none, the request is left pending (an
   interim STATUS_PENDING) until the client cancels it or closes the folder. Answering NOT_SUPPORTED made
   Explorer refuse to open the share ("The specified server cannot perform the requested operation"). */
static int change_notify(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_change_notify_request *req,
                         struct smb2_change_notify_reply *rep)
{
	struct conn *c;
	struct handle *h;
	int slot = -1;

	(void)srvr;
	(void)rep;
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	c = conn_of(smb2);
	h = c ? find_handle(c, req->file_id) : NULL;
	if (!h)
		return reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_FILE_CLOSED);
	if (!h->is_dir)
		return reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_INVALID_PARAMETER);
	for (int i = 0; i < MAX_NOTIFIES; i++) {
		if (!c->notifies[i].used) {
			slot = i;
			break;
		}
	}
	if (slot < 0)
		return reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	{
		struct notify *n = &c->notifies[slot];
		struct smb2_pdu *waiting;

		n->used = 1;
		n->message_id = smb2->message_id;
		n->async_id = 0;
		n->handle = (int)(h - c->handles);
		reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_PENDING);
		/* libsmb2 gave the interim reply an async id and kept the request waiting, marked with it */
		waiting = smb2_find_pdu(smb2, n->message_id);
		if (waiting && (waiting->header.flags & SMB2_FLAGS_ASYNC_COMMAND))
			n->async_id = waiting->header.async.async_id;
		if (smbd_trace)
			smbd_log("change notify on %s left pending (message %llu, async id %llu)", h->path,
			         (unsigned long long)n->message_id, (unsigned long long)n->async_id);
	}
	return 1;
}

/* ---- information ---------------------------------------------------------------------------------------- */

static void basic_of(struct smb2_file_basic_info *b, const struct stat *st, const char *path)
{
	b->creation_time = tv_of(BTIME(st).tv_sec, BTIME(st).tv_nsec);
	b->last_access_time = tv_of(ATIME(st).tv_sec, ATIME(st).tv_nsec);
	b->last_write_time = tv_of(MTIME(st).tv_sec, MTIME(st).tv_nsec);
	b->change_time = tv_of(CTIME(st).tv_sec, CTIME(st).tv_nsec);
	b->file_attributes = attributes_of(st, path);
}

static void standard_of(struct smb2_file_standard_info *s, const struct stat *st, int delete_pending)
{
	s->allocation_size = allocation_of(st);
	s->end_of_file = S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_size;
	s->number_of_links = (uint32_t)st->st_nlink;
	s->delete_pending = (uint8_t)delete_pending;
	s->directory = S_ISDIR(st->st_mode) ? 1 : 0;
}

static int query_info(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_query_info_request *req,
                      struct smb2_query_info_reply *rep)
{
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	struct conn *c = conn_of(smb2);
	struct handle *h = c ? find_handle(c, req->file_id) : NULL;
	struct stat st;
	void *out = NULL;
	size_t len = 0;

	(void)srvr;
	if (!h)
		return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_FILE_CLOSED);
	if (h->pipe) {
		struct smb2_file_standard_info *si;

		if (req->info_type != SMB2_0_INFO_FILE || req->file_info_class != SMB2_FILE_STANDARD_INFORMATION)
			return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_NOT_SUPPORTED);
		si = calloc(1, sizeof(*si));
		if (!si)
			return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_INSUFFICIENT_RESOURCES);
		si->number_of_links = 1;
		c->scratch = si;
		memset(rep, 0, sizeof(*rep));
		rep->output_buffer = si;
		rep->output_buffer_length = sizeof(*si);
		return 0;
	}
	if ((h->fd >= 0 ? fstat(h->fd, &st) : stat(h->path, &st)) < 0)
		return reply(smb2, SMB2_QUERY_INFO, status_of(errno));

	if (req->info_type == SMB2_0_INFO_FILE) {
		switch (req->file_info_class) {
		case SMB2_FILE_BASIC_INFORMATION: {
			struct smb2_file_basic_info *b = calloc(1, sizeof(*b));
			if (b)
				basic_of(b, &st, h->path);
			out = b;
			len = sizeof(*b);
			break;
		}
		case SMB2_FILE_STANDARD_INFORMATION: {
			struct smb2_file_standard_info *s = calloc(1, sizeof(*s));
			if (s)
				standard_of(s, &st, h->delete_on_close);
			out = s;
			len = sizeof(*s);
			break;
		}
		case SMB2_FILE_NETWORK_OPEN_INFORMATION: {
			struct smb2_file_network_open_info *n = calloc(1, sizeof(*n));
			if (n) {
				n->creation_time = tv_of(BTIME(&st).tv_sec, BTIME(&st).tv_nsec);
				n->last_access_time = tv_of(ATIME(&st).tv_sec, ATIME(&st).tv_nsec);
				n->last_write_time = tv_of(MTIME(&st).tv_sec, MTIME(&st).tv_nsec);
				n->change_time = tv_of(CTIME(&st).tv_sec, CTIME(&st).tv_nsec);
				n->allocation_size = allocation_of(&st);
				n->end_of_file = S_ISDIR(st.st_mode) ? 0 : (uint64_t)st.st_size;
				n->file_attributes = attributes_of(&st, h->path);
			}
			out = n;
			len = sizeof(*n);
			break;
		}
		case SMB2_FILE_ALL_INFORMATION: {
			/* the name is the path within the share, "\dir\file" (MS-FSCC 2.4.2), kept after the struct
			   so it lives as long as the reply buffer */
			struct smb2_file_all_info *a = calloc(1, sizeof(*a) + PATH_MAX);
			if (a) {
				char *name = (char *)(a + 1);

				basic_of(&a->basic, &st, h->path);
				standard_of(&a->standard, &st, h->delete_on_close);
				a->index_number = (uint64_t)st.st_ino;
				a->access_flags = 0x001F01FF;
				share_relative(h, name, PATH_MAX);
				a->name = (const uint8_t *)name;
			}
			out = a;
			len = sizeof(*a);
			break;
		}
		case SMB2_FILE_POSITION_INFORMATION: {
			struct smb2_file_position_info *p = calloc(1, sizeof(*p));
			out = p;
			len = sizeof(*p);
			break;
		}
		default:
			smbd_log("query info: file class %u not answered", req->file_info_class);
			return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_NOT_SUPPORTED);
		}
	} else if (req->info_type == SMB2_0_INFO_FILESYSTEM) {
		struct statvfs vfs;
		int have_vfs = statvfs(h->path, &vfs) == 0;
		uint64_t frsize = have_vfs && vfs.f_frsize ? vfs.f_frsize : 4096;

		switch (req->file_info_class) {
		case SMB2_FILE_FS_SIZE_INFORMATION: {
			struct smb2_file_fs_size_info *s = calloc(1, sizeof(*s));
			if (s) {
				s->total_allocation_units = have_vfs ? vfs.f_blocks : 0;
				s->available_allocation_units = have_vfs ? vfs.f_bavail : 0;
				s->sectors_per_allocation_unit = (uint32_t)(frsize / 512);
				s->bytes_per_sector = 512;
			}
			out = s;
			len = sizeof(*s);
			break;
		}
		case SMB2_FILE_FS_FULL_SIZE_INFORMATION: {
			struct smb2_file_fs_full_size_info *s = calloc(1, sizeof(*s));
			if (s) {
				s->total_allocation_units = have_vfs ? vfs.f_blocks : 0;
				s->caller_available_allocation_units = have_vfs ? vfs.f_bavail : 0;
				s->actual_available_allocation_units = have_vfs ? vfs.f_bfree : 0;
				s->sectors_per_allocation_unit = (uint32_t)(frsize / 512);
				s->bytes_per_sector = 512;
			}
			out = s;
			len = sizeof(*s);
			break;
		}
		case SMB2_FILE_FS_ATTRIBUTE_INFORMATION: {
			struct smb2_file_fs_attribute_info *a = calloc(1, sizeof(*a));
			if (a) {
				/* case-preserved names, Unicode names */
				a->filesystem_attributes = 0x00000002 | 0x00000004;
				a->maximum_component_name_length = 255;
				a->filesystem_name = (const uint8_t *)"NTFS";
			}
			out = a;
			len = sizeof(*a);
			break;
		}
		case SMB2_FILE_FS_VOLUME_INFORMATION: {
			struct smb2_file_fs_volume_info *v = calloc(1, sizeof(*v));
			if (v) {
				v->volume_serial_number = 0x50533500 + (uint32_t)h->share;
				v->volume_label = (const uint8_t *)smbd_shares[h->share].name;
			}
			out = v;
			len = sizeof(*v);
			break;
		}
		case SMB2_FILE_FS_DEVICE_INFORMATION: {
			struct smb2_file_fs_device_info *d = calloc(1, sizeof(*d));
			if (d)
				d->device_type = 0x00000007; /* FILE_DEVICE_DISK */
			out = d;
			len = sizeof(*d);
			break;
		}
		case SMB2_FILE_FS_SECTOR_SIZE_INFORMATION: {
			struct smb2_file_fs_sector_size_info *s = calloc(1, sizeof(*s));
			if (s) {
				s->logical_bytes_per_sector = 512;
				s->physical_bytes_per_sector_for_atomicity = 512;
				s->physical_bytes_per_sector_for_performance = 512;
				s->file_system_effective_physical_bytes_per_sector_for_atomicity = 512;
			}
			out = s;
			len = sizeof(*s);
			break;
		}
		default:
			smbd_log("query info: file system class %u not answered", req->file_info_class);
			return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_NOT_SUPPORTED);
		}
	} else {
		/* security descriptors and quotas: not kept here */
		smbd_log("query info: type %u class %u not answered", req->info_type, req->file_info_class);
		return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_NOT_SUPPORTED);
	}
	if (!out)
		return reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_INSUFFICIENT_RESOURCES);
	if (smbd_trace)
		smbd_log("query info %s: type %u class %u answered", h->path, req->info_type, req->file_info_class);
	c->scratch = out;
	memset(rep, 0, sizeof(*rep));
	rep->output_buffer = out;
	rep->output_buffer_length = (uint32_t)len;
	return 0;
}

/* Little-endian fields of a raw set-info buffer (libsmb2 hands it over undecoded). */
static uint64_t le64(const uint8_t *p)
{
	uint64_t v = 0;

	for (int i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* An NT time to a timeval; 0 and -1 mean "leave it" (MS-FSCC 2.4.7). */
static int nt_to_timeval(uint64_t nt, struct timeval *tv)
{
	if (nt == 0 || nt == UINT64_MAX || nt < 116444736000000000ull)
		return 0;
	nt -= 116444736000000000ull;
	tv->tv_sec = (time_t)(nt / 10000000ull);
	tv->tv_usec = (long)(nt % 10000000ull / 10);
	return 1;
}

static int set_info(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_set_info_request *req)
{
	struct conn *c;
	struct handle *h;
	const uint8_t *in;
	uint32_t len;

	(void)srvr;
	if (!req)
		return 1; /* a request cancelled while the connection is torn down */
	if (smbd_trace)
		smbd_log("set info: type %u class %u, %u bytes", req->info_type, req->file_info_class, req->buffer_length);
	c = conn_of(smb2);
	h = c ? find_handle(c, req->file_id) : NULL;
	in = req->input_data;
	len = req->buffer_length;
	if (!h)
		return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_FILE_CLOSED);
	/* a pipe has no times, size or name to change (and no share root to rename within) */
	if (h->pipe || req->info_type != SMB2_0_INFO_FILE)
		return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_NOT_SUPPORTED);
	switch (req->file_info_class) {
	case SMB2_FILE_BASIC_INFORMATION: { /* creation, access, write, change times, attributes */
		struct timeval tv[2];
		struct stat st;
		int a, w;

		if (!in || len < 36)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INFO_LENGTH_MISMATCH);
		if (stat(h->path, &st) < 0)
			return reply(smb2, SMB2_SET_INFO, status_of(errno));
		tv[0].tv_sec = ATIME(&st).tv_sec;
		tv[0].tv_usec = ATIME(&st).tv_nsec / 1000;
		tv[1].tv_sec = MTIME(&st).tv_sec;
		tv[1].tv_usec = MTIME(&st).tv_nsec / 1000;
		a = nt_to_timeval(le64(in + 8), &tv[0]);
		w = nt_to_timeval(le64(in + 16), &tv[1]);
		if ((a || w) && utimes(h->path, tv) < 0)
			return reply(smb2, SMB2_SET_INFO, status_of(errno));
		return 0;
	}
	case SMB2_FILE_END_OF_FILE_INFORMATION:
	case SMB2_FILE_ALLOCATION_INFORMATION: {
		uint64_t size;
		struct stat st;

		if (!in || len < 8)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INFO_LENGTH_MISMATCH);
		if (h->fd < 0)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INVALID_PARAMETER);
		size = le64(in);
		/* an allocation size only ever shrinks a file to it; growing is just a reservation */
		if (req->file_info_class == SMB2_FILE_ALLOCATION_INFORMATION &&
		    (fstat(h->fd, &st) < 0 || size >= (uint64_t)st.st_size))
			return 0;
		if (ftruncate(h->fd, (off_t)size) < 0)
			return reply(smb2, SMB2_SET_INFO, status_of(errno));
		return 0;
	}
	case SMB2_FILE_DISPOSITION_INFORMATION: {
		if (!in || len < 1)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INFO_LENGTH_MISMATCH);
		if (in[0] && h->is_dir) {
			/* refused now, as Windows does, rather than failing silently at close */
			DIR *dir = opendir(h->path);
			struct dirent *e;
			int empty = 1;

			while (dir && (e = readdir(dir))) {
				if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
					empty = 0;
			}
			if (dir)
				closedir(dir);
			if (!empty)
				return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_DIRECTORY_NOT_EMPTY);
		}
		h->delete_on_close = in[0] ? 1 : 0;
		return 0;
	}
	case SMB2_FILE_RENAME_INFORMATION: { /* ReplaceIfExists, 7 reserved, RootDirectory, length, UTF-16 name */
		char to[PATH_MAX];
		const char *name;
		uint32_t name_len;
		struct stat st;
		int replace;

		if (!in || len < 20)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INFO_LENGTH_MISMATCH);
		replace = in[0] != 0;
		name_len = le32(in + 16);
		if (name_len > len - 20 || name_len % 2)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INFO_LENGTH_MISMATCH);
		{
			/* the UTF-16 name may sit at an odd address in the buffer */
			uint16_t *u = malloc(name_len ? name_len : 2);

			if (!u)
				return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_INSUFFICIENT_RESOURCES);
			memcpy(u, in + 20, name_len);
			name = smb2_utf16_to_utf8(u, name_len / 2);
			free(u);
		}
		if (!name || join_path(h->share, name, to, sizeof(to))) {
			free((void *)name);
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_OBJECT_NAME_INVALID);
		}
		free((void *)name);
		if (!replace && stat(to, &st) == 0)
			return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_OBJECT_NAME_COLLISION);
		if (rename(h->path, to) < 0)
			return reply(smb2, SMB2_SET_INFO, status_of(errno));
		smbd_log("renamed %s -> %s", h->path, to);
		snprintf(h->path, sizeof(h->path), "%s", to);
		return 0;
	}
	default:
		/* refused, so a client falls back to a class above (Windows does for the -Ex ones); a silent
		   success would let it think a delete or rename happened */
		smbd_log("set info: file class %u not answered", req->file_info_class);
		return reply(smb2, SMB2_SET_INFO, SMB2_STATUS_NOT_SUPPORTED);
	}
}

struct smb2_server_request_handlers smbd_handlers = {
	.destruction_event = destruction,
	.authorize_user = authorize,
	.session_established = session_up,
	.logoff_cmd = logoff,
	.tree_connect_cmd = tree_connect,
	.tree_disconnect_cmd = tree_disconnect,
	.create_cmd = create,
	.close_cmd = close_file,
	.flush_cmd = flush_file,
	.read_cmd = read_file,
	.write_cmd = write_file,
	.lock_cmd = lock_file,
	.ioctl_cmd = ioctl_file,
	.cancel_cmd = cancel,
	.echo_cmd = echo,
	.query_directory_cmd = query_directory,
	.change_notify_cmd = change_notify,
	.query_info_cmd = query_info,
	.set_info_cmd = set_info,
};
