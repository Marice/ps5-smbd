/* Host tests for what the code review of 2026-10-30 found, run against `make host`:
 *   - a rename on the srvsvc pipe is refused (it read smbd_shares[-1]);
 *   - a failed create in a compound leaves the requests after it without a file (they closed an earlier
 *     handle);
 *   - a pattern of many stars against a long name answers at once (it backtracked exponentially);
 *   - a name that is not UTF-8 is left out of a listing (the listing got no reply at all);
 *   - an unknown set-info class is refused (it reported success);
 *   - FileAllInformation names the path within the share, also a long one.
 * usage: review [server:port] [the data share's folder on this computer] */
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#include "libsmb2-private.h"

#define STATUS_NONE 1u
#define STATUS_NOT_SUPPORTED 0xC00000BBu
#define STATUS_FILE_CLOSED 0xC0000128u
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034u
#define STATUS_NO_SUCH_FILE 0xC000000Fu

/* what a reply said, copied in the callback: libsmb2 frees the reply's data when the callback returns */
struct result {
	uint32_t status;
	smb2_file_id fid;  /* create */
	int entries;       /* query directory */
	char name[4096];   /* FileAllInformation */
	int kind;
};

enum { KIND_PLAIN, KIND_CREATE, KIND_LIST, KIND_ALL };

static int failures;

static void result_cb(struct smb2_context *smb2, int status, void *data, void *priv)
{
	struct result *r = priv;

	(void)smb2;
	r->status = (uint32_t)status;
	if (status || !data)
		return;
	if (r->kind == KIND_CREATE) {
		memcpy(r->fid, ((struct smb2_create_reply *)data)->file_id, SMB2_FD_SIZE);
	} else if (r->kind == KIND_LIST) {
		const struct smb2_query_directory_reply *rep = data;
		uint32_t off = 0;

		/* walk NextEntryOffset */
		for (;;) {
			uint32_t next;

			if (off + 4 > rep->output_buffer_length)
				break;
			memcpy(&next, rep->output_buffer + off, 4);
			r->entries++;
			if (!next)
				break;
			off += next;
		}
	} else if (r->kind == KIND_ALL) {
		const struct smb2_file_all_info *a = ((struct smb2_query_info_reply *)data)->output_buffer;

		snprintf(r->name, sizeof(r->name), "%s", a && a->name ? (const char *)a->name : "(none)");
	}
}

static void check(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	failures += !ok;
}

/* runs the queue until every given result has a status, or 5 s pass */
static void wait_for(struct smb2_context *smb2, struct result *a, struct result *b)
{
	time_t until = time(NULL) + 5;

	while (time(NULL) < until && (a->status == STATUS_NONE || (b && b->status == STATUS_NONE))) {
		struct pollfd p = {smb2_get_fd(smb2), (short)smb2_which_events(smb2), 0};

		if (poll(&p, 1, 100) > 0 && smb2_service(smb2, p.revents) < 0) {
			printf("FAIL service: %s\n", smb2_get_error(smb2));
			failures++;
			return;
		}
	}
}

static struct smb2_context *connect_to(const char *server, const char *share)
{
	struct smb2_context *smb2 = smb2_init_context();

	smb2_set_user(smb2, "ps5");
	smb2_set_password(smb2, "ps5");
	smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	if (smb2_connect_share(smb2, server, share, "ps5") < 0) {
		printf("FAIL connect %s: %s\n", share, smb2_get_error(smb2));
		exit(1);
	}
	return smb2;
}

/* a raw set-info (libsmb2 encodes only the classes it knows, unless in passthrough) */
static uint32_t set_info_raw(struct smb2_context *smb2, const smb2_file_id fid, uint8_t info_class,
                             uint8_t *buf, uint32_t len)
{
	struct smb2_set_info_request req;
	struct result r = {.status = STATUS_NONE};
	struct smb2_pdu *pdu;

	memset(&req, 0, sizeof(req));
	req.info_type = SMB2_0_INFO_FILE;
	req.file_info_class = info_class;
	req.buffer_length = len;
	req.input_data = buf;
	memcpy(req.file_id, fid, SMB2_FD_SIZE);
	smb2->passthrough = 1;
	pdu = smb2_cmd_set_info_async(smb2, &req, result_cb, &r);
	smb2->passthrough = 0;
	if (!pdu)
		return 0;
	smb2_queue_pdu(smb2, pdu);
	wait_for(smb2, &r, NULL);
	return r.status;
}

/* FileRenameInformation as Windows sends it: replace flag, reserved, root dir, length, UTF-16 name */
static uint32_t rename_raw(struct smb2_context *smb2, const smb2_file_id fid, const char *ascii)
{
	uint8_t buf[256];
	uint32_t n = (uint32_t)strlen(ascii);

	memset(buf, 0, sizeof(buf));
	buf[16] = (uint8_t)(n * 2);
	for (uint32_t i = 0; i < n; i++)
		buf[20 + i * 2] = (uint8_t)ascii[i];
	return set_info_raw(smb2, fid, SMB2_FILE_RENAME_INFORMATION, buf, 20 + n * 2);
}

static uint32_t create_raw(struct smb2_context *smb2, const char *name, uint32_t options, smb2_file_id fid)
{
	struct smb2_create_request req;
	struct result r = {.status = STATUS_NONE};
	struct smb2_pdu *pdu;

	memset(&req, 0, sizeof(req));
	req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	req.desired_access = SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_READ_DATA | SMB2_DELETE;
	req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
	req.create_disposition = SMB2_FILE_OPEN;
	req.create_options = options;
	req.name = name;
	r.kind = KIND_CREATE;
	pdu = smb2_cmd_create_async(smb2, &req, result_cb, &r);
	smb2_queue_pdu(smb2, pdu);
	wait_for(smb2, &r, NULL);
	if (r.status == 0)
		memcpy(fid, r.fid, SMB2_FD_SIZE);
	return r.status;
}

static void test_pipe_rename(const char *server)
{
	struct smb2_context *smb2 = connect_to(server, "IPC$");
	smb2_file_id fid;

	check("srvsvc opens on IPC$", create_raw(smb2, "srvsvc", 0, fid) == 0);
	check("a rename on the pipe is refused", rename_raw(smb2, fid, "elsewhere") == STATUS_NOT_SUPPORTED);
	check("the server still answers after it", smb2_echo(smb2) == 0);
	smb2_disconnect_share(smb2);
	smb2_destroy_context(smb2);
}

static void test_failed_compound(struct smb2_context *smb2)
{
	struct smb2_create_request creq;
	struct smb2_close_request close_req;
	struct result rc = {.status = STATUS_NONE}, rx = {.status = STATUS_NONE};
	struct smb2_pdu *create, *close;
	smb2_file_id held;
	struct smb2_stat_64 st;

	/* a folder held open, as Explorer holds the one it shows */
	check("the folder opens", create_raw(smb2, "review", SMB2_FILE_DIRECTORY_FILE, held) == 0);
	memset(&creq, 0, sizeof(creq));
	creq.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	creq.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	creq.desired_access = SMB2_FILE_READ_ATTRIBUTES;
	creq.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
	creq.create_disposition = SMB2_FILE_OPEN;
	creq.name = "review\\desktop.ini";
	create = smb2_cmd_create_async(smb2, &creq, result_cb, &rc);
	memset(&close_req, 0, sizeof(close_req));
	memcpy(close_req.file_id, compound_file_id, SMB2_FD_SIZE);
	close = smb2_cmd_close_async(smb2, &close_req, result_cb, &rx);
	smb2_add_compound_pdu(smb2, create, close);
	smb2_queue_pdu(smb2, create);
	wait_for(smb2, &rc, &rx);
	check("the create of a missing file fails", rc.status == STATUS_OBJECT_NAME_NOT_FOUND);
	check("the related close after it has no file", rx.status == STATUS_FILE_CLOSED);
	/* the held folder must still be open: a query on it by its id */
	{
		struct smb2_query_info_request q;
		struct result rq = {.status = STATUS_NONE};
		struct smb2_pdu *pdu;

		memset(&q, 0, sizeof(q));
		q.info_type = SMB2_0_INFO_FILE;
		q.file_info_class = SMB2_FILE_BASIC_INFORMATION;
		q.output_buffer_length = 65535;
		memcpy(q.file_id, held, SMB2_FD_SIZE);
		pdu = smb2_cmd_query_info_async(smb2, &q, result_cb, &rq);
		smb2_queue_pdu(smb2, pdu);
		wait_for(smb2, &rq, NULL);
		check("the folder held open is still open", rq.status == 0);
	}
	(void)st;
}

static uint32_t list_raw(struct smb2_context *smb2, const smb2_file_id dir, const char *pattern, int *entries)
{
	struct smb2_query_directory_request q;
	struct result r = {.status = STATUS_NONE};
	struct smb2_pdu *pdu;

	memset(&q, 0, sizeof(q));
	q.file_information_class = SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION;
	q.flags = SMB2_RESTART_SCANS;
	memcpy(q.file_id, dir, SMB2_FD_SIZE);
	q.name = pattern;
	q.output_buffer_length = 65535;
	r.kind = KIND_LIST;
	pdu = smb2_cmd_query_directory_async(smb2, &q, result_cb, &r);
	smb2_queue_pdu(smb2, pdu);
	wait_for(smb2, &r, NULL);
	*entries = r.entries;
	return r.status;
}

static void test_listing(struct smb2_context *smb2, const char *dir)
{
	char path[4096], name[300], pattern[300];
	smb2_file_id fid;
	struct timespec t0, t1;
	uint32_t status;
	int entries = 0;
	double took;

	/* made on this computer: a 250-character name and one that is not UTF-8 (Latin-1 e acute) */
	memset(name, 'a', 250);
	name[250] = 0;
	snprintf(path, sizeof(path), "%s/review/%s", dir, name);
	close(open(path, O_CREAT | O_WRONLY, 0644));
	snprintf(path, sizeof(path), "%s/review/caf\xe9.txt", dir);
	close(open(path, O_CREAT | O_WRONLY, 0644));
	snprintf(path, sizeof(path), "%s/review/plain.txt", dir);
	close(open(path, O_CREAT | O_WRONLY, 0644));

	check("the folder opens for listing", create_raw(smb2, "review", SMB2_FILE_DIRECTORY_FILE, fid) == 0);
	for (int k = 0; k < 120; k++) {
		pattern[2 * k] = '*';
		pattern[2 * k + 1] = 'a';
	}
	strcpy(pattern + 240, "*b");
	clock_gettime(CLOCK_MONOTONIC, &t0);
	status = list_raw(smb2, fid, pattern, &entries);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	took = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	printf("     many-star pattern: status %08x in %.3f s\n", status, took);
	check("a many-star pattern is answered at once", status == STATUS_NO_SUCH_FILE && took < 1.0);

	status = list_raw(smb2, fid, "*", &entries);
	/* ., .., the long name, plain.txt and whatever else the folder holds; not the Latin-1 name */
	check("a folder with a non-UTF-8 name still lists", status == 0 && entries >= 4);
	status = list_raw(smb2, fid, "caf*", &entries);
	check("the non-UTF-8 name is left out", status == STATUS_NO_SUCH_FILE);
	snprintf(path, sizeof(path), "%s/review/caf\xe9.txt", dir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/review/%s", dir, name);
	unlink(path);
}

static void test_set_info_and_name(struct smb2_context *smb2, const char *dir)
{
	char path[4096];
	smb2_file_id fid;
	uint8_t ex[8] = {1}; /* FileDispositionInformationEx: delete */
	struct stat st;

	snprintf(path, sizeof(path), "%s/review/plain.txt", dir);
	check("a file opens", create_raw(smb2, "review\\plain.txt", 0, fid) == 0);
	check("FileDispositionInformationEx is refused", set_info_raw(smb2, fid, 64, ex, sizeof(ex)) == STATUS_NOT_SUPPORTED);
	{
		struct smb2_query_info_request q;
		struct result rq = {.status = STATUS_NONE};
		struct smb2_pdu *pdu;

		memset(&q, 0, sizeof(q));
		q.info_type = SMB2_0_INFO_FILE;
		q.file_info_class = SMB2_FILE_ALL_INFORMATION;
		q.output_buffer_length = 65535;
		memcpy(q.file_id, fid, SMB2_FD_SIZE);
		rq.kind = KIND_ALL;
		pdu = smb2_cmd_query_info_async(smb2, &q, result_cb, &rq);
		smb2_queue_pdu(smb2, pdu);
		wait_for(smb2, &rq, NULL);
		if (rq.status == 0) {
			printf("     FileAllInformation name \"%s\"\n", rq.name);
			check("FileAllInformation names the path in the share", !strcmp(rq.name, "\\review\\plain.txt"));
		} else {
			check("FileAllInformation answered", 0);
		}
	}
	{
		struct smb2_close_request c;
		struct result rx = {.status = STATUS_NONE};
		struct smb2_pdu *pdu;

		memset(&c, 0, sizeof(c));
		memcpy(c.file_id, fid, SMB2_FD_SIZE);
		pdu = smb2_cmd_close_async(smb2, &c, result_cb, &rx);
		smb2_queue_pdu(smb2, pdu);
		wait_for(smb2, &rx, NULL);
	}
	check("the file is still there after closing", stat(path, &st) == 0);
	unlink(path);
}

/* FileAllInformation for a file deep in the share: the path in UTF-16 is longer than the 1 KB libsmb2
   adds to the reply's length, so the length has to count it (the reply was never sent). */
static void test_long_path(struct smb2_context *smb2, const char *dir)
{
	char local[4096], remote[4096], part[101];
	size_t n = 0;
	smb2_file_id fid;
	struct result rq = {.status = STATUS_NONE};
	struct smb2_query_info_request q;
	struct smb2_pdu *pdu;

	memset(part, 'd', 100);
	part[100] = 0;
	snprintf(local, sizeof(local), "%s/review", dir);
	n = (size_t)snprintf(remote, sizeof(remote), "review");
	for (int i = 0; i < 6; i++) {
		strcat(local, "/");
		strcat(local, part);
		mkdir(local, 0755);
		n += (size_t)snprintf(remote + n, sizeof(remote) - n, "\\%s", part);
	}
	strcat(local, "/deep.txt");
	close(open(local, O_CREAT | O_WRONLY, 0644));
	snprintf(remote + n, sizeof(remote) - n, "\\deep.txt");
	check("a file 600+ characters deep opens", create_raw(smb2, remote, 0, fid) == 0);
	memset(&q, 0, sizeof(q));
	q.info_type = SMB2_0_INFO_FILE;
	q.file_info_class = SMB2_FILE_ALL_INFORMATION;
	q.output_buffer_length = 65535;
	memcpy(q.file_id, fid, SMB2_FD_SIZE);
	rq.kind = KIND_ALL;
	pdu = smb2_cmd_query_info_async(smb2, &q, result_cb, &rq);
	smb2_queue_pdu(smb2, pdu);
	wait_for(smb2, &rq, NULL);
	printf("     FileAllInformation for it: status %08x, name of %zu characters\n", rq.status, strlen(rq.name));
	check("FileAllInformation answers for it with the whole path",
	      rq.status == 0 && strlen(rq.name) == strlen(remote) + 1);
	unlink(local);
	for (int i = 0; i < 6; i++) {
		*strrchr(local, '/') = 0;
		rmdir(local);
	}
}

int main(int argc, char **argv)
{
	const char *server = argc > 1 ? argv[1] : "127.0.0.1:4450";
	const char *dir = argc > 2 ? argv[2] : "build/data";
	struct smb2_context *smb2;
	char path[4096];

	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(path, sizeof(path), "%s/review", dir);
	mkdir(path, 0755);
	test_pipe_rename(server);
	smb2 = connect_to(server, "data");
	test_failed_compound(smb2);
	test_listing(smb2, dir);
	test_set_info_and_name(smb2, dir);
	test_long_path(smb2, dir);
	smb2_disconnect_share(smb2);
	smb2_destroy_context(smb2);
	rmdir(path);
	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
