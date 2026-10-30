/* A host test of ps5-smbd's change notifies: two left pending, a cancel of one ends only that one (as
   Explorer cancels them one by one), and closing the other folder ends that one. Run against `make host`. */
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>

#include "libsmb2-private.h"

#define STATUS_NONE 1u
#define STATUS_CANCELLED 0xC0000120u
#define STATUS_NOTIFY_CLEANUP 0x0000010Bu

static uint32_t status_a = STATUS_NONE, status_b = STATUS_NONE;
static int failures;

static void notify_cb(struct smb2_context *smb2, int status, void *data, void *priv)
{
	(void)smb2;
	(void)data;
	*(uint32_t *)priv = (uint32_t)status;
}

static void close_cb(struct smb2_context *smb2, int status, void *data, void *priv)
{
	(void)smb2;
	(void)status;
	(void)data;
	(void)priv;
}

static void serve(struct smb2_context *smb2, int ms)
{
	struct timespec start, now;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		struct pollfd p = {smb2_get_fd(smb2), (short)smb2_which_events(smb2), 0};

		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 > ms)
			return;
		if (poll(&p, 1, 50) > 0 && smb2_service(smb2, p.revents) < 0) {
			printf("FAIL service: %s\n", smb2_get_error(smb2));
			failures++;
			return;
		}
	}
}

/* the message id of a notify still waiting on the given handle's request */
static uint64_t waiting_notify(struct smb2_context *smb2, int nth)
{
	for (struct smb2_pdu *p = smb2->waitqueue; p; p = p->next) {
		if (p->header.command == SMB2_CHANGE_NOTIFY && nth-- == 0)
			return p->header.message_id;
	}
	return 0;
}

static void check(const char *what, uint32_t got, uint32_t want)
{
	printf("%s %s (status %08x)\n", got == want ? "ok  " : "FAIL", what, got);
	failures += got != want;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *server = argc > 1 ? argv[1] : "127.0.0.1:4450";
	struct smb2_context *smb2 = smb2_init_context();
	struct smb2fh *a, *b;
	struct smb2_pdu *cancel;
	uint64_t mid_a;

	smb2_set_user(smb2, "ps5");
	smb2_set_password(smb2, "ps5");
	smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	if (smb2_connect_share(smb2, server, "data", "ps5") < 0) {
		printf("FAIL connect: %s\n", smb2_get_error(smb2));
		return 1;
	}
	smb2_mkdir(smb2, "notify-a");
	smb2_mkdir(smb2, "notify-b");
	a = smb2_open(smb2, "notify-a", O_RDONLY | O_DIRECTORY);
	b = smb2_open(smb2, "notify-b", O_RDONLY | O_DIRECTORY);
	if (!a || !b) {
		printf("FAIL open folders: %s\n", smb2_get_error(smb2));
		return 1;
	}
	smb2_notify_change_filehandle_async(smb2, a, 0, SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 0, notify_cb,
	                                    &status_a);
	smb2_notify_change_filehandle_async(smb2, b, 0, SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 0, notify_cb,
	                                    &status_b);
	serve(smb2, 500);
	check("both notifies left pending", status_a == STATUS_NONE && status_b == STATUS_NONE ? 0 : 1, 0);

	mid_a = waiting_notify(smb2, 0);
	cancel = mid_a ? smb2_cmd_cancel_async(smb2, mid_a, NULL, NULL) : NULL;
	if (!cancel) {
		printf("FAIL cancel: %s\n", smb2_get_error(smb2));
		return 1;
	}
	smb2_queue_pdu(smb2, cancel);
	serve(smb2, 500);
	check("the cancelled notify ended", status_a, STATUS_CANCELLED);
	check("the other notify still pending", status_b, STATUS_NONE);

	/* A raw close by file id: libsmb2's client frees a folder's handle itself when its notify ends, so
	   neither handle is used once its notify has been answered. */
	{
		struct smb2_close_request close_req;
		struct smb2_pdu *close_pdu;

		memset(&close_req, 0, sizeof(close_req));
		memcpy(close_req.file_id, smb2_get_file_id(b), SMB2_FD_SIZE);
		close_pdu = smb2_cmd_close_async(smb2, &close_req, close_cb, NULL);
		if (close_pdu)
			smb2_queue_pdu(smb2, close_pdu);
	}
	serve(smb2, 300);
	check("closing its folder ended the other", status_b, STATUS_NOTIFY_CLEANUP);

	smb2_rmdir(smb2, "notify-a");
	smb2_rmdir(smb2, "notify-b");
	smb2_disconnect_share(smb2);
	smb2_destroy_context(smb2);
	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
