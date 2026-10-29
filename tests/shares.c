/* A host test of ps5-smbd's share list: what Explorer does for \\<console>, srvsvc NetrShareEnum over the
   IPC$ pipe, with libsmb2's client. Run against `make host` (port 4450) or a console (port 445). */
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/libsmb2-share-enum.h>

static int done, failures, found_data, found_mnt;

static void enum_cb(struct smb2_context *smb2, int status, void *data, void *priv)
{
	struct smb2_share_enum_reply *rep = data;

	(void)priv;
	if (status || !rep) {
		printf("FAIL share list: status %d %s\n", status, smb2_get_error(smb2));
		failures++;
	} else {
		for (uint32_t i = 0; i < rep->entries_read; i++) {
			const struct smb2_share_info_1 *s = &rep->share_info.info_1[i];

			printf("     share %-8s type %08x  %s\n", s->netname, s->type, s->remark ? s->remark : "");
			if (!strcmp(s->netname, "data"))
				found_data = 1;
			if (!strcmp(s->netname, "mnt"))
				found_mnt = 1;
		}
		printf("%s share list holds data and mnt\n", found_data && found_mnt ? "ok  " : "FAIL");
		failures += !(found_data && found_mnt);
	}
	if (rep)
		smb2_free_data(smb2, rep);
	done = 1;
}

int main(int argc, char **argv)
{
	const char *server = argc > 1 ? argv[1] : "127.0.0.1:4450";
	struct smb2_context *smb2 = smb2_init_context();
	time_t until = time(NULL) + 15;

	smb2_set_user(smb2, "ps5");
	smb2_set_password(smb2, "ps5");
	smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	if (smb2_connect_share(smb2, server, "IPC$", "ps5") < 0) {
		printf("FAIL connect IPC$: %s\n", smb2_get_error(smb2));
		return 1;
	}
	if (smb2_share_enum_async(smb2, SMB2_SHARE_INFO_1, enum_cb, NULL)) {
		printf("FAIL share enum: %s\n", smb2_get_error(smb2));
		return 1;
	}
	while (!done && time(NULL) < until) {
		struct pollfd p = {smb2_get_fd(smb2), (short)smb2_which_events(smb2), 0};

		if (poll(&p, 1, 500) < 0)
			break;
		if (p.revents && smb2_service(smb2, p.revents) < 0) {
			printf("FAIL service: %s\n", smb2_get_error(smb2));
			failures++;
			break;
		}
	}
	if (!done) {
		printf("FAIL share list: no answer\n");
		failures++;
	}
	smb2_disconnect_share(smb2);
	smb2_destroy_context(smb2);
	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
