/* A host test of ps5-smbd's share list: what Explorer does for \\<console>, srvsvc NetrShareEnum over the
   IPC$ pipe, with libsmb2's client. A drive under mnt is a share of its own: a folder ext9 in the test mnt
   becomes \\<host>\ext9 (on the host a folder with a drive's name is enough; on the console it must hold a
   file system of its own), a folder "extra" does not, and ext9 goes from the list when its folder goes.
   Run against `make host` (port 4450).
   usage: shares [server:port] [the mnt share's folder on this computer] */
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
#include <smb2/libsmb2-share-enum.h>

static int done, failures, found_data, found_mnt, found_ext9, found_extra;

static void check(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	failures += !ok;
}

static void enum_cb(struct smb2_context *smb2, int status, void *data, void *priv)
{
	struct smb2_share_enum_reply *rep = data;

	(void)priv;
	found_data = found_mnt = found_ext9 = found_extra = 0;
	if (status || !rep) {
		printf("FAIL share list: status %d %s\n", status, smb2_get_error(smb2));
		failures++;
	} else {
		for (uint32_t i = 0; i < rep->entries_read; i++) {
			const struct smb2_share_info_1 *s = &rep->share_info.info_1[i];

			printf("     share %-8s type %08x  %s\n", s->netname, s->type, s->remark ? s->remark : "");
			found_data |= !strcmp(s->netname, "data");
			found_mnt |= !strcmp(s->netname, "mnt");
			found_ext9 |= !strcmp(s->netname, "ext9");
			found_extra |= !strcmp(s->netname, "extra");
		}
	}
	if (rep)
		smb2_free_data(smb2, rep);
	done = 1;
}

static struct smb2_context *login(const char *server, const char *share)
{
	struct smb2_context *smb2 = smb2_init_context();

	smb2_set_user(smb2, "ps5");
	smb2_set_password(smb2, "ps5");
	smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	if (smb2_connect_share(smb2, server, share, "ps5") < 0) {
		smb2_destroy_context(smb2);
		return NULL;
	}
	return smb2;
}

static void list_shares(const char *server)
{
	struct smb2_context *smb2 = login(server, "IPC$");
	time_t until = time(NULL) + 15;

	done = 0;
	if (!smb2) {
		printf("FAIL connect IPC$\n");
		failures++;
		return;
	}
	if (smb2_share_enum_async(smb2, SMB2_SHARE_INFO_1, enum_cb, NULL)) {
		printf("FAIL share enum: %s\n", smb2_get_error(smb2));
		failures++;
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
}

int main(int argc, char **argv)
{
	const char *server = argc > 1 ? argv[1] : "127.0.0.1:4450";
	const char *mnt = argc > 2 ? argv[2] : "build/mnt";
	char ext9[4096], extra[4096], file[4096];
	struct smb2_context *smb2;
	struct stat st;

	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(ext9, sizeof(ext9), "%s/ext9", mnt);
	snprintf(extra, sizeof(extra), "%s/extra", mnt);
	snprintf(file, sizeof(file), "%s/ext9/written.txt", mnt);
	mkdir(ext9, 0755);
	mkdir(extra, 0755);

	list_shares(server);
	check("the share list holds data and mnt", found_data && found_mnt);
	check("and the drive ext9 under mnt as a share of its own", found_ext9);
	check("but not the folder extra", !found_extra);

	smb2 = login(server, "ext9");
	check("\\\\<host>\\ext9 connects", smb2 != NULL);
	if (smb2) {
		struct smb2fh *fh = smb2_open(smb2, "written.txt", O_WRONLY | O_CREAT | O_TRUNC);

		check("a file written there", fh && smb2_write(smb2, fh, (const uint8_t *)"ext9", 4) == 4);
		if (fh)
			smb2_close(smb2, fh);
		check("lands in mnt/ext9", stat(file, &st) == 0 && st.st_size == 4);
		smb2_disconnect_share(smb2);
		smb2_destroy_context(smb2);
	}

	unlink(file);
	rmdir(ext9);
	rmdir(extra);
	list_shares(server);
	check("a drive that is gone leaves the list", found_data && found_mnt && !found_ext9);
	smb2 = login(server, "ext9");
	check("and does not connect", smb2 == NULL);
	if (smb2) {
		smb2_disconnect_share(smb2);
		smb2_destroy_context(smb2);
	}

	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
