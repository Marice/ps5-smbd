/* A host test of ps5-smbd with libsmb2's client: list, write, read back, rename, delete, a missing file,
   a path that tries to leave the share. Run against `make host` (port 4450). */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

static int failures;
#define CHECK(cond, ...) do { if (cond) printf("ok   "); else { printf("FAIL "); failures++; } printf(__VA_ARGS__); printf("\n"); } while (0)

int main(int argc, char **argv)
{
	const char *server = argc > 1 ? argv[1] : "127.0.0.1:4450";
	struct smb2_context *smb2 = smb2_init_context();
	struct smb2dir *dir;
	struct smb2dirent *e;
	struct smb2fh *fh;
	struct smb2_stat_64 st;
	uint8_t buf[200000], back[200000];
	int n, found = 0;

	smb2_set_user(smb2, "ps5");
	smb2_set_password(smb2, "ps5");
	smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	smb2_set_timeout(smb2, 10);
	CHECK(smb2_connect_share(smb2, server, "data", "ps5") == 0, "connect data (signing required): %s", smb2_get_error(smb2));

	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)(i * 7 + 3);
	smb2_mkdir(smb2, "ps5-smbd-test");
	fh = smb2_open(smb2, "ps5-smbd-test/a.bin", O_WRONLY | O_CREAT | O_TRUNC);
	CHECK(fh != NULL, "create a.bin: %s", smb2_get_error(smb2));
	if (fh) {
		size_t done = 0;
		while (done < sizeof(buf)) {
			n = smb2_write(smb2, fh, buf + done, (uint32_t)(sizeof(buf) - done) > 65536 ? 65536 : (uint32_t)(sizeof(buf) - done));
			if (n <= 0) break;
			done += (size_t)n;
		}
		CHECK(done == sizeof(buf), "write %zu bytes", done);
		smb2_close(smb2, fh);
	}
	fh = smb2_open(smb2, "ps5-smbd-test/a.bin", O_RDONLY);
	CHECK(fh != NULL, "open a.bin: %s", smb2_get_error(smb2));
	if (fh) {
		size_t done = 0;
		while (done < sizeof(back) && (n = smb2_read(smb2, fh, back + done, 65536)) > 0)
			done += (size_t)n;
		CHECK(done == sizeof(back) && !memcmp(buf, back, sizeof(buf)), "read back %zu bytes, same content", done);
		smb2_close(smb2, fh);
	}
	CHECK(smb2_stat(smb2, "ps5-smbd-test/a.bin", &st) == 0 && st.smb2_size == sizeof(buf), "stat size %llu",
	      (unsigned long long)st.smb2_size);
	CHECK(smb2_rename(smb2, "ps5-smbd-test/a.bin", "ps5-smbd-test/b.bin") == 0, "rename: %s", smb2_get_error(smb2));
	dir = smb2_opendir(smb2, "ps5-smbd-test");
	CHECK(dir != NULL, "list ps5-smbd-test: %s", smb2_get_error(smb2));
	if (dir) {
		while ((e = smb2_readdir(smb2, dir)))
			if (!strcmp(e->name, "b.bin"))
				found = 1;
		smb2_closedir(smb2, dir);
	}
	CHECK(found, "b.bin listed");
	CHECK(smb2_stat(smb2, "ps5-smbd-test/nothere", &st) < 0, "missing file refused: %s", smb2_get_error(smb2));
	CHECK(smb2_open(smb2, "../outside.txt", O_RDONLY) == NULL, "path out of the share refused: %s", smb2_get_error(smb2));
	CHECK(smb2_unlink(smb2, "ps5-smbd-test/b.bin") == 0, "delete b.bin: %s", smb2_get_error(smb2));
	CHECK(smb2_rmdir(smb2, "ps5-smbd-test") == 0, "remove ps5-smbd-test: %s", smb2_get_error(smb2));
	dir = smb2_opendir(smb2, "");
	n = 0;
	if (dir) {
		while ((e = smb2_readdir(smb2, dir)))
			n++;
		smb2_closedir(smb2, dir);
	}
	CHECK(dir != NULL, "list the share's top: %d entries", n);
	smb2_disconnect_share(smb2);
	smb2_destroy_context(smb2);
	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
