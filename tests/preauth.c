/* A host test of requests before a login, sent as raw packets: a CANCEL right after the negotiate, a tree
   connect right after it, and a create before any negotiate. Each crashed or misread the server in
   libsmb2 (patches/libsmb2-preauth-command-check.patch); now the client is dropped and the server goes on,
   which a normal login afterwards shows. Run against `make host` (port 4450). */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

static int failures;

static void check(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	failures += !ok;
}

/* an SMB2 header (64 bytes) for a request */
static size_t header(uint8_t *p, uint16_t command, uint64_t message_id)
{
	memset(p, 0, 64);
	memcpy(p, "\xfeSMB", 4);
	p[4] = 64;              /* structure size */
	p[12] = (uint8_t)command;
	p[14] = 1;              /* credits asked */
	memcpy(p + 24, &message_id, 8);
	return 64;
}

static void send_packet(int fd, const uint8_t *smb, size_t len)
{
	uint8_t nb[4] = {0, (uint8_t)(len >> 16), (uint8_t)(len >> 8), (uint8_t)len};

	send(fd, nb, 4, 0);
	send(fd, smb, len, 0);
}

static size_t negotiate(uint8_t *p)
{
	size_t n = header(p, 0x0000, 0);
	uint8_t *b = p + n;

	memset(b, 0, 38);
	b[0] = 36;  /* structure size */
	b[2] = 1;   /* one dialect */
	b[4] = 1;   /* signing enabled */
	b[36] = 0x02;
	b[37] = 0x03; /* 0x0302 */
	return n + 38;
}

static int connect_raw(int port)
{
	struct sockaddr_in a;
	struct timeval tv = {2, 0};
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* reads until the server closes or 2 s pass; 1 when it closed or reset the connection */
static int closed_by_server(int fd)
{
	uint8_t buf[4096];

	for (int i = 0; i < 20; i++) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);

		if (n == 0)
			return 1;
		if (n < 0) /* a reset is a close too (it closed with our request still unread); a timeout is not */
			return errno != EAGAIN && errno != EWOULDBLOCK;
	}
	return 0;
}

static int login_works(const char *server)
{
	struct smb2_context *smb2 = smb2_init_context();
	int ok;

	smb2_set_user(smb2, "ps5");
	smb2_set_password(smb2, "ps5");
	smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	ok = smb2_connect_share(smb2, server, "data", "ps5") == 0;
	if (ok)
		smb2_disconnect_share(smb2);
	smb2_destroy_context(smb2);
	return ok;
}

int main(int argc, char **argv)
{
	const char *server = argc > 1 ? argv[1] : "127.0.0.1:4450";
	int port = atoi(strchr(server, ':') ? strchr(server, ':') + 1 : "445");
	uint8_t p[512];
	size_t n;
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* NEGOTIATE, then CANCEL (no payload) where the session setup is expected */
	fd = connect_raw(port);
	n = negotiate(p);
	send_packet(fd, p, n);
	usleep(200000);
	n = header(p, 0x000C, 1);
	memset(p + n, 0, 4);
	p[n] = 4;
	send_packet(fd, p, n + 4);
	check("a cancel before the login drops that client", closed_by_server(fd));
	close(fd);
	check("and the server still logs others in", login_works(server));

	/* NEGOTIATE, then TREE_CONNECT where the session setup is expected */
	fd = connect_raw(port);
	n = negotiate(p);
	send_packet(fd, p, n);
	usleep(200000);
	n = header(p, 0x0003, 1);
	memset(p + n, 0, 8);
	p[n] = 9; /* structure size, path empty */
	send_packet(fd, p, n + 8);
	check("a tree connect before the login drops that client", closed_by_server(fd));
	close(fd);
	check("and the server still logs others in", login_works(server));

	/* CREATE as the very first request */
	fd = connect_raw(port);
	n = header(p, 0x0005, 0);
	memset(p + n, 0, 56);
	p[n] = 57; /* structure size */
	send_packet(fd, p, n + 56);
	check("a create before the negotiate drops that client", closed_by_server(fd));
	close(fd);
	check("and the server still logs others in", login_works(server));

	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
