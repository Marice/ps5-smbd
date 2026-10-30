/* The console's name on the local network, so Windows finds \\<name> without the IP: NetBIOS name service
 * (UDP 137, name queries and node status), mDNS (<name>.local, UDP 5353) and LLMNR (UDP 5355), the ways
 * Windows resolves a single-label name. One thread; a port that cannot be bound is logged once and left out. */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "smbd.h"

#ifndef SMBD_NBNS_PORT
#define SMBD_NBNS_PORT 137
#endif
#ifndef SMBD_MDNS_PORT
#define SMBD_MDNS_PORT 5353
#endif
#ifndef SMBD_LLMNR_PORT
#define SMBD_LLMNR_PORT 5355
#endif

char smbd_name[16] = "PS5";      /* NetBIOS form: upper case, at most 15 characters */
static char g_label[64] = "ps5"; /* DNS label form, for <label>.local */

/* ---- the name ------------------------------------------------------------------------------------------ */

void names_set(const char *console_name)
{
	size_t n = 0, l = 0;

	if (!console_name || !*console_name)
		return;
	/* NetBIOS: letters, digits and hyphens kept, the rest a hyphen, upper case, 15 at most */
	for (const char *p = console_name; *p && n < 15; p++) {
		unsigned char c = (unsigned char)*p;
		smbd_name[n++] = isalnum(c) ? (char)toupper(c) : '-';
	}
	while (n && smbd_name[n - 1] == '-')
		n--;
	smbd_name[n] = 0;
	/* DNS label: lower case, letters, digits and single hyphens, no hyphen at either end */
	for (const char *p = console_name; *p && l < sizeof(g_label) - 1; p++) {
		unsigned char c = (unsigned char)*p;
		char out = isalnum(c) ? (char)tolower(c) : '-';
		if (out == '-' && (l == 0 || g_label[l - 1] == '-'))
			continue;
		g_label[l++] = out;
	}
	while (l && g_label[l - 1] == '-')
		l--;
	g_label[l] = 0;
	if (!smbd_name[0])
		snprintf(smbd_name, sizeof(smbd_name), "PS5");
	if (!g_label[0])
		snprintf(g_label, sizeof(g_label), "ps5");
}

const char *names_label(void)
{
	return g_label;
}

/* The console's IPv4 address on the asker's subnet (the first one otherwise); wsd.c uses it too. */
int names_address(struct in_addr peer, struct in_addr *out)
{
	struct ifaddrs *list, *i;
	int found = 0;

	if (getifaddrs(&list) < 0)
		return -1;
	for (i = list; i; i = i->ifa_next) {
		struct sockaddr_in *a = (struct sockaddr_in *)i->ifa_addr;
		struct sockaddr_in *m = (struct sockaddr_in *)i->ifa_netmask;

		if (!a || a->sin_family != AF_INET || (i->ifa_flags & IFF_LOOPBACK) || !(i->ifa_flags & IFF_UP))
			continue;
		if (m && ((a->sin_addr.s_addr ^ peer.s_addr) & m->sin_addr.s_addr) == 0) {
			*out = a->sin_addr;
			found = 2;
			break;
		}
		if (!found) {
			*out = a->sin_addr;
			found = 1;
		}
	}
	freeifaddrs(list);
	return found ? 0 : -1;
}

/* ---- NetBIOS name service (RFC 1002) ---------------------------------------------------------------- */

static void nb_decode(const uint8_t *enc, char name[16], uint8_t *suffix)
{
	for (int i = 0; i < 16; i++)
		name[i] = (char)(((enc[i * 2] - 'A') << 4) | ((enc[i * 2 + 1] - 'A') & 0x0F));
	*suffix = (uint8_t)name[15];
	name[15] = 0;
	for (int i = 14; i >= 0 && name[i] == ' '; i--)
		name[i] = 0;
}

static void nb_encode(const char *name, uint8_t suffix, uint8_t out[16])
{
	memset(out, ' ', 15);
	for (size_t i = 0; i < 15 && name[i]; i++)
		out[i] = (uint8_t)toupper((unsigned char)name[i]);
	out[15] = suffix;
}

static void nbns_handle(int fd, const uint8_t *q, ssize_t n, struct sockaddr_in *from)
{
	uint8_t r[512];
	char name[16];
	uint8_t suffix;
	uint16_t type;
	struct in_addr me;
	size_t at = 0;

	/* a query (not a response), one question, an encoded name of 32 characters */
	if (n < 12 + 34 + 4 || (q[2] & 0x80) || ((q[2] >> 3) & 0x0F) != 0 || q[5] != 1 || q[12] != 32)
		return;
	nb_decode(q + 13, name, &suffix);
	type = (uint16_t)(q[12 + 34] << 8 | q[12 + 34 + 1]);
	if (names_address(from->sin_addr, &me) < 0)
		return;
	memcpy(r, q, 2); /* the transaction id */
	if (type == 0x20 && !strcasecmp(name, smbd_name) && (suffix == 0x00 || suffix == 0x20)) {
		/* a positive name query response: one answer, our address, B-node, unique */
		r[2] = 0x85;
		r[3] = 0x00;
		r[4] = r[5] = 0;
		r[6] = 0;
		r[7] = 1;
		r[8] = r[9] = r[10] = r[11] = 0;
		at = 12;
		memcpy(r + at, q + 12, 34);
		at += 34;
		r[at++] = 0x00, r[at++] = 0x20, r[at++] = 0x00, r[at++] = 0x01;      /* NB, IN */
		r[at++] = 0x00, r[at++] = 0x04, r[at++] = 0x93, r[at++] = 0xE0;      /* TTL 300000 s */
		r[at++] = 0x00, r[at++] = 0x06, r[at++] = 0x00, r[at++] = 0x00;      /* 6 bytes: flags 0 */
		memcpy(r + at, &me.s_addr, 4);
		at += 4;
	} else if (type == 0x21 && (name[0] == '*' || !strcasecmp(name, smbd_name))) {
		/* node status: the names this machine has, as Windows asks when it browses by address */
		static const struct { int group; uint8_t suffix; } names[] = {{0, 0x00}, {0, 0x20}, {1, 0x00}};
		r[2] = 0x84;
		r[3] = 0x00;
		r[4] = r[5] = 0;
		r[6] = 0;
		r[7] = 1;
		r[8] = r[9] = r[10] = r[11] = 0;
		at = 12;
		memcpy(r + at, q + 12, 34);
		at += 34;
		r[at++] = 0x00, r[at++] = 0x21, r[at++] = 0x00, r[at++] = 0x01;      /* NBSTAT, IN */
		r[at++] = 0, r[at++] = 0, r[at++] = 0, r[at++] = 0;                  /* TTL 0 */
		{
			size_t len_at = at;
			at += 2;
			r[at++] = 3;
			for (int i = 0; i < 3; i++) {
				nb_encode(names[i].group ? "WORKGROUP" : smbd_name, names[i].suffix, r + at);
				at += 16;
				r[at++] = names[i].group ? 0x84 : 0x04; /* active, (group) */
				r[at++] = 0x00;
			}
			memset(r + at, 0, 46); /* statistics: a zero unit id (MAC) is accepted */
			at += 46;
			r[len_at] = (uint8_t)((at - len_at - 2) >> 8);
			r[len_at + 1] = (uint8_t)(at - len_at - 2);
		}
	} else {
		return;
	}
	sendto(fd, r, at, 0, (struct sockaddr *)from, sizeof(*from));
	if (smbd_trace) {
		char ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &from->sin_addr, ip, sizeof(ip));
		smbd_log("names: NetBIOS %s for %s from %s", type == 0x21 ? "node status" : "query", name, ip);
	}
}

/* ---- mDNS (RFC 6762) and LLMNR (RFC 4795): DNS-shaped queries ---------------------------------------- */

/* Reads the question's name as dotted text; returns the offset after it, 0 if malformed. */
static size_t read_name(const uint8_t *m, size_t n, size_t at, char *out, size_t size)
{
	size_t o = 0;

	while (at < n && m[at]) {
		size_t len = m[at];

		if ((len & 0xC0) || at + 1 + len > n || o + len + 2 > size)
			return 0; /* no compression in a question we answer */
		if (o)
			out[o++] = '.';
		memcpy(out + o, m + at + 1, len);
		o += len;
		at += 1 + len;
	}
	if (at >= n)
		return 0;
	out[o] = 0;
	return at + 1;
}

/* mdns: 1 for mDNS (name <label>.local), 0 for LLMNR (name <NAME>) */
static void dns_handle(int fd, int mdns, const uint8_t *q, ssize_t n, struct sockaddr_in *from)
{
	uint8_t r[512];
	char name[256];
	char want[96];
	size_t at, qend;
	uint16_t type, klass;
	struct in_addr me;
	int legacy = mdns && ntohs(from->sin_port) != SMBD_MDNS_PORT;
	int unicast;
	struct sockaddr_in to = *from;

	if (n < 12 || (q[2] & 0x80) || (q[2] & 0x78) || q[4] != 0 || q[5] != 1)
		return;
	qend = read_name(q, (size_t)n, 12, name, sizeof(name));
	if (!qend || qend + 4 > (size_t)n)
		return;
	type = (uint16_t)(q[qend] << 8 | q[qend + 1]);
	klass = (uint16_t)(q[qend + 2] << 8 | q[qend + 3]);
	if (mdns)
		snprintf(want, sizeof(want), "%s.local", g_label);
	else
		snprintf(want, sizeof(want), "%s", smbd_name);
	if (strcasecmp(name, want) || (type != 1 && type != 255) || (klass & 0x7FFF) != 1)
		return;
	if (names_address(from->sin_addr, &me) < 0)
		return;
	unicast = !mdns || legacy || (klass & 0x8000);

	/* header: the asker's id (mDNS multicast answers carry 0), an authoritative answer */
	r[0] = mdns && !legacy ? 0 : q[0];
	r[1] = mdns && !legacy ? 0 : q[1];
	r[2] = mdns ? 0x84 : 0x80;
	r[3] = 0x00;
	r[4] = 0;
	r[5] = (uint8_t)(legacy || !mdns ? 1 : 0); /* LLMNR and legacy unicast repeat the question */
	r[6] = 0;
	r[7] = 1;
	r[8] = r[9] = r[10] = r[11] = 0;
	at = 12;
	if (r[5]) {
		memcpy(r + at, q + 12, qend + 4 - 12);
		at += qend + 4 - 12;
		r[at++] = 0xC0, r[at++] = 0x0C; /* the answer's name: a pointer to the question's */
	} else {
		memcpy(r + at, q + 12, qend - 12);
		at += qend - 12;
	}
	r[at++] = 0x00, r[at++] = 0x01;                                  /* A */
	r[at++] = (uint8_t)(mdns && !legacy ? 0x80 : 0x00), r[at++] = 0x01; /* IN (cache flush for mDNS) */
	r[at++] = 0, r[at++] = 0, r[at++] = 0, r[at++] = (uint8_t)(mdns ? 120 : 30); /* TTL */
	r[at++] = 0x00, r[at++] = 0x04;
	memcpy(r + at, &me.s_addr, 4);
	at += 4;
	if (!unicast) {
		to.sin_family = AF_INET;
		to.sin_port = htons(SMBD_MDNS_PORT);
		inet_pton(AF_INET, "224.0.0.251", &to.sin_addr);
	}
	sendto(fd, r, at, 0, (struct sockaddr *)&to, sizeof(to));
	if (smbd_trace) {
		char ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &from->sin_addr, ip, sizeof(ip));
		smbd_log("names: %s answered %s for %s", mdns ? "mDNS" : "LLMNR", want, ip);
	}
}

/* ---- sockets and the thread ------------------------------------------------------------------------- */

static int open_udp(const char *what, int port, const char *group)
{
	struct sockaddr_in a;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int one = 1;

	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		smbd_log("names: %s off, port %d: %s", what, port, strerror(errno));
		close(fd);
		return -1;
	}
	if (group) {
		struct ip_mreq m;

		memset(&m, 0, sizeof(m));
		inet_pton(AF_INET, group, &m.imr_multiaddr);
		m.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m)) < 0)
			smbd_log("names: %s joins no group %s: %s", what, group, strerror(errno));
	}
	return fd;
}

static void *names_thread(void *arg)
{
	struct pollfd p[3];
	int kinds[3];
	int count = 0;
	int fd;

	(void)arg;
	if ((fd = open_udp("NetBIOS", SMBD_NBNS_PORT, NULL)) >= 0)
		p[count].fd = fd, kinds[count++] = 0;
	if ((fd = open_udp("mDNS", SMBD_MDNS_PORT, "224.0.0.251")) >= 0)
		p[count].fd = fd, kinds[count++] = 1;
	if ((fd = open_udp("LLMNR", SMBD_LLMNR_PORT, "224.0.0.252")) >= 0)
		p[count].fd = fd, kinds[count++] = 2;
	smbd_log("names: \\\\%s (NetBIOS, LLMNR) and %s.local (mDNS), %d of 3 listening", smbd_name, g_label, count);
	if (!count)
		return NULL;
	for (int i = 0; i < count; i++)
		p[i].events = POLLIN;
	for (;;) {
		if (poll(p, (nfds_t)count, -1) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (int i = 0; i < count; i++) {
			uint8_t buf[1500];
			struct sockaddr_in from;
			socklen_t len = sizeof(from);
			ssize_t n;

			if (!(p[i].revents & POLLIN))
				continue;
			n = recvfrom(p[i].fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &len);
			if (n <= 0 || from.sin_family != AF_INET)
				continue;
			if (kinds[i] == 0)
				nbns_handle(p[i].fd, buf, n, &from);
			else
				dns_handle(p[i].fd, kinds[i] == 1, buf, n, &from);
		}
	}
	return NULL;
}

void names_start(void)
{
	pthread_t t;

	if (pthread_create(&t, NULL, names_thread, NULL) == 0)
		pthread_detach(t);
	else
		smbd_log("names: no thread, the name stays unknown on the network");
}
