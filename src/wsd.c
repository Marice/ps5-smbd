/* WS-Discovery and the DPWS metadata behind it: how Windows 10 and 11 fill their Network view.
 *
 * UDP 3702 on 239.255.255.250: a Hello when the server starts, and answers to Probe (ProbeMatches) and Resolve
 * (ResolveMatches). Windows then asks the address in XAddrs, over HTTP on port 5357, for the device's
 * metadata (a WS-Transfer Get); the answer says it is a computer with this name in WORKGROUP, and Explorer
 * lists it with the other computers. Messages are matched by the text they must contain; nothing else of
 * the SOAP is parsed. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "smbd.h"

#ifndef SMBD_WSD_PORT
#define SMBD_WSD_PORT 3702
#endif
#ifndef SMBD_WSD_HTTP_PORT
#define SMBD_WSD_HTTP_PORT 5357
#endif
#define WSD_GROUP "239.255.255.250"
#define WORKGROUP "WORKGROUP"

#define NS_SOAP "http://www.w3.org/2003/05/soap-envelope"
#define NS_WSA "http://schemas.xmlsoap.org/ws/2004/08/addressing"
#define NS_WSD "http://schemas.xmlsoap.org/ws/2005/04/discovery"
#define NS_WSDP "http://schemas.xmlsoap.org/ws/2006/02/devprof"
#define NS_WSX "http://schemas.xmlsoap.org/ws/2004/09/mex"
#define NS_PUB "http://schemas.microsoft.com/windows/pub/2005/07"
#define NS_PNPX "http://schemas.microsoft.com/windows/pnpx/2005/10"
#define ANONYMOUS NS_WSA "/role/anonymous"

static char g_endpoint[40];  /* the device's id, the same on every start: derived from the console name */
static char g_sequence[40];  /* this run's AppSequence id */
static unsigned long g_instance;
static unsigned g_message_number;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void format_uuid(const uint8_t b[16], char *out)
{
	snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1], b[2],
	         b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* A name-based id: two FNV-1a hashes of the name, shaped as a version 5 UUID. */
static void endpoint_from_name(const char *name)
{
	uint64_t h[2] = {0xcbf29ce484222325ull, 0x84222325cbf29ce4ull};
	uint8_t b[16];

	for (int k = 0; k < 2; k++) {
		for (const char *p = "ps5-smbd:"; *p; p++)
			h[k] = (h[k] ^ (uint8_t)*p) * 0x100000001b3ull;
		for (const char *p = name; *p; p++)
			h[k] = (h[k] ^ (uint8_t)*p) * (k ? 0x100000001b3ull : 0x1000193ull);
	}
	memcpy(b, &h[0], 8);
	memcpy(b + 8, &h[1], 8);
	b[6] = (uint8_t)((b[6] & 0x0F) | 0x50);
	b[8] = (uint8_t)((b[8] & 0x3F) | 0x80);
	format_uuid(b, g_endpoint);
}

static void random_uuid(char *out)
{
	uint8_t b[16];
	static uint64_t state;

	/* the UDP and the HTTP thread both ask for ids */
	pthread_mutex_lock(&g_lock);
	if (!state)
		state = (uint64_t)time(NULL) * 0x9E3779B97F4A7C15ull ^ (uint64_t)(uintptr_t)&state;
	for (int i = 0; i < 16; i++) {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		b[i] = (uint8_t)state;
	}
	pthread_mutex_unlock(&g_lock);
	b[6] = (uint8_t)((b[6] & 0x0F) | 0x40);
	b[8] = (uint8_t)((b[8] & 0x3F) | 0x80);
	format_uuid(b, out);
}

/* The text between "<...name>" and "</", wherever the name's prefix; 0 when there is none. */
static int element(const char *xml, const char *name, char *out, size_t size)
{
	char open[64];
	const char *p, *start, *end;

	snprintf(open, sizeof(open), ":%s>", name);
	p = strstr(xml, open);
	if (!p) {
		snprintf(open, sizeof(open), "<%s>", name);
		p = strstr(xml, open);
		if (!p)
			return 0;
	}
	start = p + strlen(open);
	end = strstr(start, "</");
	if (!end || (size_t)(end - start) >= size)
		return 0;
	memcpy(out, start, (size_t)(end - start));
	out[end - start] = 0;
	return 1;
}

/* The SOAP header every message has; to, action and relates_to (NULL when none) differ. */
static int header(char *out, size_t size, const char *to, const char *action, const char *relates_to,
                  int with_sequence)
{
	char id[40];
	int n;

	random_uuid(id);
	n = snprintf(out, size,
	             "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
	             "<soap:Envelope xmlns:soap=\"" NS_SOAP "\" xmlns:wsa=\"" NS_WSA "\" xmlns:wsd=\"" NS_WSD
	             "\" xmlns:wsdp=\"" NS_WSDP "\" xmlns:wsx=\"" NS_WSX "\" xmlns:pub=\"" NS_PUB
	             "\" xmlns:pnpx=\"" NS_PNPX "\">"
	             "<soap:Header><wsa:To>%s</wsa:To><wsa:Action>%s</wsa:Action>"
	             "<wsa:MessageID>urn:uuid:%s</wsa:MessageID>",
	             to, action, id);
	if (relates_to)
		n += snprintf(out + n, size - (size_t)n, "<wsa:RelatesTo>%s</wsa:RelatesTo>", relates_to);
	if (with_sequence) {
		pthread_mutex_lock(&g_lock);
		n += snprintf(out + n, size - (size_t)n,
		              "<wsd:AppSequence InstanceId=\"%lu\" SequenceId=\"urn:uuid:%s\" MessageNumber=\"%u\"/>",
		              g_instance, g_sequence, ++g_message_number);
		pthread_mutex_unlock(&g_lock);
	}
	n += snprintf(out + n, size - (size_t)n, "</soap:Header>");
	return n;
}

/* The device as Hello, ProbeMatch and ResolveMatch describe it. */
static int device(char *out, size_t size, struct in_addr ip)
{
	char text[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ip, text, sizeof(text)); /* not inet_ntoa: its one buffer is shared by the threads */
	return snprintf(out, size,
	                "<wsa:EndpointReference><wsa:Address>urn:uuid:%s</wsa:Address></wsa:EndpointReference>"
	                "<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"
	                "<wsd:XAddrs>http://%s:%d/%s</wsd:XAddrs>"
	                "<wsd:MetadataVersion>1</wsd:MetadataVersion>",
	                g_endpoint, text, SMBD_WSD_HTTP_PORT, g_endpoint);
}

static void send_hello(int fd)
{
	char msg[2048];
	struct sockaddr_in to;
	struct in_addr any = {0}, me;
	int n;

	if (names_address(any, &me) < 0)
		return;
	n = header(msg, sizeof(msg), "urn:schemas-xmlsoap-org:ws:2005:04:discovery", NS_WSD "/Hello", NULL, 1);
	n += snprintf(msg + n, sizeof(msg) - (size_t)n, "<soap:Body><wsd:Hello>");
	n += device(msg + n, sizeof(msg) - (size_t)n, me);
	n += snprintf(msg + n, sizeof(msg) - (size_t)n, "</wsd:Hello></soap:Body></soap:Envelope>");
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(SMBD_WSD_PORT);
	inet_pton(AF_INET, WSD_GROUP, &to.sin_addr);
	sendto(fd, msg, (size_t)n, 0, (struct sockaddr *)&to, sizeof(to));
}

/* A Probe for a device or a computer (or for anything), or a Resolve of our id: answered to the asker. */
static void udp_message(int fd, char *msg, struct sockaddr_in *from)
{
	char reply[2048], id[128], types[256];
	struct in_addr me;
	int probe, n;
	const char *what;

	if (strstr(msg, "discovery/ProbeMatches") || strstr(msg, "discovery/ResolveMatches"))
		return;
	probe = strstr(msg, "discovery/Probe") != NULL;
	if (!probe && !strstr(msg, "discovery/Resolve"))
		return;
	if (!element(msg, "MessageID", id, sizeof(id)))
		return;
	if (probe && element(msg, "Types", types, sizeof(types)) && types[0] && !strstr(types, "Device") &&
	    !strstr(types, "Computer"))
		return;
	if (!probe && !strstr(msg, g_endpoint))
		return;
	if (names_address(from->sin_addr, &me) < 0)
		return;
	what = probe ? "ProbeMatch" : "ResolveMatch";
	n = header(reply, sizeof(reply), ANONYMOUS, probe ? NS_WSD "/ProbeMatches" : NS_WSD "/ResolveMatches", id,
	           1);
	n += snprintf(reply + n, sizeof(reply) - (size_t)n, "<soap:Body><wsd:%ses><wsd:%s>", what, what);
	n += device(reply + n, sizeof(reply) - (size_t)n, me);
	n += snprintf(reply + n, sizeof(reply) - (size_t)n, "</wsd:%s></wsd:%ses></soap:Body></soap:Envelope>",
	              what, what);
	sendto(fd, reply, (size_t)n, 0, (struct sockaddr *)from, sizeof(*from));
	if (smbd_trace) {
		char ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &from->sin_addr, ip, sizeof(ip));
		smbd_log("wsd: %s answered for %s", probe ? "Probe" : "Resolve", ip);
	}
}

/* The metadata: this device, its model, and that it hosts a computer named so in the workgroup. */
static void http_get(int fd, const char *body)
{
	char soap[4096], head[256], id[128];
	int n, h;

	if (!strstr(body, "transfer/Get") || !element(body, "MessageID", id, sizeof(id))) {
		static const char bad[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
		send(fd, bad, sizeof(bad) - 1, 0);
		return;
	}
	n = header(soap, sizeof(soap), ANONYMOUS, "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse", id,
	           0);
	n += snprintf(soap + n, sizeof(soap) - (size_t)n,
	              "<soap:Body><wsx:Metadata>"
	              "<wsx:MetadataSection Dialect=\"" NS_WSDP "/ThisDevice\"><wsdp:ThisDevice>"
	              "<wsdp:FriendlyName>%s</wsdp:FriendlyName><wsdp:FirmwareVersion>1.0</wsdp:FirmwareVersion>"
	              "<wsdp:SerialNumber>1</wsdp:SerialNumber></wsdp:ThisDevice></wsx:MetadataSection>"
	              "<wsx:MetadataSection Dialect=\"" NS_WSDP "/ThisModel\"><wsdp:ThisModel>"
	              "<wsdp:Manufacturer>ps5-smbd</wsdp:Manufacturer><wsdp:ModelName>PlayStation 5</wsdp:ModelName>"
	              "<pnpx:DeviceCategory>Computers</pnpx:DeviceCategory></wsdp:ThisModel></wsx:MetadataSection>"
	              "<wsx:MetadataSection Dialect=\"" NS_WSDP "/Relationship\">"
	              "<wsdp:Relationship Type=\"" NS_WSDP "/host\"><wsdp:Host>"
	              "<wsa:EndpointReference><wsa:Address>urn:uuid:%s</wsa:Address></wsa:EndpointReference>"
	              "<wsdp:Types>pub:Computer</wsdp:Types><wsdp:ServiceId>urn:uuid:%s</wsdp:ServiceId>"
	              "<pub:Computer>%s/Workgroup:" WORKGROUP "</pub:Computer>"
	              "</wsdp:Host></wsdp:Relationship></wsx:MetadataSection>"
	              "</wsx:Metadata></soap:Body></soap:Envelope>",
	              smbd_name, g_endpoint, g_endpoint, smbd_name);
	h = snprintf(head, sizeof(head),
	             "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: %d\r\n"
	             "Connection: close\r\n\r\n",
	             n);
	send(fd, head, (size_t)h, 0);
	send(fd, soap, (size_t)n, 0);
	if (smbd_trace)
		smbd_log("wsd: metadata sent");
}

/* The first place needle is found in hay, ignoring case (strcasestr is not in every libc). */
static char *find_nocase(char *hay, const char *needle)
{
	size_t n = strlen(needle);

	for (; *hay; hay++) {
		if (!strncasecmp(hay, needle, n))
			return hay;
	}
	return NULL;
}

/* One HTTP request: headers up to the blank line, then Content-Length bytes of SOAP. Within a few seconds
   in all: requests are served one at a time, so a client that trickles bytes would hold up the rest. */
static void http_client(int fd)
{
	char buf[16384];
	size_t got = 0;
	char *body = NULL;
	long want = -1;
	struct timeval tv = {1, 0};
	const time_t deadline = time(NULL) + 3;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	while (got < sizeof(buf) - 1) {
		ssize_t n;

		if (time(NULL) > deadline)
			return;
		n = recv(fd, buf + got, sizeof(buf) - 1 - got, 0);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
			continue;
		if (n <= 0)
			return;
		got += (size_t)n;
		buf[got] = 0;
		if (!body && (body = strstr(buf, "\r\n\r\n"))) {
			char *cl = find_nocase(buf, "Content-Length:");

			body += 4;
			want = cl && cl < body ? strtol(cl + 15, NULL, 10) : 0;
		}
		if (body && (long)(got - (size_t)(body - buf)) >= want)
			break;
	}
	if (body)
		http_get(fd, body);
}

static void *http_thread(void *arg)
{
	int lfd = (int)(intptr_t)arg;

	for (;;) {
		int fd = accept(lfd, NULL, NULL);

		if (fd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		http_client(fd);
		close(fd);
	}
	return NULL;
}

static void *udp_thread(void *arg)
{
	int fd = (int)(intptr_t)arg;
	time_t next_hello = 0;
	int hellos = 0;

	for (;;) {
		struct pollfd p = {fd, POLLIN, 0};
		char buf[8192];
		struct sockaddr_in from;
		socklen_t len = sizeof(from);
		ssize_t n;

		/* Hello on start, three times a few seconds apart (UDP may lose one) */
		if (hellos < 3 && time(NULL) >= next_hello) {
			send_hello(fd);
			hellos++;
			next_hello = time(NULL) + 3;
		}
		if (poll(&p, 1, 1000) <= 0)
			continue;
		n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &len);
		if (n <= 0)
			continue;
		buf[n] = 0;
		udp_message(fd, buf, &from);
	}
	return NULL;
}

void wsd_start(void)
{
	struct sockaddr_in a;
	struct ip_mreq m;
	int one = 1, ttl = 1;
	int ufd, hfd;
	pthread_t t;

	endpoint_from_name(smbd_name);
	random_uuid(g_sequence);
	g_instance = (unsigned long)time(NULL);

	/* the metadata over HTTP first: a Hello must not point at a port that isn't there */
	hfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons(SMBD_WSD_HTTP_PORT);
	setsockopt(hfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (hfd < 0 || bind(hfd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(hfd, 8) < 0) {
		smbd_log("wsd: off, port %d: %s", SMBD_WSD_HTTP_PORT, strerror(errno));
		if (hfd >= 0)
			close(hfd);
		return;
	}
	ufd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
	setsockopt(ufd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
	a.sin_port = htons(SMBD_WSD_PORT);
	if (ufd < 0 || bind(ufd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		smbd_log("wsd: off, port %d: %s", SMBD_WSD_PORT, strerror(errno));
		if (ufd >= 0)
			close(ufd);
		close(hfd);
		return;
	}
	memset(&m, 0, sizeof(m));
	inet_pton(AF_INET, WSD_GROUP, &m.imr_multiaddr);
	m.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(ufd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m)) < 0)
		smbd_log("wsd: joins no group " WSD_GROUP ": %s", strerror(errno));
	setsockopt(ufd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	if (pthread_create(&t, NULL, http_thread, (void *)(intptr_t)hfd) == 0)
		pthread_detach(t);
	if (pthread_create(&t, NULL, udp_thread, (void *)(intptr_t)ufd) == 0)
		pthread_detach(t);
	smbd_log("wsd: %s in the Network view (device urn:uuid:%s)", smbd_name, g_endpoint);
}
