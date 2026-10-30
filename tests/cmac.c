/* A host test of libsmb2's AES-CMAC (SMB3 signing) after patches/libsmb2-signing-aesni.patch:
 * the RFC 4493 test vectors, the same MAC as the portable code (rebuilt here from libsmb2's own
 * AES128_ECB_encrypt) for messages of every length up to 4 KB and a few large ones, and its speed.
 * Link with the host libsmb2.a. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void smb3_aes_cmac_128(uint8_t key[16], uint8_t *msg, uint64_t msg_len, uint8_t mac[16]);
void AES128_ECB_encrypt(uint8_t *input, const uint8_t *key, uint8_t *output);

static int failures;

static void check(const char *what, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	failures += !ok;
}

static void hex(const char *s, uint8_t *out)
{
	for (size_t i = 0; s[2 * i]; i++)
		sscanf(s + 2 * i, "%2hhx", &out[i]);
}

/* the portable algorithm as libsmb2 had it, one AES call per block */
static void shift_left(uint8_t d[16], int *carry)
{
	int c = 0;

	for (int i = 15; i >= 0; i--) {
		int next = d[i] >> 7;

		d[i] = (uint8_t)(d[i] << 1 | c);
		c = next;
	}
	*carry = c;
}

static void reference_cmac(const uint8_t key[16], const uint8_t *msg, uint64_t len, uint8_t mac[16])
{
	uint8_t k1[16], k2[16], zero[16] = {0}, x[16] = {0}, last[16], t[16];
	uint64_t n = (len + 15) / 16, rem = len % 16, i;
	int carry, complete = n != 0 && rem == 0;

	AES128_ECB_encrypt(zero, key, k1);
	shift_left(k1, &carry);
	if (carry)
		k1[15] ^= 0x87;
	memcpy(k2, k1, 16);
	shift_left(k2, &carry);
	if (carry)
		k2[15] ^= 0x87;
	if (n == 0)
		n = 1;
	for (i = 0; i < n - 1; i++) {
		for (int j = 0; j < 16; j++)
			x[j] ^= msg[i * 16 + j];
		AES128_ECB_encrypt(x, key, t);
		memcpy(x, t, 16);
	}
	memset(last, 0, 16);
	if (complete) {
		memcpy(last, msg + i * 16, 16);
		for (int j = 0; j < 16; j++)
			last[j] ^= k1[j];
	} else {
		memcpy(last, msg + i * 16, rem);
		last[rem] = 0x80;
		for (int j = 0; j < 16; j++)
			last[j] ^= k2[j];
	}
	for (int j = 0; j < 16; j++)
		x[j] ^= last[j];
	AES128_ECB_encrypt(x, key, mac);
}

int main(void)
{
	static const char *vectors[][2] = {
	    {"", "bb1d6929e95937287fa37d129b756746"},
	    {"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
	    {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
	     "dfa66747de9ae63030ca32611497c827"},
	    {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
	     "f69f2445df4f9b17ad2b417be66c3710",
	     "51f0bebf7e3b9d92fc49741779363cfe"},
	};
	uint8_t key[16], msg[64], want[16], got[16], ref[16];
	uint8_t *big = malloc(4 << 20);
	int bad = 0;
	struct timespec t0, t1;
	double secs;

	setvbuf(stdout, NULL, _IONBF, 0);
	hex("2b7e151628aed2a6abf7158809cf4f3c", key);
	for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
		char what[64];

		memset(msg, 0, sizeof(msg));
		hex(vectors[v][0], msg);
		hex(vectors[v][1], want);
		smb3_aes_cmac_128(key, msg, strlen(vectors[v][0]) / 2, got);
		snprintf(what, sizeof(what), "RFC 4493 example %zu (%zu bytes)", v + 1, strlen(vectors[v][0]) / 2);
		check(what, !memcmp(got, want, 16));
	}

	srand(4493);
	for (size_t i = 0; i < (4 << 20); i++)
		big[i] = (uint8_t)rand();
	for (uint64_t len = 0; len <= 4096; len++) {
		for (int k = 0; k < 16; k++)
			key[k] = (uint8_t)rand();
		smb3_aes_cmac_128(key, big + (len % 7), len, got);
		reference_cmac(key, big + (len % 7), len, ref);
		bad += memcmp(got, ref, 16) != 0;
	}
	for (uint64_t len = 1 << 20; len <= (4u << 20) - 64; len += 1048573) {
		smb3_aes_cmac_128(key, big, len, got);
		reference_cmac(key, big, len, ref);
		bad += memcmp(got, ref, 16) != 0;
	}
	check("the same MAC as the portable code, 4097 lengths and 3 large messages", bad == 0);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (int r = 0; r < 16; r++)
		smb3_aes_cmac_128(key, big, 4 << 20, got);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	printf("     speed: %.0f MB/s\n", 64.0 * 1048576 / secs / 1e6);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	reference_cmac(key, big, 4 << 20, ref);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	printf("     the portable code: %.1f MB/s\n", 4.0 * 1048576 / secs / 1e6);
	free(big);
	printf("%s\n", failures ? "SOME FAILED" : "all passed");
	return failures != 0;
}
