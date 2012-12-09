/* Program to brute-force RC4 40-bit keyspace by Dhiru Kholia.
 *
 * common_init is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "rc4.h"
#include <openssl/md5.h>
#include <omp.h>
#include <sys/time.h>
#include <time.h>

#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

char itoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
char atoi64[0x100];

char itoa16[16] =
	"0123456789abcdef";
char itoa16u[16] =
	"0123456789ABCDEF";
char atoi16[0x100];

static int initialized = 0;

void common_init(void)
{
	char *pos;

	if (initialized) return;

	memset(atoi64, 0x7F, sizeof(atoi64));
	for (pos = itoa64; pos <= &itoa64[63]; pos++)
		atoi64[ARCH_INDEX(*pos)] = pos - itoa64;

	memset(atoi16, 0x7F, sizeof(atoi16));
	for (pos = itoa16; pos <= &itoa16[15]; pos++)
		atoi16[ARCH_INDEX(*pos)] = pos - itoa16;

	atoi16['A'] = atoi16['a'];
	atoi16['B'] = atoi16['b'];
	atoi16['C'] = atoi16['c'];
	atoi16['D'] = atoi16['d'];
	atoi16['E'] = atoi16['e'];
	atoi16['F'] = atoi16['f'];

	initialized = 1;
}

int V;
int R;
int P;
char encrypt_metadata;
unsigned char u[127];
unsigned char o[127];
unsigned char id[32];
int length;
int length_id;
int length_u;
int length_o;

static const unsigned char padding[32] =
{
        0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
        0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
        0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
        0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
};

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

static inline void try_key(unsigned char *key)
{
	unsigned char output[32];
	RC4_KEY arc4;
	RC4_set_key(&arc4, 5, key);
	RC4(&arc4, 32, padding, output);

	if(memcmp(output, u, 32) == 0) {
		printf("Key is : " );
		print_hex(key, 5);
		exit(0);
	}
}


void keyspace_search()
{
	char buffer[30];
	struct timeval tv;
	time_t curtime;

	int i, j, k;
	int is = 0x00;
	int js = 0x00;
	int ks = 0x00;
	int ls = 0x00;
	int ms = 0x00;

	/* 9296c944ee is key for test.pdf */
	/* int is = 0x92;
	int js = 0x95;
	int ks = 0x00;
	int ls = 0x00;
	int ms = 0x00; */

	for(i = is; i <= 255; i++) { /* time = 256 * 2.23 * 256 seconds ~= 40.6 hours ~= 1.7 days days */
		for(j = js; j <= 255; j++) {
			/* takes 2.23 seconds on AMD FX-8120 (using all cores) for one tick */
			gettimeofday(&tv, NULL);
			curtime=tv.tv_sec;
			printf("%d %d @ ", i, j);
			strftime(buffer,30,"%m-%d-%Y  %T.",localtime(&curtime));
			printf("%s%ld\n",buffer,tv.tv_usec);
			fflush(stdout);
#pragma omp parallel for
			for(k = ks; k <= 255; k++) {
				int l, m;
				for(l = ls; l <= 255; l++) {
					for(m = ms; m <= 255; m++) {
						unsigned char hashBuf[5];
						hashBuf[0] = (char)i;
						hashBuf[1] = (char)j;
						hashBuf[2] = (char)k;
						hashBuf[3] = (char)l;
						hashBuf[4] = (char)m;
						try_key(hashBuf);
					}
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	int i;

	if(argc < 2) {
		fprintf(stderr, "Usage: %s <hash given by npdf2john program>\n\n", argv[0]);
		fprintf(stderr, "Example: %s \'test.pdf:$npdf$1*2*40*-4*1*16*c56bbc4145d25b468a873618cd71c2d3*32*bf38d7a59daaf38365a338e1fc07976102f1dfd6bdb52072032f57920109b43a*32*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499\'\n", argv[0]);
		exit(-1);
	}

	common_init();

	char *ctcopy = strdup(argv[1]);
	char *keeptr = ctcopy;
	char *p;
	ctcopy = strchr(ctcopy, ':') + 1 + 6; /* skip over filename and "$oldnpdf$" */
	p = strtok(ctcopy, "*");

	V = atoi(p);
	p = strtok(NULL, "*");
	R = atoi(p);
	if (!(R == 2)) {
		fprintf(stderr, "Only documents encrypted using RC4 40-bit are supported!\n");
		exit(-1);
	}
	p = strtok(NULL, "*");
	length = atoi(p);
	p = strtok(NULL, "*");
	P = atoi(p);
	p = strtok(NULL, "*");
	encrypt_metadata = atoi(p);
	p = strtok(NULL, "*");
	length_id = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < length_id; i++)
		id[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	length_u = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < length_u; i++)
		u[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	length_o = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < length_o; i++)
		o[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	free(keeptr);

	keyspace_search();

	return 0;
}
