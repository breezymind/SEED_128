#include <stdlib.h>
#include <string.h>
#include "b64.h"

static char __base64_pad = '=';

/*
str: 인코딩할 데이터, 
length: 인코딩을 위한 데이터의 크기, 
ret_length: 인코딩 결과 나온 데이터의 크기 
*/

unsigned char *__base64_encode(const unsigned char *str, int length, int *ret_length) {
	const unsigned char *current = str;
	int i = 0;
	unsigned char *result = (unsigned char *)malloc(((length + 3 - length % 3) * 4 / 3 + 1) * sizeof(char));

	while (length > 2) { /* keep going until we have less than 24 bits */
		/* 비트 연산을 통해 4개의 문자로 확장시킨다. */
		result[i++] = __base64_table[current[0] >> 2]; // 오른쪽으로 2bit 이동(6비트씩)
		result[i++] = __base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		result[i++] = __base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		result[i++] = __base64_table[current[2] & 0x3f];

		current += 3;
		length -= 3; /* we just handle 3 octets of data */
	}

	/* now deal with the tail end of things */
	if (length != 0) {
		result[i++] = __base64_table[current[0] >> 2];
		if (length > 1) {
			result[i++] = __base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			result[i++] = __base64_table[(current[1] & 0x0f) << 2];
			result[i++] = __base64_pad;
		}
		else {
			result[i++] = __base64_table[(current[0] & 0x03) << 4];
			result[i++] = __base64_pad;
			result[i++] = __base64_pad;
		}
	}
	if (ret_length) {
		*ret_length = i;
	}
	result[i] = '\0';
	return result;
}

/* as above, but backwards. :) */
unsigned char *__base64_decode(const unsigned char *str, int length, int *ret_length) {
	const unsigned char *current = str;
	int ch, i = 0, j = 0, k;
	/* this sucks for threaded environments */
	static short reverse_table[256];
	static int table_built;
	unsigned char *result;

	if (++table_built == 1) {
		char *chp;
		for (ch = 0; ch < 256; ch++) {
			chp = strchr(__base64_table, ch); // base64_table에서 ch의 위치를 찾는다.
			if (chp) {
				reverse_table[ch] = chp - __base64_table;
			}
			else {
				reverse_table[ch] = -1;
			}
		}
	}

	result = (unsigned char *)malloc(length + 1);
	if (result == NULL) {
		return NULL;
	}

	/* run through the whole string, converting as we go */
	while ((ch = *current++) != '\0') {
		if (ch == __base64_pad) break;

		/* When Base64 gets POSTed, all pluses are interpreted as spaces.
		This line changes them back.  It's not exactly the Base64 spec,
		but it is completely compatible with it (the spec says that
		spaces are invalid).  This will also save many people considerable
		headache.  - Turadg Aleahmad <turadg@wise.berkeley.edu>
		*/

		if (ch == ' ') ch = '+';

		ch = reverse_table[ch];
		if (ch < 0) continue;

		switch (i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >> 2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
		i++;
	}

	k = j;
	/* mop things up if we ended on a boundary */
	if (ch == __base64_pad) {
		switch (i % 4) {
		case 0:
		case 1:
			free(result);
			return NULL;
		case 2:
			k++;
		case 3:
			result[k++] = 0;
		}
	}
	if (ret_length) {
		*ret_length = j;
	}
	result[k] = '\0';
	return result;
}