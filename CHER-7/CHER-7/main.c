#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "seedcbc.h"

int main(){

	/* 대칭키와 IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	/* 입출력 버퍼 */
	unsigned char plaintext[128];
	/*unsigned char plaintext[128] = { 0xB4, 0x0D, 0x70, 0x03, 0xD9, 0xB6, 0x90, 0x4B, 0x35, 0x62, 0x27, 0x50, 0xC9, 0x1A, 0x24, 0x57, 0x5B, 0xB9, 
	0xA6, 0x32, 0x36, 0x4A, 0xA2, 0x6E, 0x3A, 0xC0, 0xCF, 0x3A, 0x9C, 0x9D, 0x0D, 0xCB };*/
	unsigned char ciphertext[144];

	/* 복호화에 사용될 평문출력버퍼 */
	unsigned char plaintext2[144];

	int plainlen; /* 암호화 후 암호문 길이 */
	int cipherlen; /* 복호화 후 평문 길이 */
	int i;
	int plaintext_length = 0; /* plaintext의 길이 */

	unsigned char *str, *dst;
	//char *source;
	int  size;

	
	/* HelloWorld 출력 */
	printf("HelloWorld\n");
	printf("\n----------------------------------암호화--------------------------------------------------\n\n");
	
	printf("SEED 암호화할 데이터를 입력하세요: ");
	fgets((char *)plaintext, sizeof(plaintext), stdin); /* 암호화할 평문 사용자입력 */
	plaintext_length = strlen((char *)plaintext); /* 입력받은 평문의 길이 계산 */
	
	/* SEED-CBC 암호화 */
	cipherlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_length, ciphertext);
	
	/* 암호화한 데이터를 Base64 인코딩 */
	str = __base64_encode((unsigned char *)ciphertext, cipherlen, &size);

	printf("평문: ");
	for (i = 0; i < plaintext_length; i++)
		printf("%c ", plaintext[i]);

	printf("\n암호문: %s\n", ciphertext);

	printf("인코딩한 데이터: %s\n인코딩 후 데이터 길이: %d\n", str, size);

	printf("\n\n---------------------------------복호화---------------------------------------------------\n\n");
	/* 암호화한 데이터를 Base64 디코딩 */
	dst = __base64_decode(str, strlen(str), &size);
	printf("디코딩한 데이터: %s\n디코딩 후 데이터 길이: %d\n", dst, size);

	/* SEED-CBC 복호화 */
	plainlen = KISA_SEED_CBC_DECRYPT(key, iv, dst, size, plaintext2);
	
	printf("복호화 되기 전의 암호문: %s\n", ciphertext);
	/*for (i = 0; i < cipherlen; i++)
		printf("%02X ", ciphertext[i]);*/

	printf("복호화된 평문: ");
	for (i = 0; i < plainlen; i++)
		printf("%c ", plaintext2[i]);
	printf("\n");

	free(str);
	free(dst);
}