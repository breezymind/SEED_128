#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "seedcbc.h"

#define BUF_SIZE 10240

void hello_world_print(); /* CHER-3 HelloWorld 출력 */
int print_encryptdata(int plaintext_len, int after_encrypt_len, unsigned char plaintext[], unsigned char ciphertext[], unsigned char *str, int size);
int print_decryptdata(int after_decrypt_len, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size);

int main(){

	/* 대칭키와 IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	
	/* 입출력 버퍼 */
	unsigned char plaintext[BUF_SIZE] = "\0";
	unsigned char ciphertext[BUF_SIZE+16] = "\0";
	/* 복호화에 사용될 평문출력버퍼 */
	unsigned char after_decrypt_plaintext[BUF_SIZE] = "\0";

	int after_decrypt_len = 0; /* 복호화 후 데이터 길이 */
	int after_encrypt_len = 0; /* 암호화 후 데이터 길이 */
	int plaintext_len = 0; /* 입력받은 plaintext의 길이 */
	unsigned char *str = NULL; /* str : base64 인코딩 후의 데이터 */
	unsigned char *dst = NULL; /* dst : base64 디코딩 후의 데이터 */
	int  size = 0;
	
	printf("\n\n---------------------------------암호화---------------------------------------------------\n\n");
	/* 암호화 시작 */
	printf("SEED 암호화할 데이터를 입력하세요: ");
	fgets((char *)plaintext, sizeof(plaintext), stdin); /* 암호화할 평문 사용자입력 */
	plaintext_len = strlen((char *)plaintext); /* 입력받은 평문의 길이 계산 */

	/* SEED-CBC 암호화 */
	after_encrypt_len = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_len, ciphertext);
	/* 암호화한 데이터를 Base64 인코딩 */
	str = __base64_encode((unsigned char *)ciphertext, after_encrypt_len, &size);
	/* 암호화 데이터 출력 */
	print_encryptdata(plaintext_len, after_encrypt_len, plaintext, ciphertext, str, size);
	
	printf("\n\n---------------------------------복호화---------------------------------------------------\n\n");
	/* 암호화한 데이터를 Base64 디코딩 */
	dst = __base64_decode(str, strlen((char *)str), &size);
	/* SEED-CBC 복호화 */
	after_decrypt_len = KISA_SEED_CBC_DECRYPT(key, iv, dst, size, after_decrypt_plaintext);
	/* 복호화 데이터 출력 */
	print_decryptdata(after_decrypt_len, after_decrypt_plaintext, dst, size);
	
	free(str);
	free(dst);

	hello_world_print();
	return 0;
}

void hello_world_print(){
	printf("HelloWorld\n");
}

int print_encryptdata(int plaintext_len, int after_encrypt_len, unsigned char plaintext[], unsigned char ciphertext[], unsigned char *str, int size){
	int i = 0;

	printf("\n평문: ");
	for (i = 0; i < plaintext_len; i++)
		printf("%c", plaintext[i]);
	printf("\n암호화 전 데이터 길이: %d\n", plaintext_len);
	
	printf("\n암호문: %s\n", ciphertext);
	printf("\n암호문(16진수): ");
	for (i = 0; i < after_encrypt_len; i++)
		printf("%02X ", ciphertext[i]);

	printf("\n\n암호화 후 데이터 길이: %d\n", after_encrypt_len);

	printf("\n인코딩 후 데이터: %s\n\n인코딩 후 데이터 길이: %d\n", str, size);
	
	return 0;
}

int print_decryptdata(int after_decrypt_len, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size){
	int i = 0;

	printf("\n디코딩 후 데이터: %s\n\n디코딩 후 데이터 길이: %d\n", dst, size);

	printf("\n복호화된 평문: ");
	for (i = 0; i < after_decrypt_len; i++)
		printf("%c", after_decrypt_plaintext[i]);
	printf("\n복호화 후 데이터 길이: %d\n", after_decrypt_len);
	printf("\n");

	return 0;
}