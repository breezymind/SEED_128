#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "seedcbc.h"

int main(){

	/* ��ĪŰ�� IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	/* ����� ���� */
	unsigned char plaintext[128];
	/*unsigned char plaintext[128] = { 0xB4, 0x0D, 0x70, 0x03, 0xD9, 0xB6, 0x90, 0x4B, 0x35, 0x62, 0x27, 0x50, 0xC9, 0x1A, 0x24, 0x57, 0x5B, 0xB9, 
	0xA6, 0x32, 0x36, 0x4A, 0xA2, 0x6E, 0x3A, 0xC0, 0xCF, 0x3A, 0x9C, 0x9D, 0x0D, 0xCB };*/
	unsigned char ciphertext[144];

	/* ��ȣȭ�� ���� ����¹��� */
	unsigned char plaintext2[144];

	int plainlen;
	int cipherlen;
	int i;
	int plaintext_length = 0; // ��plaintext�� ����

	unsigned char *str, *dst;
	//char *source;
	int  size;

	
	/* HelloWorld ��� */
	printf("HelloWorld\n");
	printf("------------------------------------------------------------------------------------\n");
	
	printf("SEED ��ȣȭ�� �����͸� �Է��ϼ���: ");
	scanf("%128s", plaintext); /* ��ȣȭ�� �� ������Է� */
	plaintext_length = strlen((char *)plaintext); /* �Է¹��� ���� ���� ��� */
	
	/* SEED-CBC ��ȣȭ */
	cipherlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_length, ciphertext);
	printf("��ȣȭ ����\n");

	/* ��ȣȭ�� �����͸� Base64 ���ڵ� */
	str = __base64_encode((unsigned char *)plaintext, plaintext_length, &size);
	printf("���ڵ��� ������: %s\n���ڵ� �� ������ ����: %d\n", str, size);

	printf("��: ");
	for (i = 0; i < plaintext_length; i++)
		printf("%02X ", plaintext[i]);

	printf("\n��ȣ��: %s", ciphertext);
	/*for (i = 0; i < cipherlen; i++)
		printf("%02X ", ciphertext[i]);*/
	printf("\n------------------------------------------------------------------------------------\n");

	dst = __base64_decode(str, strlen(str), &size);
	printf("���ڵ��� ������: %s\n���ڵ� �� ������ ����: %d\n", dst, size);
	
	free(str);
	free(dst);

	/* SEED-CBC ��ȣȭ */
	plainlen = KISA_SEED_CBC_DECRYPT(key, iv, dst, cipherlen, plaintext2);

	printf("��ȣȭ ����\n");
	printf("��ȣ��: ");
	for (i = 0; i < cipherlen; i++)
		printf("%02X ", ciphertext[i]);

	printf("\n��: ");
	for (i = 0; i < plainlen; i++)
		printf("%02X ", plaintext2[i]);
	printf("\n------------------------------------------------------------------------------------\n");
}