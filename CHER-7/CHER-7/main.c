#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "seedcbc.h"

void hello_world_print(){
	/* 
	* CHER-3
	* HelloWorld ���
	*/
	printf("HelloWorld\n");
}

int main(){

	/* ��ĪŰ�� IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	
	/* ����� ���� */
	unsigned char plaintext[1024] = "\0";
	unsigned char ciphertext[1040] = "\0";

	/* ��ȣȭ�� ���� ����¹��� */
	unsigned char after_decrypt_plaintext[1040] = "\0";

	int plainlen = 0; /* ��ȣȭ �� ��ȣ�� ���� */
	int cipherlen = 0; /* ��ȣȭ �� �� ���� */
	int i = 0;
	int plaintext_length = 0; /* plaintext�� ���� */
	
	/*
	* str : base64 ���ڵ� ���� ������,   
	* dst : base64 ���ڵ� ���� ������
	*/
	unsigned char *str, *dst;
	int  size = 0;

	hello_world_print();
	
	printf("\n----------------------------------��ȣȭ--------------------------------------------------\n\n");
	
	printf("SEED ��ȣȭ�� �����͸� �Է��ϼ���: ");
	fgets((char *)plaintext, sizeof(plaintext), stdin); /* ��ȣȭ�� �� ������Է� */
	plaintext_length = strlen((char *)plaintext); /* �Է¹��� ���� ���� ��� */
	
	/* SEED-CBC ��ȣȭ */
	cipherlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_length, ciphertext);
	
	/* ��ȣȭ�� �����͸� Base64 ���ڵ� */
	str = __base64_encode((unsigned char *)ciphertext, cipherlen, &size);

	printf("\n��: ");
	for (i = 0; i < plaintext_length; i++)
		printf("%c", plaintext[i]);

	printf("\n��ȣ��: %s\n", ciphertext);

	printf("\n���ڵ��� ������: %s\n\n���ڵ� �� ������ ����: %d\n", str, size);

	printf("\n\n---------------------------------��ȣȭ---------------------------------------------------\n\n");
	/* ��ȣȭ�� �����͸� Base64 ���ڵ� */
	dst = __base64_decode(str, strlen(str), &size);
	printf("\n���ڵ��� ������: %s\n\n���ڵ� �� ������ ����: %d\n", dst, size);

	/* SEED-CBC ��ȣȭ */
	plainlen = KISA_SEED_CBC_DECRYPT(key, iv, dst, size, after_decrypt_plaintext);
	
	printf("\n��ȣȭ �Ǳ� ���� ��ȣ��: %s\n", ciphertext);
	/*for (i = 0; i < cipherlen; i++)
		printf("%02X ", ciphertext[i]);*/

	printf("\n��ȣȭ�� ��: ");
	for (i = 0; i < plainlen; i++)
		printf("%c", after_decrypt_plaintext[i]);
	printf("\n");

	free(str);
	free(dst);
}