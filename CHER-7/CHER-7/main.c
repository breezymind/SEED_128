#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "seedcbc.h"

#define BUF_SIZE 10240

void hello_world_print(); /* CHER-3 HelloWorld ��� */
int print_encryptdata(int plaintext_len, int after_encrypt_len, unsigned char plaintext[], unsigned char ciphertext[], unsigned char *str, int size);
int print_decryptdata(int after_decrypt_len, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size);

int main(){

	/* ��ĪŰ�� IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	
	/* ����� ���� */
	unsigned char plaintext[BUF_SIZE] = "\0";
	unsigned char ciphertext[BUF_SIZE+16] = "\0";
	/* ��ȣȭ�� ���� ����¹��� */
	unsigned char after_decrypt_plaintext[BUF_SIZE] = "\0";

	int after_decrypt_len = 0; /* ��ȣȭ �� ������ ���� */
	int after_encrypt_len = 0; /* ��ȣȭ �� ������ ���� */
	int plaintext_len = 0; /* �Է¹��� plaintext�� ���� */
	unsigned char *str = NULL; /* str : base64 ���ڵ� ���� ������ */
	unsigned char *dst = NULL; /* dst : base64 ���ڵ� ���� ������ */
	int  size = 0;
	
	printf("\n\n---------------------------------��ȣȭ---------------------------------------------------\n\n");
	/* ��ȣȭ ���� */
	printf("SEED ��ȣȭ�� �����͸� �Է��ϼ���: ");
	fgets((char *)plaintext, sizeof(plaintext), stdin); /* ��ȣȭ�� �� ������Է� */
	plaintext_len = strlen((char *)plaintext); /* �Է¹��� ���� ���� ��� */

	/* SEED-CBC ��ȣȭ */
	after_encrypt_len = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_len, ciphertext);
	/* ��ȣȭ�� �����͸� Base64 ���ڵ� */
	str = __base64_encode((unsigned char *)ciphertext, after_encrypt_len, &size);
	/* ��ȣȭ ������ ��� */
	print_encryptdata(plaintext_len, after_encrypt_len, plaintext, ciphertext, str, size);
	
	printf("\n\n---------------------------------��ȣȭ---------------------------------------------------\n\n");
	/* ��ȣȭ�� �����͸� Base64 ���ڵ� */
	dst = __base64_decode(str, strlen((char *)str), &size);
	/* SEED-CBC ��ȣȭ */
	after_decrypt_len = KISA_SEED_CBC_DECRYPT(key, iv, dst, size, after_decrypt_plaintext);
	/* ��ȣȭ ������ ��� */
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

	printf("\n��: ");
	for (i = 0; i < plaintext_len; i++)
		printf("%c", plaintext[i]);
	printf("\n��ȣȭ �� ������ ����: %d\n", plaintext_len);
	
	printf("\n��ȣ��: %s\n", ciphertext);
	printf("\n��ȣ��(16����): ");
	for (i = 0; i < after_encrypt_len; i++)
		printf("%02X ", ciphertext[i]);

	printf("\n\n��ȣȭ �� ������ ����: %d\n", after_encrypt_len);

	printf("\n���ڵ� �� ������: %s\n\n���ڵ� �� ������ ����: %d\n", str, size);
	
	return 0;
}

int print_decryptdata(int after_decrypt_len, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size){
	int i = 0;

	printf("\n���ڵ� �� ������: %s\n\n���ڵ� �� ������ ����: %d\n", dst, size);

	printf("\n��ȣȭ�� ��: ");
	for (i = 0; i < after_decrypt_len; i++)
		printf("%c", after_decrypt_plaintext[i]);
	printf("\n��ȣȭ �� ������ ����: %d\n", after_decrypt_len);
	printf("\n");

	return 0;
}