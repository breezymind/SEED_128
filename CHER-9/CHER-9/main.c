#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Winsock2.h>

#include "b64.h"
#include "seedcbc.h"

#define BUF_SIZE 10240
#define SERVER_IP "172.16.10.141"
#define PORT_NUM 5005

void hello_world_print();
int print_encryptdata(int plaintext_length, int cipherlen, unsigned char plaintext[], unsigned char ciphertext[], unsigned char *str, int size);
int print_decryptdata(int plainlen, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size);
void error_handling(char *msg);

int main(){

	/* ��ĪŰ�� IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	
	/* ����� ���� */
	unsigned char plaintext[BUF_SIZE] = "\0";
	unsigned char ciphertext[BUF_SIZE+16] = "\0";

	unsigned char after_decrypt_plaintext[BUF_SIZE] = "\0"; /* ��ȣȭ�� ���� ����¹��� */
	unsigned char server_text[BUF_SIZE] = "\0";
	int server_text_length = 0;

	int plainlen = 0; /* ��ȣȭ �� ������ ���� */
	int cipherlen = 0; /* ��ȣȭ �� ������ ���� */
	int plaintext_length = 0; /* �Է¹��� plaintext�� ���� */
	
	/*
	* str : base64 ���ڵ� ���� ������
	* dst : base64 ���ڵ� ���� ������
	*/
	unsigned char *str = '\0';
	unsigned char *dst = '\0';
	int  size = 0;
	char  exit_str[7] = "\0";
	WSADATA wsaData;
	SOCKET connect_sock;
	SOCKADDR_IN connect_addr;

	/*
	* ���� ���̺귯�� �ʱ�ȭ
	* 2.2������ winsock���
	*/
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		error_handling("WSAStartup() Error");
	}
	printf("socket ���̺귯�� �ʱ�ȭ\n");
	/* ������ ������ SOCKET ����ü�� ����*/
	connect_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(connect_sock == INVALID_SOCKET){
		error_handling("socket() Error");
	}
	printf("socket ����\n");
	memset(&connect_addr, 0, sizeof(connect_addr));
	connect_addr.sin_family = AF_INET; /* Internet Protocol Version(IPv4) */
	connect_addr.sin_addr.s_addr = inet_addr(SERVER_IP); /* IP�ּ� ���� */
	connect_addr.sin_port = htons(PORT_NUM); /* port��ȣ ���� */
	
	printf("������...\n");
	/* ����ü�� ����� �ּҷ� connect_sock ������ ���� ���� �õ� */
	if(connect(connect_sock, (SOCKADDR*)&connect_addr, sizeof(connect_addr)) == SOCKET_ERROR){
		printf("Err_No: %d\n", WSAGetLastError());
		error_handling("connect() Error");
	}
	printf("���Ἲ��\n");

	while(1){
		memset(&exit_str, 0, sizeof(exit_str));
		memset(&server_text, 0, sizeof(server_text));
		/* ��ȣȭ ���� */
		printf("SEED ��ȣȭ�� �����͸� �Է��ϼ���: ");
		fgets((char *)plaintext, sizeof(plaintext), stdin); /* ��ȣȭ�� �� ������Է� */
		plaintext_length = strlen((char *)plaintext); /* �Է¹��� ���� ���� ��� */

		if(plaintext_length == 5){
			strncpy(exit_str, (char *)plaintext, 4);
			exit_str[5] = '\0';
		}
		/* �Է¹��� �����Ͱ� exit�� ���� */
		if(strcmp(exit_str, "exit") == 0){
			send(connect_sock, exit_str, strlen(exit_str), 0);
			break;
		}
		/* SEED-CBC ��ȣȭ */
		cipherlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_length, ciphertext);
		/* ��ȣȭ�� �����͸� Base64 ���ڵ� */
		str = __base64_encode((unsigned char *)ciphertext, cipherlen, &size);
		/* ������ ��ȣȭ�� ������ ���� */
		send(connect_sock, (const char *)str, size, 0);
		printf("��ȣȭ ������ ���ۼ���\n");

		/* �����κ��� ���۵Ǵ� ������ ���� */
		server_text_length = recv(connect_sock, (char *)server_text, sizeof(server_text) - 1, 0);
		if(server_text_length == -1){
			error_handling("read() error");
		}
		printf("�����κ��� ���� ������: %s", server_text);
		
		/* �����κ��� ���� ��ȣȭ �����͸� Base64 ���ڵ� */
		dst = __base64_decode(server_text, strlen((char *)server_text), &size);
		/* SEED-CBC ��ȣȭ */
		plainlen = KISA_SEED_CBC_DECRYPT(key, iv, dst, size, after_decrypt_plaintext);
		/* ��ȣȭ ������ ��� */
		print_decryptdata(plainlen, after_decrypt_plaintext, dst, size);
		free(str);
		free(dst);
		
		printf("--------------------------------------------------------------\n");
	}
	printf("��������\n");
	closesocket(connect_sock); /* ���� �ݱ� */
	WSACleanup();/* winsock ���� */
	//hello_world_print();
	return ;
}

/* 
* CHER-3
* HelloWorld ���
*/
void hello_world_print(){
	printf("HelloWorld\n");
}

int print_encryptdata(int plaintext_length, int cipherlen, unsigned char plaintext[], unsigned char ciphertext[], unsigned char *str, int size){
	int i = 0;

	printf("\n��: ");
	for (i = 0; i < plaintext_length; i++)
		printf("%c", plaintext[i]);
	printf("\n��ȣȭ �� ������ ����: %d\n", plaintext_length);
	
	printf("\n��ȣ��: %s\n", ciphertext);
	printf("\n��ȣ��(16����): ");
	for (i = 0; i < cipherlen; i++)
		printf("%02X ", ciphertext[i]);

	printf("\n\n��ȣȭ �� ������ ����: %d\n", cipherlen);

	printf("\n���ڵ� �� ������: %s\n\n���ڵ� �� ������ ����: %d\n", str, size);
	
	return 0;
}

int print_decryptdata(int plainlen, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size){
	int i = 0;

	//printf("\n���ڵ� �� ������: %s\n\n���ڵ� �� ������ ����: %d\n", dst, size);

	printf("\n������ ��ȣȭ ���: ");
	for (i = 0; i < plainlen; i++)
		printf("%c", after_decrypt_plaintext[i]);
	//printf("\n��ȣȭ �� ������ ����: %d\n", plainlen);
	printf("\n");

	return 0;
}

void error_handling(char *msg){
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}