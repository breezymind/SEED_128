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

	/* 대칭키와 IV */
	unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	
	/* 입출력 버퍼 */
	unsigned char plaintext[BUF_SIZE] = "\0";
	unsigned char ciphertext[BUF_SIZE+16] = "\0";

	unsigned char after_decrypt_plaintext[BUF_SIZE] = "\0"; /* 복호화에 사용될 평문출력버퍼 */
	unsigned char server_text[BUF_SIZE] = "\0";
	int server_text_length = 0;

	int plainlen = 0; /* 복호화 후 데이터 길이 */
	int cipherlen = 0; /* 암호화 후 데이터 길이 */
	int plaintext_length = 0; /* 입력받은 plaintext의 길이 */
	
	/*
	* str : base64 인코딩 후의 데이터
	* dst : base64 디코딩 후의 데이터
	*/
	unsigned char *str = '\0';
	unsigned char *dst = '\0';
	int  size = 0;
	char  exit_str[7] = "\0";
	WSADATA wsaData;
	SOCKET connect_sock;
	SOCKADDR_IN connect_addr;

	/*
	* 소켓 라이브러리 초기화
	* 2.2버전의 winsock사용
	*/
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		error_handling("WSAStartup() Error");
	}
	printf("socket 라이브러리 초기화\n");
	/* 소켓을 생성해 SOCKET 구조체에 대입*/
	connect_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(connect_sock == INVALID_SOCKET){
		error_handling("socket() Error");
	}
	printf("socket 생성\n");
	memset(&connect_addr, 0, sizeof(connect_addr));
	connect_addr.sin_family = AF_INET; /* Internet Protocol Version(IPv4) */
	connect_addr.sin_addr.s_addr = inet_addr(SERVER_IP); /* IP주소 저장 */
	connect_addr.sin_port = htons(PORT_NUM); /* port번호 저장 */
	
	printf("연결중...\n");
	/* 구조체에 저장된 주소로 connect_sock 소켓을 통해 접속 시도 */
	if(connect(connect_sock, (SOCKADDR*)&connect_addr, sizeof(connect_addr)) == SOCKET_ERROR){
		printf("Err_No: %d\n", WSAGetLastError());
		error_handling("connect() Error");
	}
	printf("연결성공\n");

	while(1){
		memset(&exit_str, 0, sizeof(exit_str));
		memset(&server_text, 0, sizeof(server_text));
		/* 암호화 시작 */
		printf("SEED 암호화할 데이터를 입력하세요: ");
		fgets((char *)plaintext, sizeof(plaintext), stdin); /* 암호화할 평문 사용자입력 */
		plaintext_length = strlen((char *)plaintext); /* 입력받은 평문의 길이 계산 */

		if(plaintext_length == 5){
			strncpy(exit_str, (char *)plaintext, 4);
			exit_str[5] = '\0';
		}
		/* 입력받은 데이터가 exit면 종료 */
		if(strcmp(exit_str, "exit") == 0){
			send(connect_sock, exit_str, strlen(exit_str), 0);
			break;
		}
		/* SEED-CBC 암호화 */
		cipherlen = KISA_SEED_CBC_ENCRYPT(key, iv, plaintext, plaintext_length, ciphertext);
		/* 암호화한 데이터를 Base64 인코딩 */
		str = __base64_encode((unsigned char *)ciphertext, cipherlen, &size);
		/* 서버로 암호화한 데이터 전송 */
		send(connect_sock, (const char *)str, size, 0);
		printf("암호화 데이터 전송성공\n");

		/* 서버로부터 전송되는 데이터 수신 */
		server_text_length = recv(connect_sock, (char *)server_text, sizeof(server_text) - 1, 0);
		if(server_text_length == -1){
			error_handling("read() error");
		}
		printf("서버로부터 받은 데이터: %s", server_text);
		
		/* 서버로부터 받은 암호화 데이터를 Base64 디코딩 */
		dst = __base64_decode(server_text, strlen((char *)server_text), &size);
		/* SEED-CBC 복호화 */
		plainlen = KISA_SEED_CBC_DECRYPT(key, iv, dst, size, after_decrypt_plaintext);
		/* 복호화 데이터 출력 */
		print_decryptdata(plainlen, after_decrypt_plaintext, dst, size);
		free(str);
		free(dst);
		
		printf("--------------------------------------------------------------\n");
	}
	printf("연결종료\n");
	closesocket(connect_sock); /* 소켓 닫기 */
	WSACleanup();/* winsock 해제 */
	//hello_world_print();
	return ;
}

/* 
* CHER-3
* HelloWorld 출력
*/
void hello_world_print(){
	printf("HelloWorld\n");
}

int print_encryptdata(int plaintext_length, int cipherlen, unsigned char plaintext[], unsigned char ciphertext[], unsigned char *str, int size){
	int i = 0;

	printf("\n평문: ");
	for (i = 0; i < plaintext_length; i++)
		printf("%c", plaintext[i]);
	printf("\n암호화 전 데이터 길이: %d\n", plaintext_length);
	
	printf("\n암호문: %s\n", ciphertext);
	printf("\n암호문(16진수): ");
	for (i = 0; i < cipherlen; i++)
		printf("%02X ", ciphertext[i]);

	printf("\n\n암호화 후 데이터 길이: %d\n", cipherlen);

	printf("\n인코딩 후 데이터: %s\n\n인코딩 후 데이터 길이: %d\n", str, size);
	
	return 0;
}

int print_decryptdata(int plainlen, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size){
	int i = 0;

	//printf("\n디코딩 후 데이터: %s\n\n디코딩 후 데이터 길이: %d\n", dst, size);

	printf("\n데이터 복호화 결과: ");
	for (i = 0; i < plainlen; i++)
		printf("%c", after_decrypt_plaintext[i]);
	//printf("\n복호화 후 데이터 길이: %d\n", plainlen);
	printf("\n");

	return 0;
}

void error_handling(char *msg){
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}