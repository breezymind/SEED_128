SEED_128
===================

SEED 알고리즘을 사용한 데이터 암복호화 

----------


목표
-------------

> - string과 binary에 대한 개념 정립
> -  string과 binary의 변환
> - 간단한 TCP 통신 경험으로 길이의 중요성
> - encode / decode 개념 정립
> - 보안 채널 개발 경험
> - 네이티브 개발 환경 경험

개발환경
-------------

> - C
> -  SEED ( http://seed.kisa.or.kr/ )

----------


#### <i class="icon-pencil"></i> 1단계. Hello World 출력
console 창에 Hello World라는 문장을 출력해본다.

#### <i class="icon-pencil"></i> 2단계. encode / decode
Base64를 이용해 데이터를 encode / decode 해본다.

#### <i class="icon-pencil"></i> 3단계. 대칭키 암복호
SEED 알고리즘을 이용해 데이터를 입력받아 암/복호화 해본다.
( SEED-128 64bit용 / CBC mode / PKCS7 padding )

    - Base64 encoding(대칭키 암호화(‘abc’)) => encryptData
    - 대칭키 복호화 (Base64 decoding(encryptData)) => ‘abc’

#### <i class="icon-pencil"></i> 4단계. TCP 통신
클라이언트 쪽에서 데이터를 암호화해 서버로 전송하면
서버 쪽에서는 암호화된 데이터를 복호화해 클라이언트에게 넘겨준다. (Winsock2 사용)
'exit'를 입력하면 프로그램이 종료된다.
