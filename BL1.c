#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

const char* filename = "./BL2/BL2.c";

int main()
{
    // 파일로부터 데이터 읽기
    FILE* in_file = fopen(filename, "rb");
    if (!in_file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    struct stat sb;
    if (stat(filename, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    char* file_contents = malloc(sb.st_size); // st_size = total size in byte
    fread(file_contents, sb.st_size, 1, in_file);

    // SHA-256 시작
    unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    /*
        unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
    */
    SHA256(file_contents, sb.st_size, digest);

    printf("입력값 : ");
    for (int i = 0; i < sb.st_size; i++)
    {
        printf("%x", file_contents[i]);
    }
    printf("입력 파일 크기 : %ld", sb.st_size);
    printf("\n");

    printf("해시값 : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%x", digest[i]);
    }
    printf("\n");


    // RSA 시작
    unsigned char cipher_text[256]; // 암호화된 데이터가 들어갈 배열
    unsigned char plain_text_receiver[256]; // cipher_text를 복호화한 데이터

    // BIGNUM 구조체 생성
    BIGNUM *bne = BN_new();
    if(bne == NULL)
    {
        printf("BIGNUM 구조체 생성 실패\n");
        return 0;
    }

    // BIGNUM 구조체 값 할당
    if(BN_set_word(bne, RSA_F4) != 1)
    {
        printf("BIGNUM 구조체에 값 할당 실패\n");
        return 0;
    }

    // RSA 구조체 생성
    RSA *key_pair = RSA_new();
    if(key_pair == NULL)
    {
        printf("RSA 구조체 생성 실패\n");
        return 0;
    }

    // 공용키, 개인키 생성
    if(RSA_generate_key_ex(key_pair, 2048, bne, NULL) != 1)
    {
        printf("RSA 키 생성 실패\n");
        return 0;
    }

    // 키 유효성 검사
    if(RSA_check_key(key_pair) != 1)
    {
        printf("유효하지 않은 RSA 키\n");
        return 0;
    }

    /*
    ※ 주의 ※
    RSA_public_encrypt, RSA_private_decrypt = deprecated
    Applications should instead use 
    EVP_PKEY_encrypt_init_ex, EVP_PKEY_encrypt, EVP_PKEY_decrypt_init_ex and EVP_PKEY_decrypt.
    */

    // 암호화 과정
    unsigned int num;
    num = RSA_public_encrypt(sizeof(digest), digest, cipher_text, key_pair, RSA_PKCS1_PADDING);
    printf("\nsizeof(digest) = %ld", sizeof(digest));
    printf("\n암호화된 해시값 : ");
    for (int i = 0; i < 256; i++)
    {
        printf("%x", cipher_text[i]);
    }
    printf("\n");

    // 복호화 과정
    num = RSA_private_decrypt(num, cipher_text, plain_text_receiver, key_pair, RSA_PKCS1_PADDING);

    printf("\n\n[DEBUG] num = %d\n\n", num);

    plain_text_receiver[num] = '\0';
    printf("\n복호화된 데이터 : ");
    for (int i = 0; plain_text_receiver[i] != '\0'; i++)
    {
        printf("%x", plain_text_receiver[i]);
    }
    printf("\n");

    printf("\n...프로그램 종료...\n\n");
    // 구조체 메모리 해제
    RSA_free(key_pair);
    BN_free(bne);    
    fclose(in_file);
    free(file_contents);
    exit(EXIT_SUCCESS);
    return 0;
}