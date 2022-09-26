#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const char* filename = "./BL2/BL2";

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

    // // SHA-256 시작
    // unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    // /*
    //     unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
    // */
    // SHA256(file_contents, sb.st_size, digest);

    // // printf("입력값 : ");
    // // for (int i = 0; i < sb.st_size; i++)
    // // {
    // //     printf("%x", file_contents[i]);
    // // }
    // printf("\n입력 파일 크기 : %lld", sb.st_size);
    // printf("\n");

    unsigned char hash_value[SHA256_DIGEST_LENGTH] = {0x0B, 0x6C, 0xF8, 0xFF, 0xC3, 0x76, 0x75, 0xA5, 0xA9, 0x5B, 0x79, 0x01, 0x64, 0x15, 0xED, 0xD2, 0xC8, 0x71, 0x79, 0x9A, 0x2C, 0xA1, 0x54, 0x86, 0xB9, 0xFC, 0x22, 0xC9, 0xE1, 0xA6, 0x8B, 0x7D};

    unsigned char temp = 0x00;

    // to little endian
    for (int i = 0; i < 32; i += 4)
    {
        for (int j = 0; j < 2; j++)
        {
            temp = hash_value[i+j];
            hash_value[i+j] = hash_value[i+(3-j)];
            hash_value[i+(3-j)] = temp;
        }
    }

    printf("해시값 : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02X ", hash_value[i]);
    }
    printf("\n");

    // RSA 시작
    unsigned char cipher_text[256]; // 암호화된 데이터가 들어갈 배열
    unsigned char plain_text_receiver[256]; // cipher_text를 복호화한 데이터

    // // BIGNUM 구조체 생성
    // BIGNUM *bne = BN_new();
    // if(bne == NULL)
    // {
    //     printf("BIGNUM 구조체 생성 실패\n");
    //     return 0;
    // }

    // // BIGNUM 구조체 값 할당
    // if(BN_set_word(bne, RSA_F4) != 1)
    // {
    //     printf("BIGNUM 구조체에 값 할당 실패\n");
    //     return 0;
    // }

    // // RSA 구조체 생성
    // RSA *key_pair = RSA_new();
    // if(key_pair == NULL)
    // {
    //     printf("RSA 구조체 생성 실패\n");
    //     return 0;
    // }

    // // 공용키, 개인키 생성
    // if(RSA_generate_key_ex(key_pair, 2048, bne, NULL) != 1)
    // {
    //     printf("RSA 키 생성 실패\n");
    //     return 0;
    // }

    // RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u);
    // 마지막 두 인수는 파일에 비밀번호가 걸려있을 때만 해당
    FILE *privfp = fopen("private_key.pem", "r");
    RSA *rsa_pri = PEM_read_RSAPrivateKey(privfp, NULL, NULL, NULL);

    // FILE *pubfp = fopen("public_key.pem", "r");
    // RSA *rsa_pub = PEM_read_RSA_PUBKEY(pubfp, NULL, NULL, NULL);

    // 키 유효성 검사
    if(RSA_check_key(rsa_pri) != 1)
    {
        printf("유효하지 않은 RSA Private 키\n");
        return 0;
    }

    // if(RSA_check_key(rsa_pub) != 1)
    // {
    //     printf("유효하지 않은 RSA Public 키\n");
    //     return 0;
    // }

    /*
    ※ 주의 ※
    RSA_public_encrypt, RSA_private_decrypt = deprecated
    Applications should instead use 
    EVP_PKEY_encrypt_init_ex, EVP_PKEY_encrypt, EVP_PKEY_decrypt_init_ex and EVP_PKEY_decrypt.
    */

    // 암호화 과정
    printf("\n");
    printf("[DEBUG] sizeof(digest) = %lu\n", sizeof(hash_value));
    printf("[DEBUG] RSA_size(rsa_pri) = %d\n", RSA_size(rsa_pri));

    unsigned char digest_padded[256] = {0, };

    for (int k = 0; k < 32; k++)
    {
        digest_padded[k+4] = hash_value[k];
    }

    printf("\n");
    for (int j = 0; j < 256; j++)
    {
        printf("%02X ", digest_padded[j]);
    }
    printf("\n");

    unsigned int num;
    // num = RSA_public_encrypt(sizeof(hash_value), hash_value, cipher_text, rsa_pri, RSA_NO_PADDING);
    // printf("\n해시값 -> 암호문 : ");
    // for (int i = 0; i < 256; i++)
    // {
    //     printf("%02X ", cipher_text[i]);
    // }
    printf("\n");

    num = RSA_public_encrypt(RSA_size(rsa_pri), digest_padded, cipher_text, rsa_pri, RSA_NO_PADDING);
    printf("\n해시값 -> 암호문 : \n");
    for (int i = 0; i < 256; i++)
    {
        printf("%02X ", cipher_text[i]);
    }
    printf("\n");

    // // 복호화 과정
    // num = RSA_private_decrypt(num, cipher_text, plain_text_receiver, key_pair, RSA_PKCS1_PADDING);

    // printf("\n\n[DEBUG] num = %d\n\n", num);

    // plain_text_receiver[num] = '\0';
    // printf("\n복호화된 데이터 : ");
    // for (int i = 0; plain_text_receiver[i] != '\0'; i++)
    // {
    //     printf("%x", plain_text_receiver[i]);
    // }
    // printf("\n");

    printf("\n...프로그램 종료...\n\n");
    // 구조체 메모리 해제
    // RSA_free(key_pair);
    // BN_free(bne);    
    fclose(in_file);
    free(file_contents);
    exit(EXIT_SUCCESS);
    return 0;
}