#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const char* filename = "./sources/dummy";

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
    // unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    /*
        unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
    */
    // SHA256(file_contents, sb.st_size, digest);

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
    unsigned char cipher_text[256];
    unsigned char plain_text[256];

    // RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u);
    // 마지막 두 인수는 파일에 비밀번호가 걸려있을 때만 해당
    FILE *privfp = fopen("private_key_1.pem", "r");
    RSA *rsa_pri = PEM_read_RSAPrivateKey(privfp, NULL, NULL, NULL);

    const BIGNUM *n = BN_new();
    const BIGNUM *e = BN_new();
    const BIGNUM *d = BN_new();
    char * n_str = NULL;
    char * e_str = NULL;
    char * d_str = NULL;

    RSA_get0_key(rsa_pri, &n, &e, &d);

    printf("\n");
    n_str = BN_bn2hex(n);
    printf("[DEBUG] n_str = %s\n", n_str);
    e_str = BN_bn2hex(e);
    printf("[DEBUG] e_str = %s\n", e_str);
    d_str = BN_bn2hex(d);
    printf("[DEBUG] d_str = %s\n", d_str);

    FILE *pubfp = fopen("public_key_1.pem", "r");
    RSA *rsa_pub = PEM_read_RSA_PUBKEY(pubfp, NULL, NULL, NULL);
    //RSA *rsa_pub = PEM_read_RSAPublicKey(pubfp, NULL, NULL, NULL);

    // RSA_get0_key(rsa_pub, &n, &e, &d);
    // printf("\n");
    // n_str = BN_bn2hex(n);
    // printf("[DEBUG] n_str = %s\n", n_str);
    // e_str = BN_bn2hex(e);
    // printf("[DEBUG] e_str = %s\n", e_str);

    // 키 유효성 검사
    if(RSA_check_key(rsa_pri) != 1)
    {
        // 아 RSA_check_key 함수는 개인키 전용 함수였음
        printf("유효하지 않은 RSA Private 키\n");
        return 0;
    }

    /*
    ※ 주의 ※
    RSA_public_encrypt, RSA_private_decrypt = deprecated
    Applications should instead use 
    EVP_PKEY_encrypt_init_ex, EVP_PKEY_encrypt, EVP_PKEY_decrypt_init_ex and EVP_PKEY_decrypt.
    */

    printf("\n");
    printf("[DEBUG] sizeof(digest) = %lu\n", sizeof(hash_value));
    printf("[DEBUG] RSA_size(rsa_pri) = %d\n", RSA_size(rsa_pri));

    // 자체 패딩
    unsigned char digest_padded[256] = {0, };
    for (int k = 0; k < 32; k++)
    {
        digest_padded[k+4] = hash_value[k];
    }

    printf("\n패딩된 해시값 :\n");
    for (int j = 0; j < 256; j++)
    {
        printf("%02X ", digest_padded[j]);
    }
    printf("\n");

    // 암호화 과정 (개인키)
    unsigned int num;
    num = RSA_private_encrypt(RSA_size(rsa_pri), digest_padded, cipher_text, rsa_pri, RSA_NO_PADDING);
    printf("\n해시값 -> 암호문 : \n");
    for (int i = 0; i < 256; i++)
    {
        printf("%02X ", cipher_text[i]);
    }
    printf("\n");

    // 복호화 과정 (공개키)
    num = RSA_public_decrypt(num, cipher_text, plain_text, rsa_pub, RSA_NO_PADDING);
    plain_text[num] = '\0';
    printf("\n암호문 -> 해시값 : \n");
    for (int i = 0; i < 256; i++)
    {
        printf("%02X ", plain_text[i]);
    }
    printf("\n");

    printf("\n...프로그램 종료...\n\n");
    fclose(in_file);
    free(file_contents);
    exit(EXIT_SUCCESS);
    return 0;
}
