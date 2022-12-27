#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const char *fileName = "";

int main()
{
    printf("\n... Start Verifying Program ...\n\n");
    // Open a file
    FILE *pFile = fopen(fileName, "rb");
    if (!pFile)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // Read data from the file
    // 'stat' <= Linux system call
    // If OS == window, use 'fseek' to get file size
    struct stat sb;
    if (stat(fileName, &sb) == -1)
    {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    char *fileData = malloc(sb.st_size); // st_size = total size in byte
    fread(fileData, sb.st_size, 1, pFile);

    /* SHA-256 */
    unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    SHA256(fileData, sb.st_size, digest);

    printf("Hash Value of file data : \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02X ", digest[i]);
    }
    printf("\n");

    /* RSA-2048 */
    unsigned char cipherText[256];
    unsigned char plainText[32];

    // Get Alice's private key from PEM file
    FILE *pKey1 = fopen("keys/private_key_1.pem", "rb");
    RSA *rsaPrivate = PEM_read_RSAPrivateKey(pKey1, NULL, NULL, NULL);

    // const BIGNUM *n = BN_new();
    // const BIGNUM *e = BN_new();
    // const BIGNUM *d = BN_new();
    // char * n_str = NULL;
    // char * e_str = NULL;
    // char * d_str = NULL;

    // RSA_get0_key(rsaPrivate, &n, &e, &d);

    // printf("\n");
    // n_str = BN_bn2hex(n);
    // printf("[DEBUG] n_str = %s\n", n_str);
    // e_str = BN_bn2hex(e);
    // printf("[DEBUG] e_str = %s\n", e_str);
    // d_str = BN_bn2hex(d);
    // printf("[DEBUG] d_str = %s\n", d_str);

    // Get Alice's public key from PEM file
    FILE *pKey2 = fopen("keys/public_key_1.pem", "rb");
    RSA *rsaPublic = PEM_read_RSA_PUBKEY(pKey2, NULL, NULL, NULL);

    // RSA_get0_key(rsa_pub, &n, &e, &d);
    // printf("\n");
    // n_str = BN_bn2hex(n);
    // printf("[DEBUG] n_str = %s\n", n_str);
    // e_str = BN_bn2hex(e);
    // printf("[DEBUG] e_str = %s\n", e_str);

    // check if private key is vaild
    if (RSA_check_key(rsaPrivate) != 1)
    {
        // 아 RSA_check_key 함수는 개인키 전용 함수였음
        printf("RSA private key is unvalid\n");
        return 0;
    }

    // Encryption with Alice's private key
    unsigned int num;
    num = RSA_private_encrypt(SHA256_DIGEST_LENGTH, digest, cipherText, rsaPrivate, RSA_PKCS1_PADDING);

    printf("\nCipher Text : \n");
    for (int i = 0; i < num; i++)
    {
        printf("%02X ", cipherText[i]);
    }
    printf("\n");

    // Decryption with Alice's public key
    num = RSA_public_decrypt(num, cipherText, plainText, rsaPublic, RSA_PKCS1_PADDING);

    printf("\nPlain Text : \n");
    for (int i = 0; i < num; i++)
    {
        printf("%02X ", plainText[i]);
    }
    printf("\n");

    fclose(pFile);
    fclose(pKey1);
    fclose(pKey2);
    free(fileData);

    printf("\n... End Verifying Program ...\n\n");

    return 0;
}
