#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const char *fileName = "../sources/dummy";

int main()
{
    printf("\n... Start Signing Program ...\n\n");

    // Open a raw file
    FILE *pFile1 = fopen(fileName, "rb");
    if (!pFile1)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // Read data from the file
    // 'stat' is a Linux system call
    // If OS is window, use 'fseek' to get file size
    struct stat sb;
    if (stat(fileName, &sb) == -1)
    {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    char *fileData = malloc(sb.st_size); // st_size = total size in byte
    fread(fileData, sb.st_size, 1, pFile1);

    /* SHA-256 */

    // Hashing file
    unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    SHA256(fileData, sb.st_size, digest);

    printf("Hash Value of file data : \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02X ", digest[i]);
    }
    printf("\n");

    /* RSA-2048 */

    // Encrypt hash value
    unsigned char signature[256];

    // Get Alice's private key from PEM file
    FILE *pKey1 = fopen("../keys/Alice_private.pem", "rb");
    RSA *rsaPrivate = PEM_read_RSAPrivateKey(pKey1, NULL, NULL, NULL);

    // check if private key is vaild
    if (RSA_check_key(rsaPrivate) != 1)
    {
        printf("RSA private key is unvalid\n");
        return 0;
    }

    // Encryption with Alice's private key
    unsigned int num;
    num = RSA_private_encrypt(SHA256_DIGEST_LENGTH, digest, signature, rsaPrivate, RSA_PKCS1_PADDING);

    printf("\nsignature : \n");
    for (int i = 0; i < num; i++)
    {
        printf("%02X ", signature[i]);
    }
    printf("\n");

    FILE *pFile2;
    if ((pFile2 = fopen("signed_file", "wb")) == NULL)
    {
        perror("fopen");
        exit(1);
    }

    fwrite(signature, 1, num, pFile2);
    fwrite(fileData, 1, sb.st_size, pFile2);
    
    fclose(pFile1);
    fclose(pFile2);
    fclose(pKey1);
    free(fileData);

    printf("\n... End Signing Program ...\n\n");

    return 0;
}
