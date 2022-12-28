#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const char *fileName = "../Alice/signed_file";

int main()
{
    printf("\n... Start Verifying Program ...\n\n");
    // Open a file
    FILE *pFile1 = fopen(fileName, "rb");
    if (!pFile1)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // Read signature and data from the file
    // 'stat' is a Linux system call
    // If OS is window, use 'fseek' to get file size
    struct stat sb;
    if (stat(fileName, &sb) == -1)
    {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    int totalSize   = sb.st_size;
    int dataSize    = totalSize - 256;

    char *signature = (char *)malloc(sizeof(char) * 256);
    char *fileData  = (char *)malloc(sizeof(char) * dataSize);

    fread(signature, 256, 1, pFile1);
    fread(fileData, dataSize, 1, pFile1);

    /* SHA-256 */

    // Hashing data of file(except signature)
    unsigned char digest[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32
    SHA256(fileData, dataSize, digest);

    printf("Hash Value of file data : \n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02X ", digest[i]);
    }
    printf("\n");

    /* RSA-2048 */

    // Decrypt a signature
    unsigned char decrypted[32];

    // Get Alice's public key from PEM file
    FILE *pKey = fopen("../keys/Alice_public.pem", "rb");
    RSA *rsaPublic = PEM_read_RSA_PUBKEY(pKey, NULL, NULL, NULL);

    // Decryption with Alice's public key
    unsigned int num;
    num = RSA_public_decrypt(256, signature, decrypted, rsaPublic, RSA_PKCS1_PADDING);

    if (num == -1)
    {
        printf("*** RSA decryption Error ***\n");
        return 1;
    }

    printf("\nDecrypted : \n");
    for (int i = 0; i < num; i++)
    {
        printf("%02X ", decrypted[i]);
    }
    printf("\n");

    for(int i = 0; i < 32; i++)
    {
        if (digest[i] != decrypted[i])
        {
            printf("*** File is corrupted ***\n");
            return 1;
        }
    }

    printf("\n    [Verification Success]\n");

    FILE *pFile2;
    if ((pFile2 = fopen("dummy", "wb")) == NULL)
    {
        perror("fopen");
        exit(1);
    }

    fwrite(fileData, 1, dataSize, pFile2);

    char path[50] = "./dummy";

    if(chmod(path, 0744) == -1) {
        fprintf(stderr, "chmod error: %s\n", strerror(errno));
        return -1;
    }

    fclose(pFile1);
    fclose(pFile2);
    fclose(pKey);
    free(signature);
    free(fileData);

    printf("\n... End Verifying Program ...\n\n");

    return 0;
}
