# Digital Signature Program

## Project description
- Digital signature implementation
- Applicable to encryption/decryption

## Getting Started
### Prerequisite
* linux
* C language
* makefile
* openssl 1.1.1 (https://www.openssl.org/source/)
* SHA-256 & RSA-2048
### Installation
1. Clone the repo
    ```sh
    git clone https://github.com/bpsswu/openSSLpractice
    ```
2. make
3. Execute signing in the Alice directory (./signing)
4. Execute verifying in the Bob directory (./verifying)
5. Execute dummy in the Bob directory (./dummy)

## Program Flow
![image](https://user-images.githubusercontent.com/101001675/209760380-3596c140-06f9-4c70-996c-16db2fe59304.png)

## Directory Structure
- /sources
    - dummy.c : dummy file
- /keys
    - This directory contains Alice and Bob's RSA private key and public key
    - The key is stored in the form of a pem file
- /Alice
    - Creates a digital signature by importing a file from the sources directory, and creates a new file with the digital signature added to the existing file
- /Bob
    - After importing and verifying the newly created file in the Alice directory, the original file is obtained

## cf.
- openssl docs : https://www.openssl.org/docs/manpages.html
