# SHA-256 & RSA-2048 C practice

👻 Use OpenSSL 1.1.1q library

## Getting Started
### Prerequisite
* linux
* makefile
* openssl 1.1.1 (https://www.openssl.org/source/)
### Installation
1. Clone the repo
    ```sh
    git clone https://github.com/bpsswu/openSSLpractice
    ```
2. make
3. go to /Alice and ./signing
4. go to /Bob and ./verifying

## Program Usage
1. Hash the original message using SHA-256
2. Encrypt the hash value from 1. using RSA-2048 private key
3. Decrypt the encrypted value from 2. using RSA-2048 public key

## cf.
1. RSA signing/verifying

    Alice -> Bob
    Alice encrypt message using private key of Alice
    Bob decrypt cipher text using public key of Alice
    * Ensure that the source of the data is Alice
    
2. RSA encryption/decryption

    Alice -> Bob
    Alice encrypt message using public key of Bob
    Bob decrypt cipher text using private key of Bob
    * Only Bob can decrypt encrypted messages
