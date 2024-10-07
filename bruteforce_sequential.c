// bruteforce_sequential.c
// nota: el key usado es bastante pequenio, cuando sea random speedup variara

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>

void decrypt(long key, char *ciph, int len) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    // Set key parity and prepare key schedule
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (i * 8)) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_set_key_checked(&keyBlock, &schedule);

    // Decrypt
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

void encrypt(long key, char *ciph, int len) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    // Set key parity and prepare key schedule
    for (int i = 0; i < 8; ++i) {
        keyBlock[i] = (key >> (i * 8)) & 0xFF;
    }
    DES_set_odd_parity(&keyBlock);
    DES_set_key_checked(&keyBlock, &schedule);

    // Encrypt
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

char search[] = " the ";
int tryKey(long key, char *ciph, int len) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);
    return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

int main(int argc, char *argv[]) {
    long upper = (1L << 56); // upper bound DES keys 2^56
    int ciphlen = strlen((char *)cipher);
    long found = 0;

    for (long i = 0; i < upper; ++i) {
        if (tryKey(i, (char *)cipher, ciphlen)) {
            found = i;
            break;
        }
    }

    if (found) {
        decrypt(found, (char *)cipher, ciphlen);
        printf("Key: %li\nDecrypted message: %s\n", found, cipher);
    } else {
        printf("Key not found.\n");
    }

    return 0;
}