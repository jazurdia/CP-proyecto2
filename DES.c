#include <openssl/des.h>
#include <string.h>
#include <stdio.h>

void decrypt(long key, char *ciph, int len) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    // Convert key into DES_cblock
    memcpy(keyBlock, &key, 8);
    DES_set_key_unchecked(&keyBlock, &schedule);

    // Decrypt
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

void encrypt(long key, char *ciph, int len) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    // Convert key into DES_cblock
    memcpy(keyBlock, &key, 8);
    DES_set_key_unchecked(&keyBlock, &schedule);

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

// Cambia esto para que contenga "the"
unsigned char cipher[] = "thexxxx"; // Texto de 8 caracteres

int main() {
    long upper = (1L << 56); // 2^56 keys is a massive space
    int ciphlen = sizeof(cipher) - 1; // Correct length of the cipher array
    long found = 0;

    for (long i = 0; i < upper; ++i) {
        if (i % 1000000 == 0) {
            printf("Progress: Key %li\n", i);
        }

        if (tryKey(i, (char *)cipher, ciphlen)) {
            found = i;
            break;
        }
    }

    if (found != 0) {
        decrypt(found, (char *)cipher, ciphlen);
        cipher[ciphlen] = '\0'; // Ensure null-terminated string
        printf("Key: %li\nDecrypted: %s\n", found, cipher);
    } else {
        printf("Key not found.\n");
    }

    return 0;
}
