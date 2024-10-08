#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>

void decrypt(long key, char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir la clave larga en 8 bytes
    for (int i = 0; i < 8; ++i) {
        key_block[i] = (key >> (i * 8)) & 0xFF;
    }

    DES_set_odd_parity(&key_block);  // Establecer la paridad
    DES_set_key(&key_block, &schedule);
    
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

void encrypt(long key, char *ciph, int len) {
    DES_cblock key_block;
    DES_key_schedule schedule;

    // Convertir la clave larga en 8 bytes
    for (int i = 0; i < 8; ++i) {
        key_block[i] = (key >> (i * 8)) & 0xFF;
    }

    DES_set_odd_parity(&key_block);
    DES_set_key(&key_block, &schedule);

    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

int tryKey(long key, char *ciph, int len, const char *search_phrase) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);
    return strstr(temp, search_phrase) != NULL;
}

int main() {
    char filename[] = "text_to_encrypt.txt";
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error al abrir el archivo %s\n", filename);
        return 1;
    }

    // Leer el texto del archivo
    char text[1024];
    fread(text, sizeof(char), 1024, file);
    fclose(file);

    // Pedir la clave al usuario
    char user_key[9];  // Clave de 8 caracteres + '\0'
    printf("Ingrese una clave de 8 caracteres: ");
    fgets(user_key, 9, stdin);
    if (strlen(user_key) != 8) {
        printf("La clave debe tener exactamente 8 caracteres.\n");
        return 1;
    }

    // Usar la clave ingresada por el usuario para encriptar el texto
    int text_len = strlen(text);
    encrypt(*(long *)user_key, text, text_len);
    
    // Establecer la frase de búsqueda fija
    char search_phrase[128] = "secret message";
    
    // Medir el tiempo de búsqueda
    clock_t start_time = clock();
    long upper = (1L << 56);  // Límite superior para claves DES (2^56)
    long found = 0;

    for (long i = 0; i < upper; ++i) {
        if (tryKey(i, text, text_len, search_phrase)) {
            found = i;
            break;
        }
    }

    clock_t end_time = clock();
    double time_spent = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    if (found) {
        printf("Clave encontrada: %lx\n", found);
        printf("Tiempo tardado: %f segundos\n", time_spent);
    } else {
        printf("Clave no encontrada.\n");
    }

    return 0;
}
