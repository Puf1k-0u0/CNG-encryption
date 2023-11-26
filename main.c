#pragma comment(lib, "bcrypt.lib")
#include "source/cng_interface.h"

typedef enum {
    KEY,
    PLAINTEXT,
    IV,
    ENCRYPT,
    DECRYPT,
    TOTAL,
} path;
typedef enum {
    EXIT,
    GENERATE_KEY,
    ENCRYPT_DATA,
    DECRYPT_DATA,
    COMPARE,
} commands;

void __cdecl wmain(int argc, __in_ecount(argc) LPWSTR* wargv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(wargv);

    BCRYPT bcrypt = { NULL, NULL, STATUS_UNSUCCESSFUL, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL };
    BCRYPT* pbcrypt = &bcrypt;

    if (!init(pbcrypt)) {
        Cleanup(bcrypt);
        return;
    }

    // data\key.txt   data\plaintext.txt    data\iv.txt   data\encrypt.txt  data\decrypt.txt
    char* paths[TOTAL];
    for (int i = 0; i < TOTAL; i++) {
        paths[i] = (char*)malloc(LENGTH_PATH);
        if (paths[i] != NULL) strcpy(paths[i], "");
        else {
            printf("**** Error memory allocation for paths!\n");
            Cleanup(bcrypt);
            return;
        }
    }

    bool exit = false;
    int code = 0;
    while (!exit) {
        printf("\n=======================================MAIN_MENU=======================================\n");
        printf("\n\t0 - exit, 1 - generate key, 2 - encrypt data, 3 - decrypt data,"
               "\n\t4 - compare plaintext and decrypt data\n\tEnter command(0-4): ");
        if (scanf("%d", &code) != 1) {
            printf("**** Error input command!\n");
            Cleanup(bcrypt);
            return;
        }
        while (getchar() != '\n') continue;

        switch (code) {
        case EXIT: {
            exit = true;
            break;
        }
        case GENERATE_KEY: {
            if (!generate_key(bcrypt, paths[KEY])) {
                printf("**** Error generate key\n");
                Cleanup(bcrypt);
                return;
            }
            else printf("[Key has been saved to: %s]\n", paths[KEY]);
            break;
        }
        case ENCRYPT_DATA: {
            if (!encrypt_data(bcrypt, paths[KEY], paths[PLAINTEXT], paths[IV], paths[ENCRYPT])) {
                printf("**** Error encrypt data\n");
                Cleanup(bcrypt);
                return;
            }
            else {
                printf("[Initialisation vector has been saved to: %s]\n", paths[IV]);
                printf("[Encrypt data has been saved to: %s]\n", paths[ENCRYPT]);
            }
            break;
        }
        case DECRYPT_DATA: {
            if (!decrypt_data(bcrypt, paths[KEY], paths[IV], paths[ENCRYPT], paths[DECRYPT])) {
                printf("**** Error decrypt data\n");
                Cleanup(bcrypt);
                return;
            }
            else printf("[Decrypt data has been saved to: %s]\n", paths[DECRYPT]);
            break;
        }
        case COMPARE: {
            if (!cmp_plain_dec(bcrypt, paths[PLAINTEXT], paths[DECRYPT])) printf("****DECRYPT does not match the PLAINTEXT.(\n");
            else printf("DECRYPT matches the PLAINTEXT!)\n");
            break;
        }
        default:
            printf("**** Invalid input command, READ INSTRUCTION!!!\n");
        }
    }

    Cleanup(bcrypt);
}
