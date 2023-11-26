#pragma once
#pragma warning(disable : 4996) //fopen(), scanf()

#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <string.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define LENGTH_PATH 40

static const BYTE rgbAES128Key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

typedef enum {
    false,
    true,
} bool;

typedef struct BCRYPT {
    BCRYPT_ALG_HANDLE       hAesAlg;
    BCRYPT_KEY_HANDLE       hKey;
    NTSTATUS                status;
    DWORD                   cbCipherText,
                            cbPlainText,
                            cbData,
                            cbKeyObject,
                            cbBlockLen,
                            cbIV,
                            cbBlob;
    PBYTE                   pbCipherText,
                            pbPlainText,
                            pbKeyObject,
                            pbIV,
                            pbBlob;
} BCRYPT;


bool generate_key(BCRYPT bcrypt, char* _path);
bool encrypt_data(BCRYPT, char* _path_key, char* _path_plaintext, char* _path_iv, char* _path_chiper);
bool decrypt_data(BCRYPT, char* _path_key, char* path_iv, char* _path_encrypt, char* _path_decrypt);
bool cmp_plain_dec(BCRYPT, char* _path_plaintext, char* _path_decrypt);

extern bool export_buf(IN BYTE* pbPrintData, IN DWORD cbDataLen, char* path);
extern bool import_buf(IN BYTE* pbPrintData, IN DWORD cbDataLen, char* path);
extern DWORD get_size_buf(char* path);
extern void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen);

extern bool init(BCRYPT*);
extern void Cleanup(BCRYPT);
extern bool destroy_key(BCRYPT);
extern bool clear_crypt_data(BCRYPT);
