#include "cng_interface.h"

bool decrypt_data(BCRYPT bcrypt, char* _path_key, char* _path_iv, char* _path_encrypt, char* _path_decrypt) {
    printf("\n======================DECRYPT_DATA======================\n");

    // ===============================KEY=============================== //
    printf("-> Enter the KEY path for decrypt (not more 40 symbols): ");
    if (strcmp(_path_key, "") == 0) fgets(_path_key, LENGTH_PATH, stdin);
    else {
        printf("\n[Enter 0 to use the path to the generated key or 1 for to enter another path to the key]: ");
        bool tmp;
        if (scanf("%d", &tmp) != 1) {
            printf("**** Error input option to enter key path!");
            return false;
        }
        while (getchar() != '\n') continue;
        if (tmp == 1) fgets(_path_key, LENGTH_PATH, stdin);
    }
    if (strchr(_path_key, '\n') != NULL)
        *(strchr(_path_key, '\n')) = '\0';
    if (!import_buf(bcrypt.pbBlob, bcrypt.cbBlob, _path_key)) {
        return false;
    }

    // Import key to the KeyObject from BLOB.
    if (!NT_SUCCESS(bcrypt.status = BCryptImportKey(
        bcrypt.hAesAlg,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        &bcrypt.hKey,
        bcrypt.pbKeyObject,
        bcrypt.cbKeyObject,
        bcrypt.pbBlob,
        bcrypt.cbBlob,
        0)))
    {
        printf("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", bcrypt.status);
        return false;
    }

    // ===============================IV=============================== //
    printf("-> Enter the IV path for decrypt (not more 40 symbols): ");
    if (strcmp(_path_iv, "") == 0) fgets(_path_iv, LENGTH_PATH, stdin);
    else {
        printf("\n[Enter 0 to use the path to the generated IV or 1 for to enter another path to the IV]: ");
        bool tmp;
        if (scanf("%d", &tmp) != 1) {
            printf("**** Error input option to enter key path!");
            return false;
        }
        while (getchar() != '\n') continue;
        if (tmp == 1) fgets(_path_iv, LENGTH_PATH, stdin);
    }
    if (strchr(_path_iv, '\n') != NULL)
        *(strchr(_path_iv, '\n')) = '\0';
    if (!import_buf(bcrypt.pbBlob, bcrypt.cbBlob, _path_iv)) {
        return false;
    }

    // Calculate the block length for the IV.
    bcrypt.cbIV = get_size_buf(_path_iv);
    if (bcrypt.cbIV == -1) {
        return false;
    }
    if (!NT_SUCCESS(bcrypt.status = BCryptGetProperty(
        bcrypt.hAesAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE) & (bcrypt.cbBlockLen),
        sizeof(DWORD),
        &(bcrypt.cbData),
        0)))
    {
        printf("**** Error 0x%x returned by BCryptGetProperty\n", bcrypt.status);
        return false;
    }
    // Determine whether the cbBlockLen is not longer than the IV length.
    if (bcrypt.cbBlockLen > bcrypt.cbIV)
    {
        printf("**** block length is longer than the provided IV length\n");
        return false;
    }
    // Allocate a buffer for the IV. The buffer is consumed during the 
    // encrypt/decrypt process.
    bcrypt.pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bcrypt.cbBlockLen);
    if (NULL == bcrypt.pbIV)
    {
        printf("**** memory allocation failed\n");
        return false;
    }
    if (!import_buf(bcrypt.pbIV, bcrypt.cbBlockLen, _path_iv)) {
        return false;
    }

    // ===============================CIPHER=============================== //
    printf("-> Enter the ENCRYPT path for decrypt (not more 40 symbols): ");
    if (strcmp(_path_encrypt, "") == 0) fgets(_path_encrypt, LENGTH_PATH, stdin);
    else {
        printf("\n[Enter 0 to use the path to the encrypted data or 1 for to enter another path to the chipertext]: ");
        bool tmp;
        if (scanf("%d", &tmp) != 1) {
            printf("**** Error input option to enter key path!");
            return false;
        }
        while (getchar() != '\n') continue;
        if (tmp == 1) fgets(_path_key, LENGTH_PATH, stdin);
    }
    if (strchr(_path_encrypt, '\n') != NULL)
        *(strchr(_path_encrypt, '\n')) = '\0';
    if (!import_buf(bcrypt.pbBlob, bcrypt.cbBlob, _path_encrypt)) {
        return false;
    }

    // Calculate the size for CipherText.
    bcrypt.cbCipherText = get_size_buf(_path_encrypt);
    if (bcrypt.cbCipherText == -1) {
        return false;
    }
    bcrypt.pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bcrypt.cbCipherText);
    if (NULL == bcrypt.pbCipherText)
    {
        printf("**** memory allocation failed\n");
        return false;
    }
    if (!import_buf(bcrypt.pbCipherText, bcrypt.cbCipherText, _path_encrypt)) {
        return false;
    }

    // ===============================DECRYPT=============================== //
    // Get the output buffer size.
    if (!NT_SUCCESS(bcrypt.status = BCryptDecrypt(
        bcrypt.hKey,
        bcrypt.pbCipherText,
        bcrypt.cbCipherText,
        NULL,
        bcrypt.pbIV,
        bcrypt.cbBlockLen,
        NULL,
        0,
        &bcrypt.cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%x returned by BCryptDecrypt\n", bcrypt.status);
        return false;
    }

    bcrypt.pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bcrypt.cbPlainText);
    if (NULL == bcrypt.pbPlainText)
    {
        printf("**** memory allocation failed\n");
        return false;
    }

    // Use the key to decrypt the encrypt buffer.
    if (!NT_SUCCESS(bcrypt.status = BCryptDecrypt(
        bcrypt.hKey,
        bcrypt.pbCipherText,
        bcrypt.cbCipherText,
        NULL,
        bcrypt.pbIV,
        bcrypt.cbBlockLen,
        bcrypt.pbPlainText,
        bcrypt.cbPlainText,
        &bcrypt.cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        printf("**** Error 0x%x returned by BCryptDecrypt\n", bcrypt.status);
        return false;
    }

    // Export decrypt data
    printf("-> Enter the DECRYPT path to write decrypt data (not more 40 symbols): ");
    fgets(_path_decrypt, LENGTH_PATH, stdin);
    if (strchr(_path_decrypt, '\n') != NULL)
        *(strchr(_path_decrypt, '\n')) = '\0';

    if (!export_buf(bcrypt.pbPlainText, bcrypt.cbPlainText, _path_decrypt))
        return false;
    else {
        printf("Decrypt Data:\n");
        PrintBytes(bcrypt.pbPlainText, bcrypt.cbPlainText);
    }

    if (!destroy_key(bcrypt) || !clear_crypt_data(bcrypt))
        return false;

    return true;
}
