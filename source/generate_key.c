#include "cng_interface.h"

bool generate_key(BCRYPT bcrypt, char* _path) {
     printf("\n======================GENERATE_KEY======================\n");

    // Set mode coupling block (CBC, CFB, ECB)
    if (!NT_SUCCESS(bcrypt.status = BCryptSetProperty(
        bcrypt.hAesAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0)))
    {
        printf("**** Error 0x%x returned by BCryptSetProperty\n", bcrypt.status);
        return false;
    }

    // Generate the key from supplied input key bytes.
    if (!NT_SUCCESS(bcrypt.status = BCryptGenerateSymmetricKey(
        bcrypt.hAesAlg,
        &(bcrypt.hKey),
        bcrypt.pbKeyObject,
        bcrypt.cbKeyObject,
        (PBYTE)rgbAES128Key,
        sizeof(rgbAES128Key),
        0)))
    {
        printf("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", bcrypt.status);
        return false;
    }

    // Export key to the BLOB for writing to a file.
    if (!NT_SUCCESS(bcrypt.status = BCryptExportKey(
        bcrypt.hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        bcrypt.pbBlob,
        bcrypt.cbBlob,
        &(bcrypt.cbBlob),
        0)))
    {
        printf("**** Error 0x%x returned by BCryptExportKey\n", bcrypt.status);
        return false;
    }

    // Export key from BLOB to file
    printf("-> Enter the KEY path for save key (not more 40 symbols): ");
    fgets(_path, LENGTH_PATH, stdin);
    if (strchr(_path, '\n') != NULL)
        *(strchr(_path, '\n')) = '\0';

    if (!export_buf(bcrypt.pbBlob, bcrypt.cbBlob, _path))
        return false;
    if (!destroy_key(bcrypt))
        return false;

    return true;
}
