#include "init-delete_bcrypt.h"

bool init(BCRYPT bcrypt) {
    // Open an algorithm handle.
    if (!NT_SUCCESS(bcrypt.status = BCryptOpenAlgorithmProvider(
        &(bcrypt.hAesAlg),
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", bcrypt.status);
        Cleanup(bcrypt);
        return false;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if (!NT_SUCCESS(bcrypt.status = BCryptGetProperty(
        bcrypt.hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE) & (bcrypt.cbKeyObject),
        sizeof(DWORD),
        &(bcrypt.cbData),
        0)))
    {
        printf("**** Error 0x%x returned by BCryptGetProperty\n", bcrypt.status);
        Cleanup(bcrypt);
        return false;
    }
    // Allocate the key object on the heap.
    bcrypt.pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bcrypt.cbKeyObject);
    if (NULL == bcrypt.pbKeyObject)
    {
        printf("**** memory allocation failed\n");
        Cleanup(bcrypt);
        return false;
    }

    // Generate the key from supplied input key bytes. (Init hKey)
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
        Cleanup(bcrypt);
        return false;
    }

    // Calculate the size of the buffer to hold the BLOB.
    if (!NT_SUCCESS(bcrypt.status = BCryptExportKey(
        bcrypt.hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        0,
        &(bcrypt.cbBlob),
        0)))
    {
        printf("**** Error 0x%x returned by BCryptExportKey\n", bcrypt.status);
        Cleanup(bcrypt);
        return false;
    }
    // Allocate the buffer to hold the BLOB.
    bcrypt.pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, bcrypt.cbBlob);
    if (NULL == bcrypt.pbBlob)
    {
        printf("**** memory allocation failed\n");
        Cleanup(bcrypt);
        return false;
    }

    if (!destroy_key(bcrypt))
        return false;

    return true;
}

void Cleanup(BCRYPT bcrypt) {
    if (bcrypt.hAesAlg)
        BCryptCloseAlgorithmProvider(bcrypt.hAesAlg, 0);

    if (bcrypt.hKey)
        BCryptDestroyKey(bcrypt.hKey);

    if (bcrypt.pbCipherText)
        HeapFree(GetProcessHeap(), 0, bcrypt.pbCipherText);

    if (bcrypt.pbPlainText)
        HeapFree(GetProcessHeap(), 0, bcrypt.pbPlainText);

    if (bcrypt.pbKeyObject)
        HeapFree(GetProcessHeap(), 0, bcrypt.pbKeyObject);

    if (bcrypt.pbIV)
        HeapFree(GetProcessHeap(), 0, bcrypt.pbIV);
}

bool destroy_key(BCRYPT bcrypt) {
    // Destroy the key. (Clear hKey, BLOB, KeyObject)
    if (!NT_SUCCESS(bcrypt.status = BCryptDestroyKey(bcrypt.hKey)))
    {
        printf("**** Error 0x%x returned by BCryptDestroyKey\n", bcrypt.status);
        return false;
    }
    bcrypt.hKey = 0;

    if (bcrypt.pbBlob == NULL || bcrypt.pbKeyObject == NULL) {
        printf("**** Error clear key! Buffers is NULL\n");
        return false;
    }
    memset(bcrypt.pbBlob, 0, bcrypt.cbBlob);
    memset(bcrypt.pbKeyObject, 0, bcrypt.cbKeyObject);
    return true;
}

bool clear_crypt_data(BCRYPT bcrypt) {
    if (bcrypt.pbCipherText == NULL || bcrypt.pbPlainText == NULL || bcrypt.pbIV == NULL) {
        printf("**** Error clear data! Buffers is NULL!\n");
        return false;
    }
    memset(bcrypt.pbCipherText, 0, bcrypt.cbCipherText);
    memset(bcrypt.pbPlainText, 0, bcrypt.cbPlainText);
    memset(bcrypt.pbIV, 0, bcrypt.cbBlockLen);
    return true;
}
