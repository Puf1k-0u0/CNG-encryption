#include "import-export_data.h"

bool export_buf(IN BYTE* pbPrintData, IN DWORD cbDataLen, char* path) {
    DWORD dwCount = 0;

    FILE* fp;
    if ((fp = fopen(path, "w")) != NULL) {
        for (dwCount; dwCount < cbDataLen - 1; ++dwCount)
            fprintf(fp, "%02x ", pbPrintData[dwCount]);
        fprintf(fp, "%02x", pbPrintData[dwCount]);
        fclose(fp);
    }
    else {
        printf("**** Error open or create file for write '%s'\n", path);
        return false;
    }

    return true;
}

bool import_buf(IN BYTE* pbPrintData, IN DWORD cbDataLen, char* path) {
    DWORD dwCount = 0;
    char ch = 0;
    BYTE value = 0;

    FILE* fp;
    if ((fp = fopen(path, "r")) != NULL) {
        while (((ch = getc(fp)) != EOF) && (dwCount < cbDataLen)) {
            if (ch == ' ') {
                pbPrintData[dwCount] = value;
                dwCount++;
                value = 0;
                continue;
            }

            value *= 16; // bytes saved in HEX
            if ((int)ch >= 48 && (int)ch <= 57)
                value += (int)ch - 48; // ch ['0'; '9'] '0' = 48, ch - 48 = [0; 9]
            else value += (int)ch - 87; // ch ['a'; 'f'] 'a' = 97, ch - 97 + 10 = [10; 15]
        }
        fclose(fp);
    }
    else {
        printf("**** Error open file for read:%s\n", path);
        return false;
    }
    if (dwCount < cbDataLen) {
        pbPrintData[dwCount] = value;
        dwCount++;
    }
    return true;
}

DWORD get_size_buf(char* path) {
    DWORD dwCount = 0;
    char ch = 0;

    FILE* fp;
    if ((fp = fopen(path, "r")) != NULL) {
        while ((ch = getc(fp)) != EOF)
            if (ch == ' ') dwCount++;
        fclose(fp);
    }
    else {
        printf("**** Error open file for read '%s'\n", path);
        return -1;
    }
    return (dwCount == 0 ? dwCount : ++dwCount); // increment counter for last byte ('EOF' instead ' '), not incrememt if void buf
}

void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen) {
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen; dwCount++)
    {
        printf("0x%02x ", pbPrintData[dwCount]);
        if (0 == (dwCount + 1) % 16) putchar('\n');
    }

    printf("\n");
}
