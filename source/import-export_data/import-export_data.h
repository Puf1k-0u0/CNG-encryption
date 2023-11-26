#pragma once
#include "../cng_interface.h"

bool export_buf(IN BYTE* pbPrintData, IN DWORD cbDataLen, char* path);
bool import_buf(IN BYTE* pbPrintData, IN DWORD cbDataLen, char* path);
DWORD get_size_buf(char* path);
void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen);
