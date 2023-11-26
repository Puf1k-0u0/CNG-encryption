#include "cng_interface.h"

bool cmp_plain_dec(BCRYPT bcrypt, char* _path_plaintext, char* _path_decrypt) {
	printf("\n======================COMPARE_PLAINTEXT_AND_DECRYPT======================\n");

	// ===============================PlainText=============================== //
	printf("-> Enter the PLAINTEXT path for compare with decrypt data (not more 40 symbols): ");
	fgets(_path_plaintext, LENGTH_PATH, stdin);
	if (strchr(_path_plaintext, '\n') != NULL)
		*(strchr(_path_plaintext, '\n')) = '\0';

	DWORD plaintext_size = get_size_buf(_path_plaintext);
	if (plaintext_size == -1)
		return false;

	// Allocate the buffer to hold the PlainText.
	BYTE* plaintext_buf = NULL;
	plaintext_buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, plaintext_size);
	if (NULL == plaintext_buf) {
		printf("**** memory allocation failed\n");
		return false;
	}
	if (!import_buf(plaintext_buf, plaintext_size, _path_plaintext))
		return false;

	printf("Plaintext:\n");
	PrintBytes(plaintext_buf, plaintext_size);

	// ===============================DECRYPT=============================== //
	printf("-> Enter the DECRYPT path for compare with plaintext (not more 40 symbols): ");
	fgets(_path_decrypt, LENGTH_PATH, stdin);
	if (strchr(_path_decrypt, '\n') != NULL)
		*(strchr(_path_decrypt, '\n')) = '\0';

	DWORD decrypt_size = get_size_buf(_path_decrypt);
	if (decrypt_size == -1)
		return false;

	// Allocate the buffer to hold the DecrytpData.
	BYTE* decrypt_buf = NULL;
	decrypt_buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, decrypt_size);
	if (NULL == decrypt_buf) {
		printf("**** memory allocation failed\n");
		return false;
	}
	if (!import_buf(decrypt_buf, decrypt_size, _path_decrypt))
		return false;

	printf("Decrypt data:\n");
	PrintBytes(decrypt_buf, decrypt_size);

	// ===============================COMPARE=============================== //
	if (plaintext_size != decrypt_size)
		return false;
	else {
		for (DWORD i = 0; i < plaintext_size; i++)
			if (plaintext_buf[i] != decrypt_buf[i])
				return false;
	}
	
	return true;
}
