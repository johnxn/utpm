#ifndef _ROCKEY_APIS_H
#define _ROCKEY_APIS_H

#include "Dongle_CORE.h"
#include "Dongle_API.h"

#define INOUTBUF_LEN 1020
#define INPUT_BLOB_SIZE 241
#define ENCRYPTED_BLOB_SIZE 256


DWORD open_rockey(BYTE isPriv, BYTE *pin);
DWORD download_bin_file(char *path);
DWORD run_bin_file(BYTE *inoutbuf, WORD len);
DWORD change_admin_pin(BYTE *oldPin, BYTE *newPin);
DWORD get_uniquekey(BYTE *adminPIN);
DWORD encrypt_with_pubkey(RSA_PUBLIC_KEY *pubkey, BYTE *input, DWORD inputSize, BYTE *output, DWORD *outputSize);
DWORD decrypt_with_pubkey(RSA_PUBLIC_KEY *pubkey, BYTE *input, DWORD inputSize, BYTE *output, DWORD *outputSize);
DWORD get_random(BYTE *buf, DWORD size);
DWORD read_rsa_pubkey(DWORD fileid, RSA_PUBLIC_KEY *pubkey);

#endif /* _ROCKEY_APIS_H */
