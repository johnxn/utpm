#ifndef _STUFF_INOUTBUF_H
#define _STUFF_INOUTBUF_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tpm_structures.h"
#include "tpm_marshalling.h"
#include "utpm_functions.h"

#undef TRUE
#undef FALSE

#include "Dongle_API.h"

#define   COMMAND_GET_RANDOM    0xfffffffe
#define   COMMAND_ENCRYPT_PUB   0xfffffffb
#define   COMMAND_DECRYPT_PUB   0xfffffffc



int stuff_inoutbuf_firsttime();
int stuff_inoutbuf_startup();

int stuff_inoutbuf_get_random(
    UINT32 size
);
int get_random_info(
    TPM_RESULT *res,
    BYTE *out
);

int stuff_inoutbuf_oiap();
int get_oiap_info(
    TPM_RESULT *res,
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven
);

int stuff_inoutbuf_osap(
    TPM_ENTITY_TYPE entityType,
    UINT32 entityValue,
    TPM_NONCE *nonceOddOSAP
);
int get_osap_info(
    TPM_RESULT *res,
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceEvenOSAP
);

int stuff_inoutbuf_createcrapkey(
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_SECRET usageAuth,
    TPM_SECRET migrationAuth,
    TPM_KEY_USAGE keyUsage,
    TPM_NONCE *nonceOddOSAP, 
    TPM_NONCE *nonceEvenOSAP, 
    TPM_NONCE *nonceEven, 
    TPM_NONCE *nonceOdd,
    TPM_AUTHHANDLE authHandle
);
int get_wrappedkey_info(
    TPM_RESULT *res,
    TPM_KEY *wrappedKey
);

int stuff_inoutbuf_ownership(
    TPM_SECRET ownerAuth,
    UINT32 encOwnerAuthSize,
    BYTE *encOwnerAuth,
    UINT32 encSrkAuthSize,
    BYTE *encSrkAuth,
    TPM_AUTHHANDLE authHandle, 
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
);
int get_ownership_info(
    TPM_RESULT *res
);


int stuff_inoutbuf_loadkey(
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY *inKey, 
    TPM_AUTHHANDLE authHandle, 
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
);
int get_loadkey_info(
    TPM_RESULT *res,
    TPM_KEY_HANDLE *inkeyHandle
);

int stuff_inoutbuf_getpubkey();

int stuff_inoutbuf_bind(
    RSA_PUBLIC_KEY *pubkey,
    UINT32 inputSize,
    BYTE *input
);
int get_bind_info(
    TPM_RESULT *res,
    UINT32 *outputSize,
    BYTE *output
);

int stuff_inoutbuf_unbind(
    TPM_KEY_HANDLE keyHandle, 
    TPM_SECRET keyAuth,
    BYTE *inData, 
    UINT32 inDataSize,
    TPM_AUTHHANDLE authHandle, 
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
);
int get_unbind_info(
    TPM_RESULT *res,
    UINT32 *outDataSize,
    BYTE *outData
);

int stuff_inoutbuf_sign(
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    BYTE *areaToSign,
    UINT32 areaToSignSize,
    TPM_AUTHHANDLE authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
);
int get_sign_info(
    TPM_RESULT *res,
    UINT32 *sigSize,
    BYTE *sig
);

int stuff_inoutbuf_verify(
    RSA_PUBLIC_KEY *pubkey,
    UINT32 inputSize,
    BYTE *input
);
int get_verify_info(
    TPM_RESULT *res,
    UINT32 *outputSize,
    BYTE *output
);

int stuff_inoutbuf_makeidentity(
    TPM_AUTHHANDLE srkAuthHandle, 
    TPM_NONCE *srkNonceEven, 
    TPM_NONCE *nonceOddOSAP, 
    TPM_NONCE *nonceEvenOSAP, 
    TPM_NONCE *nonceEven, 
    TPM_AUTHHANDLE authHandle
);
int stuff_inoutbuf_flush(
    TPM_HANDLE handle, 
    TPM_RESOURCE_TYPE resourceType
);
int get_flush_info(TPM_RESULT *res);

int stuff_inoutbuf_certify(
    TPM_HANDLE certAuthHandle, 
    TPM_NONCE *certNonceEven, 
    TPM_HANDLE keyAuthHandle, 
    TPM_NONCE *keyNonceEven, 
    TPM_KEY_HANDLE certHandle, 
    TPM_KEY_HANDLE keyHandle, 
    TPM_SECRET certSecret, 
    TPM_SECRET keySecret
);
int stuff_inoutbuf_extend(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *inDigest
);
int get_pcr_extend_info(
    TPM_RESULT *res
);
int stuff_inoutbuf_read(
    TPM_PCRINDEX pcrNum
);
int get_pcr_read_info(
    TPM_RESULT *res,
    TPM_DIGEST *outDigest
);
int stuff_inoutbuf_quote(
    TPM_HANDLE authHandle, 
    TPM_NONCE *nonceEven
);


#endif /* _STUFF_INOUTBUF_H */
