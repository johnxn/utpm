#ifndef _UTPM_FUNCTIONS_H
#define _UTPM_FUNCTIONS_H

#include "utpm_structures.h"

#define   INOUTBUF_LEN          1020
#define   ENCRYPTED_BLOB_SIZE   256
#define   INPUT_BLOB_SIZE       241

#define WELL_KNOWN_SECRET "\x01\x02\x03\x04\x05\x06"

UTPM_RESULT utpm_create_context();

UTPM_RESULT utpm_close_context();

UTPM_RESULT utpm_get_random(
    BYTE *out,
    UINT32 size
);

UTPM_RESULT utpm_open_oiap_session(
    UTPM_AUTHHANDLE *authHandle,
    UTPM_NONCE *nonceEven
);

UTPM_RESULT utpm_open_osap_session(
    /* in */
    UTPM_ENTITY_TYPE entityType,
    UINT32 entityValue,
    UTPM_NONCE *nonceOddOSAP,
    /* out */
    UTPM_AUTHHANDLE *authHandle,
    UTPM_NONCE *nonceEven,
    UTPM_NONCE *nonceEvenOSAP
);

UTPM_RESULT utpm_create_wrap_key(
    /* in */
    UTPM_KEY_HANDLE parentHandle,
    UTPM_SECRET parentAuth,
    UTPM_KEY_USAGE keyUsage,
    UTPM_SECRET usageAuth,
    /* out */
    UTPM_KEY *wrappedKey
);

UTPM_RESULT utpm_load_key(
    /* in */
    UTPM_KEY_HANDLE parentHandle,
    UTPM_SECRET parentAuth,
    UTPM_KEY *inKey,
    /* out */
    UTPM_KEY_HANDLE *inkeyHandle
);

UTPM_RESULT utpm_bind_data(
    /* in */
    UTPM_STORE_PUBKEY *pubKey,
    UINT32 dataSize,
    BYTE *data,
    /* out */
    UINT32 *encDataSize,
    BYTE *encData
);

UTPM_RESULT utpm_unbind_data(
    /* in */
    UTPM_KEY_HANDLE keyHandle,
    UTPM_SECRET keyAuth,
    UINT32 encDataSize,
    BYTE *encData,
    /* out */
    UINT32 *dataSize,
    BYTE *data
);
 
UTPM_RESULT utpm_sign_data(
    /* in */
    UTPM_KEY_HANDLE keyHandle,
    UTPM_SECRET keyAuth,
    UINT32 areaToSignSize,
    BYTE *areaToSign,
    /* out */
    UINT32 *sigSize,
    BYTE *sig
);
 
UTPM_RESULT utpm_verify_data(
    /* in */
    UTPM_STORE_PUBKEY *pubKey,
    UINT32 sigSize,
    BYTE *sig,
    UINT32 dataSize,
    BYTE *data
);

UTPM_RESULT utpm_make_hash(
    UINT32 dataSize,
    BYTE *data,
    UTPM_DIGEST *digest
);

UTPM_RESULT utpm_flush_specific(
    UTPM_HANDLE handle,
    UTPM_RESOURCE_TYPE resourceType
);

UTPM_RESULT utpm_flush_all();

UTPM_RESULT utpm_pcr_extend(
    UTPM_PCRINDEX pcrNum,
    UTPM_DIGEST *inDigest
);

UTPM_RESULT utpm_pcr_read(
    UTPM_PCRINDEX pcrNum,
    UTPM_DIGEST *outDigest
);


#endif /* _UTPM_FUNCTIONS_H */
