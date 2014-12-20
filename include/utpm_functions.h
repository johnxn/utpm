#include "tpm_structures.h"

#define INOUTBUF_LEN 1020
#define ENCRYPTED_BLOB_SIZE 256
#define INPUT_BLOB_SIZE 241

#define WELL_KNOWN_SECRET "\x01\x02\x03\x04\x05\x06"

TPM_RESULT utpm_create_context();

TPM_RESULT utpm_get_random(
    BYTE *out,
    UINT32 size
);

TPM_RESULT utpm_open_oiap_session(
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven
);

TPM_RESULT utpm_open_osap_session(
    /* in */
    TPM_ENTITY_TYPE entityType,
    UINT32 entityValue,
    TPM_NONCE *nonceOddOSAP,
    /* out */
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceEvenOSAP
);

TPM_RESULT utpm_create_wrap_key(
    /* in */
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY_USAGE keyUsage,
    TPM_SECRET usageAuth,
    /* out */
    TPM_KEY *wrappedKey
);

TPM_RESULT utpm_load_key(
    /* in */
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY *inKey,
    /* out */
    TPM_KEY_HANDLE *inkeyHandle
);

TPM_RESULT utpm_bind_data(
    /* in */
    TPM_STORE_PUBKEY *pubKey,
    UINT32 dataSize,
    BYTE *data,
    /* out */
    UINT32 *encDataSize,
    BYTE *encData
);

TPM_RESULT utpm_unbind_data(
    /* in */
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    UINT32 encDataSize,
    BYTE *encData,
    /* out */
    UINT32 *dataSize,
    BYTE *data
);
 
TPM_RESULT utpm_sign_data(
    /* in */
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    UINT32 areaToSignSize,
    BYTE *areaToSign,
    /* out */
    UINT32 *sigSize,
    BYTE *sig
);
 
TPM_RESULT utpm_verify_data(
    /* in */
    TPM_STORE_PUBKEY *pubKey,
    UINT32 sigSize,
    BYTE *sig,
    UINT32 dataSize,
    BYTE *data
);

TPM_RESULT utpm_make_hash(
    UINT32 dataSize,
    BYTE *data,
    TPM_DIGEST *digest
);

TPM_RESULT utpm_flush_specific(
    TPM_HANDLE handle,
    TPM_RESOURCE_TYPE resourceType
);

TPM_RESULT utpm_flush_all();

TPM_RESULT utpm_pcr_extend(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *inDigest
);

TPM_RESULT utpm_pcr_read(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *outDigest
);
