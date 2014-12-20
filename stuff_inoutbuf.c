#include "stuff_inoutbuf.h"
#include "request_length.h"
#include "utils.h"

BYTE InOutBuf[INOUTBUF_LEN];

int stuff_inoutbuf_firsttime() {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = 0xffffffff;
    memcpy(InOutBuf, &in_size, sizeof(UINT32));
    return 0;
}

int stuff_inoutbuf_startup() {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = 2 + 4 + 4 + 2;
    if (in_size + 4 > sizeof(InOutBuf)) return -1;
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;

    TPM_TAG tag = TPM_TAG_RQU_COMMAND; 
    UINT32 paramSize = in_size; 
    TPM_COMMAND_CODE ordinal = TPM_ORD_Startup; 
    TPM_STARTUP_TYPE startupType = TPM_ST_CLEAR;

    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, paramSize);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_STARTUP_TYPE(&ptr, &length, startupType);
    if (length != 0) return -1;
    return 0;
}

int stuff_inoutbuf_get_random(UINT32 size) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    int command = COMMAND_GET_RANDOM;
    memcpy(InOutBuf, &command, sizeof(int));
    memcpy(InOutBuf+sizeof(int), &size, sizeof(int));
    return 0;
}
int get_random_info(
    TPM_RESULT *res,
    BYTE *out
) {
    int size;
    memcpy(&size, InOutBuf, sizeof(int));
    if (size == 0xffffffff) {
        //printf("0xffffffff got.\n");
        return -1;
    }
    memcpy(out, InOutBuf+sizeof(int), size);
    *res = TPM_SUCCESS;
    return 0;
}

int stuff_inoutbuf_oiap() {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = 2 + 4 + 4;
    if (in_size + 4 > sizeof(InOutBuf)) return -1;
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size; 

    TPM_TAG tag = TPM_TAG_RQU_COMMAND; 
    UINT32 paramSize = in_size; 
    TPM_COMMAND_CODE oridnal = TPM_ORD_OIAP;
    tpm_marshal_UINT16(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, paramSize);
    tpm_marshal_UINT32(&ptr, &length, oridnal);
    if (length != 0) return -1;
    return 0;
}

int get_oiap_info(
    TPM_RESULT *res,
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven
){
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &length, authHandle);
    tpm_unmarshal_TPM_NONCE(&ptr, &length, nonceEven);
    return 0;
}

int stuff_inoutbuf_osap(
    TPM_ENTITY_TYPE entityType, 
    UINT32 entityValue,
    TPM_NONCE *nonceOddOSAP
) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = LENGTH_OSAP;
    if (in_size + 4 > sizeof(InOutBuf)) return -1;
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_OSAP;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_ENTITY_TYPE(&ptr, &length, entityType);
    tpm_marshal_UINT32(&ptr, &length, entityValue);
    tpm_marshal_TPM_NONCE(&ptr, &length, nonceOddOSAP);
    if (length != 0) return -1;
    return 0;
}

int get_osap_info(
    TPM_RESULT *res,
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceEvenOSAP
){
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_TPM_AUTHHANDLE(&ptr, &length, authHandle);
    tpm_unmarshal_TPM_NONCE(&ptr, &length, nonceEven);
    tpm_unmarshal_TPM_NONCE(&ptr, &length, nonceEvenOSAP);
    return 0;
}

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
) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = LENGTH_CREATE_WRAPPEDKEY;
    if (in_size + 4 > sizeof(InOutBuf)) return -1;
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_CreateWrapKey;
    TPM_SECRET sharedSecret;
    compute_shared_secret(parentAuth, nonceEvenOSAP, nonceOddOSAP, sharedSecret);
    TPM_ENCAUTH encUsageAuth;
    TPM_ENCAUTH encMigrationAuth;
    tpm_encrypt_auth_secret(usageAuth, sharedSecret, nonceEven, encUsageAuth);
    tpm_encrypt_auth_secret(migrationAuth, sharedSecret, nonceOdd, encMigrationAuth);
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, parentHandle);
    tpm_marshal_TPM_ENCAUTH(&ptr, &length, &encUsageAuth);
    tpm_marshal_TPM_ENCAUTH(&ptr, &length, &encMigrationAuth);
    TPM_KEY keyInfo;
    keyInfo.tag = 0x0000; // doesn't matter here.
    keyInfo.fill = 0x0000;
    keyInfo.keyUsage = keyUsage;
    keyInfo.keyFlags = 0x0;
    //keyInfo.authDataUsage = TPM_AUTH_NEVER; 
    keyInfo.algorithmParms.algorithmID = TPM_ALG_RSA;
    keyInfo.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
    keyInfo.algorithmParms.sigScheme = TPM_SS_NONE;
    keyInfo.algorithmParms.parmSize = 12;
    keyInfo.algorithmParms.parms.rsa.keyLength = 2048;
    keyInfo.algorithmParms.parms.rsa.numPrimes = 2;
    keyInfo.algorithmParms.parms.rsa.exponentSize = 0;
    keyInfo.PCRInfoSize = 0;
    keyInfo.pubKey.keyLength = 0;
    keyInfo.encDataSize = 0;
    tpm_marshal_TPM_KEY(&ptr, &length, &keyInfo);

    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    memcpy(auth1.nonceOdd.nonce, nonceOdd->nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, sharedSecret, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_CreateWrapKey, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    if (length != 0) return -1;
    return 0;
} 
int get_wrappedkey_info(TPM_RESULT *res, TPM_KEY *wrappedKey) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }

    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_TPM_KEY(&ptr, &length, wrappedKey);
    BYTE *dumpEncData = malloc(wrappedKey->encDataSize);
    BYTE *dumppubKey = malloc(wrappedKey->pubKey.keyLength);
    if (dumppubKey == NULL || dumpEncData == NULL) {
        return -1;
    }
    memcpy(dumpEncData, wrappedKey->encData, wrappedKey->encDataSize);
    memcpy(dumppubKey, wrappedKey->pubKey.key, wrappedKey->pubKey.keyLength);
    wrappedKey->encData = dumpEncData;
    wrappedKey->pubKey.key = dumppubKey;
    return 0;
}

int stuff_inoutbuf_loadkey(
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY *inKey,
    TPM_AUTHHANDLE authHandle, 
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = LENGTH_LOAD_KEY;
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_LoadKey;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, parentHandle);
    tpm_marshal_TPM_KEY(&ptr, &length, inKey);
    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    memcpy(auth1.nonceOdd.nonce, nonceOdd->nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, parentAuth, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_LoadKey, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    if (length != 0) return -1;
    return 0;
}
int get_loadkey_info(
    TPM_RESULT *res,
    TPM_KEY_HANDLE *inkeyHandle
) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_TPM_KEY_HANDLE(&ptr, &length, inkeyHandle);
    return 0;
}
int stuff_inoutbuf_bind(
    RSA_PUBLIC_KEY *pubkey,
    UINT32 inputSize,
    BYTE *input
) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    int command = COMMAND_ENCRYPT_PUB;
    memcpy(InOutBuf, &command, sizeof(int));
    memcpy(InOutBuf+sizeof(int), pubkey, sizeof(RSA_PUBLIC_KEY));
    memcpy(InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY), &inputSize, sizeof(UINT32));
    memcpy(InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY)+sizeof(UINT32), input, inputSize);
    return 0;
}
int get_bind_info(
    TPM_RESULT *res,
    UINT32 *outputSize,
    BYTE *output
) {
    //printf_buf("InOutBuf", InOutBuf, sizeof(InOutBuf));
    memcpy(outputSize, InOutBuf, sizeof(UINT32));
    if (*outputSize == 0xffffffff) {
        //printf("0xffffffff got.\n");
        //*res = TPM_FAIL;
        return -1;
    }
    memcpy(output, InOutBuf+sizeof(UINT32), *outputSize);
    *res = TPM_SUCCESS;
    return 0;
}
int stuff_inoutbuf_unbind(
    TPM_KEY_HANDLE keyHandle, 
    TPM_SECRET keyAuth,
    BYTE *inData, 
    UINT32 inDataSize,
    TPM_AUTHHANDLE authHandle, 
    TPM_NONCE *nonceEven, 
    TPM_NONCE *nonceOdd
) {
    UINT32 in_size = LENGTH_UNBIND;
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_UnBind;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    tpm_marshal_UINT32(&ptr, &length, inDataSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, inData, inDataSize);
    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    memcpy(auth1.nonceOdd.nonce, nonceOdd->nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, keyAuth, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_UnBind, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    if (length != 0) return -1;
    return 0;
}
int get_unbind_info(
    TPM_RESULT *res,
    UINT32 *outDataSize,
    BYTE *outData
) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_UINT32(&ptr, &length, outDataSize);
    //outData = malloc(*outDataSize);
    memcpy(outData, ptr, *outDataSize);
    return 0;
}

int stuff_inoutbuf_sign(
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    BYTE *areaToSign,
    UINT32 areaToSignSize,
    TPM_AUTHHANDLE authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
){
    UINT32 in_size = LENGTH_SIGN;
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_Sign;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    tpm_marshal_UINT32(&ptr, &length, areaToSignSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, areaToSign, areaToSignSize);
    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    memcpy(auth1.nonceOdd.nonce, nonceOdd->nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, keyAuth, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_Sign, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    if (length != 0) return -1;
    return 0;
}
int get_sign_info(
    TPM_RESULT *res,
    UINT32 *sigSize,
    BYTE *sig
) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_UINT32(&ptr, &length, sigSize);
    memcpy(sig, ptr, *sigSize);
    return 0;

}
int stuff_inoutbuf_verify(
    RSA_PUBLIC_KEY *pubkey,
    UINT32 inputSize,
    BYTE *input
) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    int command = COMMAND_DECRYPT_PUB;
    memcpy(InOutBuf, &command, sizeof(int));
    memcpy(InOutBuf+sizeof(int), pubkey, sizeof(RSA_PUBLIC_KEY));
    memcpy(InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY), &inputSize, sizeof(UINT32));
    memcpy(InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY)+sizeof(UINT32), input, inputSize);
    return 0;
}
int get_verify_info(
    TPM_RESULT *res,
    UINT32 *outputSize,
    BYTE *output
) {
    memcpy(outputSize, InOutBuf, sizeof(UINT32));
    if (*outputSize == 0xffffffff) {
        //printf("0xffffffff got.\n");
        //*res = TPM_FAIL;
        return -1;
    }
    memcpy(output, InOutBuf+sizeof(UINT32), *outputSize);
    *res = TPM_SUCCESS;
    return 0;
}

int stuff_inoutbuf_flush(
    TPM_HANDLE handle, 
    TPM_RESOURCE_TYPE resourceType
) {
    UINT32 in_size = LENGTH_FLUSH;
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_FlushSpecific;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
    tpm_marshal_TPM_HANDLE(&ptr, &length, handle);
    tpm_marshal_TPM_RESOURCE_TYPE(&ptr, &length, resourceType);
    if (length != 0) return -1;
    return 0;
}
int get_flush_info(TPM_RESULT *res) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    return 0;
}

int stuff_inoutbuf_ownership(
    TPM_SECRET ownerAuth,
    UINT32 encOwnerAuthSize,
    BYTE *encOwnerAuth,
    UINT32 encSrkAuthSize,
    BYTE *encSrkAuth,
    TPM_AUTHHANDLE authHandle, 
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceOdd
) {
    memset(InOutBuf, 0, sizeof(InOutBuf));
    UINT32 in_size = LENGTH_OWNERSHIP;
    if (in_size + 4 > sizeof(InOutBuf)) return -1;
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;

    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size =  in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_TakeOwnership;
    tpm_marshal_UINT16(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_UINT32(&ptr, &length, ordinal);

    /* setup encSrkAuth and encOwnerAuth */
    TPM_PROTOCOL_ID protocolID = TPM_PID_OWNER;
    tpm_marshal_UINT16(&ptr, &length, protocolID);
    tpm_marshal_UINT32(&ptr, &length, encOwnerAuthSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, encOwnerAuth, encOwnerAuthSize);
    tpm_marshal_UINT32(&ptr, &length, encSrkAuthSize);
    tpm_marshal_BYTE_ARRAY(&ptr, &length, encSrkAuth, encSrkAuthSize);

    /* set up srkParams */
    TPM_KEY srkParams;
    srkParams.tag = 0x0000; // doesn't matter here.
    srkParams.fill = 0x0000;
    srkParams.keyUsage = TPM_KEY_STORAGE;
    srkParams.algorithmParms.algorithmID = TPM_ALG_RSA;
    srkParams.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;
    srkParams.algorithmParms.sigScheme = TPM_SS_NONE;
    srkParams.algorithmParms.parmSize = 12;
    srkParams.algorithmParms.parms.rsa.keyLength = 2048;
    srkParams.algorithmParms.parms.rsa.numPrimes = 2;
    srkParams.algorithmParms.parms.rsa.exponentSize = 0;
    srkParams.PCRInfoSize = 0;
    srkParams.pubKey.keyLength = 0;
    srkParams.encDataSize = 0;

    tpm_marshal_TPM_KEY(&ptr, &length, &srkParams);

    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = authHandle;
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    memcpy(auth1.nonceOdd.nonce, nonceOdd->nonce, sizeof(TPM_NONCE));
    auth1.continueAuthSession = 0x00;
    memcpy(auth1.secret, ownerAuth, sizeof(TPM_SECRET));
    /* compute input paramters digest */
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; //pass in_size, tag, parmSize, ordinal;
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1); // pass tag, parmsSize, ordinal and auth.
    compute_in_parm_digest(auth1.digest, TPM_ORD_TakeOwnership, ptr2, length2); 
    compute_auth_data(&auth1);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    return 0;
}
int get_ownership_info(TPM_RESULT *res) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }

    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    return 0;
}


#if 0

int stuff_inoutbuf_makeidentity( UINT32 buf_size, TPM_AUTHHANDLE srkAuthHandle, TPM_NONCE *srkNonceEven, TPM_NONCE *nonceOddOSAP, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceEven, TPM_AUTHHANDLE authHandle)  {
    UINT32 in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           20 + //identityAuth
                           20 + //labelPrivCADigest
                           2 + //idkeyParams.tag
                           2 + //idkeyParams.fill
                           2 + //idkeyParams.keyUsage
                           4 + //idkeyParams.keyFlags
                           1 + //idkeyParams.authDataUsage
                           4 + //idkeyParams.algorithmParms.algorithmID
                           2 + //idkeyParams.algorithmParms.encScheme
                           2 + //idkeyParams.algorithmParms.sigScheme
                           4 + //idkeyParams.algorithmParms.parmSize
                           4 + //idkeyParams.algorithmParms.rsa.keyLength
                           4 + //idkeyParams.algorithmParms.rsa.numPrimes
                           4 + //idkeyParams.algorithmParms.rsa.exponentSize
                           4 + //idkeyParams.PCRInfoSize
                           4 + //idkeyParams.pubKey.keyLength
                           4 + //idkeyParams.encDataSize
                           4 + //srkAuthHandle
                           20 + //srkNonceOdd
                           1 + //continueAuthSession
                           20 + //srkAuth
                           4 + //authHandle
                           20 + //nonceOdd
                           1 + //continueAuthSession
                           20; //ownerAuth
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_AUTH2_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_MakeIdentity;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    /* generate identityAuth */
    TPM_SECRET ownerSecret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TPM_SECRET sharedSecret;
    compute_shared_secret(ownerSecret, nonceEvenOSAP, nonceOddOSAP, sharedSecret);
    TPM_ENCAUTH identityAuth;
    TPM_SECRET identitySecret = {0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    tpm_encrypt_auth_secret(identitySecret, sharedSecret, nonceEven, identityAuth);
    tpm_marshal_TPM_ENCAUTH(&ptr, &length, &identityAuth);

    TPM_CHOSENID_HASH labelPrivCADigest;
    memset(labelPrivCADigest.digest, 0, sizeof(TPM_CHOSENID_HASH)); // we don't need this.
    tpm_marshal_TPM_CHOSENID_HASH(&ptr, &length, &labelPrivCADigest);
 
    TPM_KEY idkeyParams;
    idkeyParams.tag = 0x0101; //TPM_KEY_STRUCTURE
    idkeyParams.keyUsage = TPM_KEY_IDENTITY;
    idkeyParams.algorithmParms.algorithmID = TPM_ALG_RSA;
    idkeyParams.algorithmParms.encScheme = TPM_ES_NONE;
    idkeyParams.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    idkeyParams.algorithmParms.parmSize = 12;
    idkeyParams.algorithmParms.parms.rsa.keyLength = 2048;
    idkeyParams.algorithmParms.parms.rsa.numPrimes = 2;
    idkeyParams.algorithmParms.parms.rsa.exponentSize = 0;
    idkeyParams.PCRInfoSize = 0;
    idkeyParams.pubKey.keyLength = 0;
    idkeyParams.encDataSize = 0;
    tpm_marshal_TPM_KEY(&ptr, &length, &idkeyParams);

    /* set up auth1 */
    TPM_SECRET srkSecret = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    TPM_AUTH auth1;
    auth1.authHandle = srkAuthHandle; // auth1.authHandle
    memcpy(auth1.nonceEven.nonce, srkNonceEven->nonce, sizeof(TPM_NONCE)); 
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE)); // auth1.nonceOdd
    auth1.continueAuthSession = 0x00; //auth1.continueAuthSession
    memcpy(auth1.secret, srkSecret, sizeof(TPM_SECRET));
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; 
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1) * 2;
    compute_in_parm_digest(auth1.digest, TPM_ORD_MakeIdentity, ptr2, length2); 
    compute_auth_data(&auth1); //auth1.auth
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);

    /* set up auth2 */
    TPM_AUTH auth2;
    auth2.authHandle = authHandle;
    memcpy(auth2.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth2.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth2.continueAuthSession = 0x00; 
    memcpy(auth2.secret, sharedSecret, sizeof(TPM_SECRET));
    memcpy(auth2.digest, auth1.digest, sizeof(TPM_DIGEST));
    compute_auth_data(&auth2);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth2.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth2.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth2.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth2.auth);

    if (length != 0) {
        prUINT32f("stuff make identity inoutbuf failed.\n");
        exit(EXIT_FAILURE);
    }

}

int stuff_inoutbuf_certify(
         
        UINT32 buf_size, 
        TPM_HANDLE certAuthHandle, 
        TPM_NONCE *certNonceEven, 
        TPM_HANDLE keyAuthHandle, 
        TPM_NONCE *keyNonceEven, 
        TPM_KEY_HANDLE certHandle, 
        TPM_KEY_HANDLE keyHandle, 
        TPM_SECRET certSecret,
        TPM_SECRET keySecret
) 
{
    UINT32 in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //certHandle
                           4 + //keyHandle
                           20 + //antiReplay
                           4 + //certAuthHandle
                           20 + //certNonceEven
                           1 + //continueAuthSession
                           20 + //certAuth
                           4 + //keyAuthHandle
                           20 + //keyNonceEven
                           1 + //continueAuthSession
                           20; //keyAuth
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_AUTH2_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_CertifyKey;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, certHandle);
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    TPM_NONCE antiReplay;
    get_random(antiReplay.nonce, sizeof(TPM_NONCE));
    tpm_marshal_TPM_NONCE(&ptr, &length, &antiReplay);

    /* set up auth1 */
    TPM_AUTH auth1;
    auth1.authHandle = certAuthHandle; // auth1.authHandle
    memcpy(auth1.nonceEven.nonce, certNonceEven->nonce, sizeof(TPM_NONCE)); 
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE)); // auth1.nonceOdd
    auth1.continueAuthSession = 0x00; //auth1.continueAuthSession
    memcpy(auth1.secret, certSecret, sizeof(TPM_SECRET));
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; 
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1) * 2;
    compute_in_parm_digest(auth1.digest, TPM_ORD_CertifyKey, ptr2, length2); 
    compute_auth_data(&auth1); //auth1.auth
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);

    /* set up auth2 */
    TPM_AUTH auth2;
    auth2.authHandle = keyAuthHandle;
    memcpy(auth2.nonceEven.nonce, keyNonceEven->nonce, sizeof(TPM_NONCE));
    get_random(auth2.nonceOdd.nonce, sizeof(TPM_NONCE));
    auth2.continueAuthSession = 0x00; 
    memcpy(auth2.secret, keySecret, sizeof(TPM_SECRET));
    memcpy(auth2.digest, auth1.digest, sizeof(TPM_DIGEST));
    compute_auth_data(&auth2);
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth2.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth2.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth2.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth2.auth);

    if (length != 0) {
        prUINT32f("stuff certify key inoutbuf failed.\n");
        exit(EXIT_FAILURE);
    }

}
#endif

int stuff_inoutbuf_extend(TPM_PCRINDEX pcrNum, TPM_DIGEST *inDigest) {
    UINT32 in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //pcrNum
                           20; //inDigest
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_Extend;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);
/*
    TPM_PCRINDEX pcrNum = 0;
    TPM_DIGEST inDigest = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0f, 0x0e, 0x0c, 0x0d, 0x0c, 0x0d, 0x0c, 0x0a};
    */
    tpm_marshal_TPM_PCRINDEX(&ptr, &length, pcrNum);
    tpm_marshal_TPM_DIGEST(&ptr, &length, inDigest);
    return 0;
}
int get_pcr_extend_info(TPM_RESULT *res) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    return 0;

}

int stuff_inoutbuf_read(
    TPM_PCRINDEX pcrIndex
) {
    UINT32 in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4; //pcrIndex
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_PCRRead;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    tpm_marshal_TPM_PCRINDEX(&ptr, &length, pcrIndex);
    return 0;
}

int get_pcr_read_info(
    TPM_RESULT *res,
    TPM_DIGEST *outDigest
) {
    UINT32 length;
    BYTE *ptr;
    memcpy(&length, InOutBuf, sizeof(UINT32));
    if (length == 0xffffffff) {
        return -1;
    }
    ptr = InOutBuf + sizeof(UINT32);
    TPM_TAG tag;
    UINT32 size;
    tpm_unmarshal_TPM_TAG(&ptr, &length, &tag);
    tpm_unmarshal_UINT32(&ptr, &length, &size);
    tpm_unmarshal_TPM_RESULT(&ptr, &length, res);
    tpm_unmarshal_TPM_DIGEST(&ptr, &length, outDigest);
    return 0;

}

#if 0
int stuff_inoutbuf_quote( UINT32 buf_size, TPM_AUTHHANDLE authHandle, TPM_NONCE *nonceEven) {
    UINT32 in_size = 2 + //tag
                           4 + //size 
                           4 + //ordinal
                           4 + //keyHandle
                           20 + //externalData
                           2 + //targetPCR.sizeOfSelect
                           1 + //targetPCR.pcrSelect
                           4 + //authHandle
                           20 + //nonceEven
                           1 + //continueAuthSession
                           20; //auth
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, &in_size, 4);

    BYTE *ptr = InOutBuf + 4;
    UINT32 length = in_size;
    
    /* set up tag, size and ordinal */
    TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
    UINT32 size = in_size;
    TPM_COMMAND_CODE ordinal = TPM_ORD_Quote;
    tpm_marshal_TPM_TAG(&ptr, &length, tag);
    tpm_marshal_UINT32(&ptr, &length, size);
    tpm_marshal_TPM_COMMAND_CODE(&ptr, &length, ordinal);

    TPM_KEY_HANDLE keyHandle = 0x1000000;
    TPM_NONCE externalData = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a};
    TPM_PCR_SELECTION targetPCR;
    targetPCR.sizeOfSelect = 1;
    targetPCR.pcrSelect[0] = 0x01; // select PCR0
    tpm_marshal_TPM_KEY_HANDLE(&ptr, &length, keyHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &externalData);
    tpm_marshal_TPM_PCR_SELECTION(&ptr, &length, &targetPCR);

    /* set up auth1 */
    TPM_SECRET aikSecret = {0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    TPM_AUTH auth1;
    auth1.authHandle = authHandle; // auth1.authHandle
    memcpy(auth1.nonceEven.nonce, nonceEven->nonce, sizeof(TPM_NONCE)); 
    get_random(auth1.nonceOdd.nonce, sizeof(TPM_NONCE)); // auth1.nonceOdd
    auth1.continueAuthSession = 0x00; //auth1.continueAuthSession
    memcpy(auth1.secret, aikSecret, sizeof(TPM_SECRET));
    BYTE *ptr2 =  InOutBuf + 4 + 2 + 4 + 4; 
    UINT32 length2 = in_size - (2+4+4) - (4+20+20+1);
    compute_in_parm_digest(auth1.digest, TPM_ORD_Quote, ptr2, length2); 
    compute_auth_data(&auth1); //auth1.auth
    tpm_marshal_TPM_AUTHHANDLE(&ptr, &length, auth1.authHandle);
    tpm_marshal_TPM_NONCE(&ptr, &length, &auth1.nonceOdd);
    tpm_marshal_BOOL(&ptr, &length, auth1.continueAuthSession);
    tpm_marshal_TPM_AUTHDATA(&ptr, &length, &auth1.auth);
    if (length != 0) {
        prUINT32f("stuff quote failed.\n");
        exit(EXIT_FAILURE);
    }
}

#endif
