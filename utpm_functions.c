#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include "utpm_functions.h"
#include "utils.h"
#include "stuff_inoutbuf.h"



extern BYTE InOutBuf[INOUTBUF_LEN];

int sock;
const char *utpmd_socket_addr = "/var/run/utpmd.socket";
const char *client_socket_prefix = "/var/tmp/";


int connect_utpmd() {
    struct sockaddr_un utpmd_add, client_add;
    memset(&utpmd_add, 0, sizeof(utpmd_add));
    utpmd_add.sun_family = AF_UNIX;
    strncpy(utpmd_add.sun_path, utpmd_socket_addr, sizeof(utpmd_add.sun_path));
    memset(&client_add, 0, sizeof(client_add));
    client_add.sun_family = AF_UNIX;
    sprintf(client_add.sun_path, "%s%05d", client_socket_prefix, getpid());
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        printf("create socket failed.\n");
        return -1;
    }
    unlink(client_add.sun_path);
    if (bind(sock, (struct sockaddr *)&client_add, sizeof(client_add)) < 0) {
        printf("bind socket failed: %s\n", strerror(errno));
        return -1;
    }
    chmod(client_add.sun_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (connect(sock, (struct sockaddr *)&utpmd_add, sizeof(utpmd_add)) < 0) {
        printf("connect socket failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
int run_inoutbuf() {
    if (write(sock, InOutBuf, sizeof(InOutBuf)) < 0) {
        printf("write socket failed: %s\n", strerror(errno));
        return -1;
    }
    memset(InOutBuf, 0, sizeof(InOutBuf));
    if (read(sock, InOutBuf, sizeof(InOutBuf)) < 0) {
        printf("read socket failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
int disconnect_utpmd() {
    if (close(sock) < 0) {
        return -1;
    }
    return 0;
};
TPM_RESULT utpm_create_context() {
    if (connect_utpmd() < 0) {
        return TPM_FAIL;
    }
    memset(InOutBuf, 0, sizeof(InOutBuf));
    return TPM_SUCCESS;
}

TPM_RESULT utpm_get_random(
    BYTE *out,
    UINT32 size
) {
    TPM_RESULT res;
    if (stuff_inoutbuf_get_random(size) < 0) return TPM_FAIL;
    if (run_inoutbuf() < 0)  return TPM_FAIL;
    if (get_random_info(&res, out) < 0) return TPM_FAIL;
    return res;
}

TPM_RESULT utpm_open_oiap_session(
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven
){
    TPM_RESULT res;   
    if (stuff_inoutbuf_oiap() < 0) return TPM_FAIL;
    if (run_inoutbuf() < 0) return TPM_FAIL;
    if (get_oiap_info(&res, authHandle, nonceEven) < 0) return TPM_FAIL;
    return res;
}

TPM_RESULT utpm_open_osap_session(
    /* in */
    TPM_ENTITY_TYPE entityType,
    UINT32 entityValue,
    TPM_NONCE *nonceOddOSAP,
    /* out */
    TPM_AUTHHANDLE *authHandle,
    TPM_NONCE *nonceEven,
    TPM_NONCE *nonceEvenOSAP
) {
    TPM_RESULT res;
    if (stuff_inoutbuf_osap(entityType, entityValue, nonceOddOSAP)) return TPM_FAIL;
    //printf_TPM_REQUEST(InOutBuf);
    if (run_inoutbuf() < 0) {
        return TPM_FAIL;
    }
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_OSAP);
    if (get_osap_info(&res, authHandle, nonceEven, nonceEvenOSAP)) return TPM_FAIL;
    return res;
}

TPM_RESULT utpm_create_wrap_key(
    /* in */
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY_USAGE keyUsage,
    TPM_SECRET usageAuth,
    /* out */
    TPM_KEY *wrappedKey
) {
    TPM_RESULT res;
    TPM_NONCE nonceOddOSAP;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceEvenOSAP;
    TPM_NONCE nonceOdd;
    TPM_ENTITY_TYPE entityType;
    UINT32 entityValue;
    if (parentHandle == TPM_KH_SRK) {
        entityType = TPM_ET_SRK;
        entityValue = TPM_KH_SRK;
    }
    else {
        entityType = TPM_ET_KEY;
        entityValue = parentHandle;
    }
    utpm_get_random(nonceOddOSAP.nonce, sizeof(TPM_NONCE));
    if (utpm_open_osap_session(entityType, entityValue, &nonceOddOSAP,
            &authHandle, &nonceEven, &nonceEvenOSAP) != TPM_SUCCESS) {
        return TPM_FAIL;
    }

    utpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_createcrapkey(parentHandle, parentAuth, usageAuth, usageAuth, keyUsage, 
            &nonceOddOSAP, &nonceEvenOSAP, &nonceEven, &nonceOdd, authHandle) != 0){
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (run_inoutbuf() < 0) {
        return TPM_FAIL;
    }
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_CreateWrapKey);
    if (get_wrappedkey_info(&res, wrappedKey) != 0) {
        return TPM_FAIL;
    }
    return res;
}

TPM_RESULT utpm_load_key(
    /* in */
    TPM_KEY_HANDLE parentHandle,
    TPM_SECRET parentAuth,
    TPM_KEY *inKey,
    /* out */
    TPM_KEY_HANDLE *inkeyHandle
) {
    TPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (utpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    utpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_loadkey(parentHandle, parentAuth, inKey,
                authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (run_inoutbuf() != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_LoadKey);
    if (get_loadkey_info(&res, inkeyHandle) != 0) {
        return TPM_FAIL;
    }
    return res;
}

TPM_RESULT utpm_bind_data(
    /* in */
    TPM_STORE_PUBKEY *pubKey,
    UINT32 dataSize,
    BYTE *data,
    /* out */
    UINT32 *encDataSize,
    BYTE *encData
) {
    TPM_RESULT res;
    RSA_PUBLIC_KEY donglePub;
    if (pubKey->keyLength != sizeof(RSA_PUBLIC_KEY)) {
        return TPM_ENCRYPT_ERROR;
    }
    memcpy(&donglePub, pubKey->key, pubKey->keyLength);
    BYTE flags[] = {0x01, 0x01, 0x00, 0x00, 0x02}; //TPM_BOUND_DATA flag.
    BYTE raw[INPUT_BLOB_SIZE];
    UINT32 rawSize = sizeof(flags) + dataSize;
    if (rawSize > INPUT_BLOB_SIZE) {
        return TPM_BAD_DATASIZE;
    }
    memcpy(raw, flags, sizeof(flags));
    memcpy(raw+sizeof(flags), data, dataSize);
    /*
    UINT32 errcode;
    if ((errcode = encrypt_with_pubkey(&donglePub, raw, rawSize, encData, encDataSize)) != DONGLE_SUCCESS) {
        printf("errcode is %x\n", errcode);
        return TPM_ENCRYPT_ERROR;
    }
    */
    if (stuff_inoutbuf_bind(&donglePub, rawSize, raw) != 0) return TPM_FAIL;
    if (run_inoutbuf() != 0) return TPM_FAIL;
    if (get_bind_info(&res, encDataSize, encData) != 0) return TPM_FAIL;
    return TPM_SUCCESS;
}

TPM_RESULT utpm_unbind_data(
    /* in */
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    UINT32 encDataSize,
    BYTE *encData,
    /* out */
    UINT32 *dataSize,
    BYTE *data
){
    TPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (utpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    utpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_unbind(keyHandle, keyAuth, encData,
                encDataSize, authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (run_inoutbuf() != DONGLE_SUCCESS) {
        return TPM_FAIL;
    }
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_UnBind);
    if (get_unbind_info(&res, dataSize, data) != 0) {
        return TPM_FAIL;
    }
    return res;

}

TPM_RESULT utpm_sign_data(
    /* in */
    TPM_KEY_HANDLE keyHandle,
    TPM_SECRET keyAuth,
    UINT32 areaToSignSize,
    BYTE *areaToSign,
    /* out */
    UINT32 *sigSize,
    BYTE *sig
) {
    TPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (areaToSignSize != 20) {
        return TPM_BAD_PARAMETER;
    }
    if (utpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    utpm_get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    if (stuff_inoutbuf_sign(keyHandle, keyAuth, areaToSign,
                areaToSignSize, authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    //printf_TPM_REQUEST(InOutBuf);
    if (run_inoutbuf() != DONGLE_SUCCESS) {
        return TPM_FAIL;
    }
    //printf_TPM_RESPONSE(InOutBuf, TPM_ORD_Sign);
    if (get_sign_info(&res, sigSize, sig) != 0) {
        return TPM_FAIL;
    }
    return res;
}

TPM_RESULT utpm_verify_data(
    /* in */
    TPM_STORE_PUBKEY *pubKey,
    UINT32 sigSize,
    BYTE *sig,
    UINT32 dataSize,
    BYTE *data
){
    TPM_RESULT res;
    RSA_PUBLIC_KEY donglePub;
    if (pubKey->keyLength != sizeof(RSA_PUBLIC_KEY)) {
        return TPM_DECRYPT_ERROR;
    }
    memcpy(&donglePub, pubKey->key, pubKey->keyLength);
    BYTE raw[20];
    UINT32 rawSize = 20;
    /*
    UINT32 errcode;
    if ((errcode = decrypt_with_pubkey(&donglePub, sig, sigSize, raw, &rawSize)) != DONGLE_SUCCESS) {
        printf("errcode is %x\n", errcode);
        return TPM_DECRYPT_ERROR;
    }
    */
    if (stuff_inoutbuf_verify(&donglePub, sigSize, sig) != 0) return TPM_DECRYPT_ERROR;
    if (run_inoutbuf() != 0) return TPM_DECRYPT_ERROR;
    if (get_verify_info(&res, &rawSize, raw) != 0) return TPM_DECRYPT_ERROR;
    if (rawSize != 20 || memcmp(data, raw, 20)) return TPM_BAD_SIGNATURE;
    return TPM_SUCCESS;

}

TPM_RESULT utpm_make_hash(
    UINT32 dataSize,
    BYTE *data,
    TPM_DIGEST *digest
) {
    tpm_sha1_ctx_t sha1;
    tpm_sha1_init(&sha1);
    tpm_sha1_update(&sha1, data, dataSize);
    tpm_sha1_final(&sha1, digest->digest);
    return TPM_SUCCESS;
}

TPM_RESULT utpm_flush_specific(
    TPM_HANDLE handle,
    TPM_RESOURCE_TYPE resourceType
){
    TPM_RESULT res;
    if (stuff_inoutbuf_flush(handle, resourceType) != 0) return TPM_FAIL;
    if (run_inoutbuf() != 0)  return TPM_FAIL;
    if (get_flush_info(&res) != 0) return TPM_FAIL;
    return res;
}

TPM_RESULT utpm_flush_all(){
    TPM_RESULT res;
    int i;
    for (i = 0; i < TPM_MAX_SESSIONS; i++) {
        if ((res = utpm_flush_specific(0x2000000+i, TPM_RT_AUTH)) != TPM_SUCCESS) return res;
    }
    for (i = 0; i < TPM_MAX_KEYS; i++) {
        if ((res = utpm_flush_specific(0x1000000+i, TPM_RT_KEY)) != TPM_SUCCESS) return res;
    }
    return TPM_SUCCESS;
}

TPM_RESULT utpm_pcr_extend(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *inDigest
) {
    TPM_RESULT res;
    if (stuff_inoutbuf_extend(pcrNum, inDigest) != 0) return TPM_FAIL;
    if (run_inoutbuf() != 0) return TPM_FAIL;
    if (get_pcr_extend_info(&res) != 0) return TPM_FAIL;
    return res;
}

TPM_RESULT utpm_pcr_read(
    TPM_PCRINDEX pcrNum,
    TPM_DIGEST *outDigest
) {
    TPM_RESULT res;
    if (stuff_inoutbuf_read(pcrNum) != 0) return TPM_FAIL;
    if (run_inoutbuf() !=0) return TPM_FAIL;
    if (get_pcr_read_info(&res, outDigest) !=0) return TPM_FAIL;
    return res;
}
#if 0

TPM_RESULT take_owner_ship(TPM_SECRET ownerAuth, TPM_SECRET srkAuth) {
    TPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (utpm_open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
        return TPM_FAIL;
    }
    get_random(nonceOdd.nonce, sizeof(TPM_NONCE));
    UINT32 encOwnerAuthSize = 256;
    BYTE encOwnerAuth[256];
    RSA_PUBLIC_KEY pubkey;
    if (read_rsa_pubkey(FILEID_EK_PUB, &pubkey) != 0) {
        return TPM_ENCRYPT_ERROR;
    }
    if (encrypt_with_pubkey(&pubkey, ownerAuth, sizeof(TPM_SECRET), encOwnerAuth, &encOwnerAuthSize) != 0) {
        return TPM_ENCRYPT_ERROR;
    }
    UINT32 encSrkAuthSize = 256;
    BYTE encSrkAuth[256]; 
    if (encrypt_with_pubkey(&pubkey, srkAuth, sizeof(TPM_SECRET), encSrkAuth, &encSrkAuthSize) != 0) {
        return TPM_ENCRYPT_ERROR;
    }
    if (stuff_inoutbuf_ownership(ownerAuth, encOwnerAuthSize, encOwnerAuth, encSrkAuthSize,
            encSrkAuth, authHandle, &nonceEven, &nonceOdd) != 0) {
        return TPM_FAIL;
    }
    printf_TPM_REQUEST(InOutBuf);
    if (run_bin_file() != DONGLE_SUCCESS) {
        return TPM_FAIL;
    }
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_TakeOwnership);
    if (get_ownership_info(&res) != 0) {
        return TPM_FAIL;
    }
    return res;
}

TPM_RESULT run_first_time() {
    if (stuff_inoutbuf_firsttime() != 0) return TPM_FAIL;
    if (run_bin_file() != DONGLE_SUCCESS != DONGLE_SUCCESS) return TPM_FAIL;
    return TPM_SUCCESS;
}
#endif
