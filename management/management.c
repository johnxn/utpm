#include "stuff_inoutbuf.h"
#include "utils.h"
#include "tpm_data.h"
#include "rockey_apis.h"
#include "management.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern BYTE InOutBuf[INOUTBUF_LEN];

TPM_RESULT run_first_time() {
    if (stuff_inoutbuf_firsttime() != 0) return TPM_FAIL;
    if (run_bin_file(InOutBuf, sizeof(InOutBuf)) != DONGLE_SUCCESS != DONGLE_SUCCESS) return TPM_FAIL;
    return TPM_SUCCESS;
}

TPM_RESULT take_owner_ship(TPM_SECRET ownerAuth, TPM_SECRET srkAuth) {
    TPM_RESULT res;
    TPM_AUTHHANDLE authHandle;
    TPM_NONCE nonceEven;
    TPM_NONCE nonceOdd;
    if (open_oiap_session(&authHandle, &nonceEven) != TPM_SUCCESS) {
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
    if (run_bin_file(InOutBuf, sizeof(InOutBuf)) != DONGLE_SUCCESS) {
        return TPM_FAIL;
    }
    printf_TPM_RESPONSE(InOutBuf, TPM_ORD_TakeOwnership);
    if (get_ownership_info(&res) != 0) {
        return TPM_FAIL;
    }
    return res;
}


int init_rockey(char *admin_pin, char *bin_path, char *owner_secret, char *srk_secret) {
    DWORD errcode;
    if (open_rockey(1, CONST_ADMINPIN) == DONGLE_SUCCESS)  {
        char old_pin[17];
        if ((errcode = get_uniquekey(old_pin)) != DONGLE_SUCCESS) {
            printf("Get unique key failed.\n");
            return -1;
        }
        if ((errcode = change_admin_pin(old_pin, admin_pin)) != DONGLE_SUCCESS) {
            printf("Change admin PIN failed.\n");
            return -1;
        }
    }
    if (open_rockey(1, admin_pin) != DONGLE_SUCCESS) {
        printf("Open rockey failed.\n");
        return -1;
    }
    if (bin_path == NULL) bin_path = "./demo.bin";
    if (owner_secret == NULL) owner_secret = WELL_KNOWN_SECRET;
    if (srk_secret == NULL) srk_secret = WELL_KNOWN_SECRET;
    if (download_bin_file(bin_path) != DONGLE_SUCCESS) {
        printf("Download bin file failed.\n");
        return -1;
    }
    if (run_first_time() != TPM_SUCCESS) {
        printf("Init tpm engine failed.\n");
        return -1;
    }
    TPM_SECRET ownerAuth;
    TPM_SECRET srkAuth;
    memset(ownerAuth, 0, sizeof(TPM_SECRET));
    memset(srkAuth, 0, sizeof(TPM_SECRET));
    memcpy(ownerAuth, owner_secret, strlen(owner_secret));
    memcpy(srkAuth, srk_secret, strlen(srk_secret));
    if (take_owner_ship(ownerAuth, srkAuth) != TPM_SUCCESS) {
        printf("Take ownership failed.\n");
        return -1;
    }
    return 0;
}

