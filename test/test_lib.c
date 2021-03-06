#include "utpm_functions.h"
#include "utils.h"

int main() {

    if (utpm_create_context() != UTPM_SUCCESS) {
        printf("create tpm context failed.\n");
        exit(1);
    }

#if 0
    utpm_flush_all();
    /* Test 1: generate a binding key, load this key, and use this key to bind and unbind */
    UTPM_KEY wrappedKey;
    UTPM_KEY_HANDLE parentHandle = UTPM_KH_SRK;
    UTPM_SECRET parentAuth= {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    UTPM_KEY_USAGE keyUsage = UTPM_KEY_BIND;
    UTPM_SECRET keyAuth = {0x0a, 0x0b};
    if (utpm_create_wrap_key(parentHandle, parentAuth, keyUsage, keyAuth, &wrappedKey) != UTPM_SUCCESS) {
        printf("Create wrapped key failed.\n");
        exit(EXIT_FAILURE);
    }
		FILE *fp = fopen("./credit_holder.key", "w");
		BYTE *buffer = malloc(2048);
		BYTE *tail = buffer;
		size_t buffer_len = 2048;
		tpm_marshal_TPM_KEY(&tail, &buffer_len, &wrappedKey);
		printf("buffer: %s", buffer);
		fwrite(buffer, 2048, 1, fp);
		
    printf_TPM_KEY(&wrappedKey);

    UTPM_KEY_HANDLE keyHandle;
    if (utpm_load_key(parentHandle, parentAuth, &wrappedKey, &keyHandle) != UTPM_SUCCESS) {
       printf("Load key failed.\n");
       exit(EXIT_FAILURE);
    }
    printf("Key handle is %x\n", keyHandle);

    BYTE data[] = {0x1, 0x03, 0x05};
    UINT32 dataSize = sizeof(data);
    BYTE encData[ENCRYPTED_BLOB_SIZE];
    UINT32 encDataSize = ENCRYPTED_BLOB_SIZE; //need to set this!!!
    if (utpm_bind_data(&(wrappedKey.pubKey), dataSize, data, &encDataSize, encData) != UTPM_SUCCESS) {
        printf("Bind data failed.\n");
        exit(EXIT_FAILURE);
    }
    printf_buf("Encrypted data is", encData, encDataSize);

    BYTE decData[1024];
    UINT32 decDataSize;
    if (utpm_unbind_data(keyHandle, keyAuth, encDataSize, encData, &decDataSize, decData) != UTPM_SUCCESS) {
        printf("Unbind data failed.\n");
        exit(EXIT_FAILURE);
    }
    printf_buf("Decrypted data is", decData, decDataSize);
    
    /* Test 2: create a signing key, load the key, and use this key to sign and verify a 20-byte data. */
    UTPM_KEY wrappedKey;
    UTPM_KEY_HANDLE parentHandle = UTPM_KH_SRK;
    UTPM_SECRET parentAuth= {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    UTPM_KEY_USAGE keyUsage = UTPM_KEY_SIGNING;
    UTPM_SECRET keyAuth = {0x0a, 0x0b};
    if (utpm_create_wrap_key(parentHandle, parentAuth, keyUsage, keyAuth, &wrappedKey) != UTPM_SUCCESS) {
        printf("Create wrapped key failed.\n");
        exit(EXIT_FAILURE);
    }
    printf_TPM_KEY(&wrappedKey);

    UTPM_KEY_HANDLE keyHandle;
    if (utpm_load_key(parentHandle, parentAuth, &wrappedKey, &keyHandle) != UTPM_SUCCESS) {
       printf("Load key failed.\n");
       exit(EXIT_FAILURE);
    }
    printf("Key handle is %x\n", keyHandle);

    BYTE areaToSign[20] = {0x1, 0x03, 0x05};
    UINT32 areaToSignSize = 20;
    BYTE sig[256];
    UINT32 sigSize = 256; //need to set this!!!
    if (utpm_sign_data(keyHandle, keyAuth, areaToSignSize, areaToSign, &sigSize, sig) != UTPM_SUCCESS) {
        printf("Sign data failed.\n");
        exit(EXIT_FAILURE);
    }
    BYTE fakeAreaToSing[20] = {0x2,0x3};
    printf_buf("Signature is", sig, sigSize);
    if (utpm_verify_data(&wrappedKey.pubKey, sigSize, sig, areaToSignSize, areaToSign) != UTPM_SUCCESS) {
        printf("Verify data failed.\n");
        exit(EXIT_FAILURE);
    }
    printf("Verify data succeed.\n");
    
#endif
    /* Test 3: pcr extend pcr read */
    UTPM_PCRINDEX pcrNum = 0x07;
    UTPM_DIGEST inDigest = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    if (utpm_pcr_extend(pcrNum, &inDigest) != UTPM_SUCCESS) {
        printf("extend PCR 0 failed.\n");
        exit(EXIT_FAILURE);
    }
    printf("extend PCR 0x%x succeed.\n", pcrNum);
    UTPM_DIGEST outDigest;
    if (utpm_pcr_read(pcrNum, &outDigest) != UTPM_SUCCESS) {
        printf("read PCR 0x%x failed.\n", pcrNum);
        exit(EXIT_FAILURE);
    }
    printf_buf("PCR  is", &outDigest, sizeof(UTPM_DIGEST));

#if 0
    /* Test 4: hash */
    BYTE data[] = "23333333333333333333333";
    UTPM_DIGEST digest;
    if (utpm_make_hash(sizeof(data), data, &digest) != UTPM_SUCCESS) {
        printf("hash failed.\n");
        exit(EXIT_FAILURE);
    }
    printf_buf("digest is ", &digest, sizeof(UTPM_DIGEST));
#endif

}

