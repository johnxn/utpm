#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rockey_apis.h"

DONGLE_HANDLE rockeyHandle;

DWORD open_rockey(BYTE isPriv, BYTE *pin) {
    int key_count;
    int key_id;
    DWORD errcode;
    int remain_count;
    errcode = Dongle_Enum(NULL, &key_count);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    if (key_count > 1) {
        printf("Input which key to use <0-%d>: ", key_count-1);
        scanf("%d", &key_id);
    }
    else {
        key_id = 0;
    }
    errcode = Dongle_Open(&rockeyHandle, key_id);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    if (isPriv) {
        BYTE pin2[17];
        memset(pin2, 0xff, sizeof(pin2));
        memcpy(pin2, pin, strlen(pin));
        pin2[16] = '\0';
        errcode = Dongle_VerifyPIN(rockeyHandle, FLAG_ADMINPIN, pin2, &remain_count);
        if (errcode != DONGLE_SUCCESS) {
            return errcode;
        }
    }
    return DONGLE_SUCCESS;
}

DWORD change_admin_pin(BYTE *oldPin, BYTE *newPin) {
    DWORD errcode;
    BYTE oldPin2[17];
    BYTE newPin2[17];
    memset(oldPin2, 0xff, sizeof(oldPin2));
    memset(newPin2, 0xff, sizeof(newPin2));
    oldPin2[16] = '\0';
    newPin2[16] = '\0';
    memcpy(oldPin2, oldPin, strlen(oldPin));
    memcpy(newPin2, newPin, strlen(newPin));
    errcode = Dongle_ChangePIN(rockeyHandle, FLAG_ADMINPIN, oldPin2, newPin2, 0xFF);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}

DWORD get_uniquekey(BYTE *adminPIN) {
    DWORD errcode;
    BYTE seed[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    char pidStr[10];
    errcode = Dongle_GenUniqueKey(rockeyHandle, sizeof(seed), seed, pidStr, adminPIN);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}

DWORD run_bin_file(BYTE *inoutbuf, WORD len) {
    DWORD errcode;
    if ((errcode = Dongle_RunExeFile(rockeyHandle, 0x0001, inoutbuf, len, NULL)) != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}

DWORD download_bin_file(char *path) {
    char bin_data[1024*64];
    memset(bin_data, 0, sizeof(bin_data));
    FILE *bin_file;
    short data_size;
    short i;
    int errcode;
    bin_file = fopen(path, "r");
    if (bin_file == NULL) {
        perror(path);
        exit(EXIT_FAILURE);
    }
    fseek(bin_file, 0, SEEK_END);
    data_size = ftell(bin_file);
    fseek(bin_file, 0, SEEK_SET);
    fread(bin_data, sizeof(char), data_size, bin_file);
    if (fclose(bin_file) != 0) {
        perror(path);
        exit(EXIT_FAILURE);
    }
    EXE_FILE_INFO pExeFileInfo;
    pExeFileInfo.m_dwSize = data_size;
    pExeFileInfo.m_wFileID = 0x0001;
    pExeFileInfo.m_Priv = 0;
    pExeFileInfo.m_pData = bin_data;
    errcode = Dongle_DownloadExeFile(rockeyHandle, &pExeFileInfo, 1);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}

DWORD encrypt_with_pubkey(RSA_PUBLIC_KEY *pubkey, BYTE *input, DWORD inputSize, BYTE *output, DWORD *outputSize) {
    DWORD errcode;
    errcode = Dongle_RsaPub(rockeyHandle, FLAG_ENCODE, pubkey, input, inputSize, output, outputSize);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}

DWORD decrypt_with_pubkey(RSA_PUBLIC_KEY *pubkey, BYTE *input, DWORD inputSize, BYTE *output, DWORD *outputSize) {
    DWORD errcode;
    errcode = Dongle_RsaPub(rockeyHandle, FLAG_DECODE, pubkey, input, inputSize, output, outputSize);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}


DWORD get_random(BYTE *buf, DWORD size) {
    DWORD errcode;
    errcode = Dongle_GenRandom(rockeyHandle, size, buf);
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}

DWORD read_rsa_pubkey(DWORD fileid, RSA_PUBLIC_KEY *pubkey) {
    DWORD errcode;
    errcode = Dongle_ReadFile(rockeyHandle, fileid, 0, (BYTE *)pubkey, sizeof(RSA_PUBLIC_KEY));
    if (errcode != DONGLE_SUCCESS) {
        return errcode;
    }
    return DONGLE_SUCCESS;
}


