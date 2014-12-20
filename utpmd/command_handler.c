#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include "command_handler.h"
#include "rockey_apis.h"


int setup_error(unsigned char *out, int *out_size, int errcode) {
    int err = 0xffffffff;
    memcpy(out, &err, sizeof(int));
    memcpy(out+sizeof(int), &errcode, sizeof(int));
    *out_size = sizeof(int) *2;
    return 0;
}

int handle_command(unsigned char *in, int in_size, unsigned char *out, int *out_size) {
    DWORD errcode;
    int command;
    BYTE InOutBuf[INOUTBUF_LEN];
    memset(InOutBuf, 0, sizeof(InOutBuf));
    memcpy(InOutBuf, in, in_size);
    memcpy(&command, InOutBuf, sizeof(int));
    switch(command) {
        case COMMAND_GET_RANDOM: {
           DWORD buf_size;
           memcpy(&buf_size, InOutBuf+sizeof(int), sizeof(int));
           BYTE *buf = malloc(buf_size);
           if (buf == NULL) {
               syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
               return errno;
           }
           if ((errcode = get_random(buf, buf_size)) != DONGLE_SUCCESS) {
               free(buf);
               syslog(LOG_ERR, "get_random() failed: %x", errcode);
               return errcode;
           }
           memset(InOutBuf, 0, sizeof(InOutBuf));
           memcpy(InOutBuf, &buf_size, sizeof(int));
           memcpy(InOutBuf+sizeof(int), buf, buf_size);
           free(buf);
           break;
        }
        case COMMAND_ENCRYPT_PUB: {
            RSA_PUBLIC_KEY pubkey;
            DWORD inputSize;
            BYTE *input;
            memcpy(&pubkey, InOutBuf+sizeof(int), sizeof(RSA_PUBLIC_KEY));
            memcpy(&inputSize, InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY), sizeof(int));
            input = malloc(inputSize);
            if (input == NULL) {
                syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
                return errno;
            }
            memcpy(input, InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY)+sizeof(int), inputSize);
            DWORD outputSize = ENCRYPTED_BLOB_SIZE;
            BYTE *output = malloc(outputSize);
            if ((errcode = encrypt_with_pubkey(&pubkey, input, inputSize, output, &outputSize)) != DONGLE_SUCCESS) {
                free(output);
                syslog(LOG_ERR, "encrypt_with_pubkey() failed: %x", errcode);
                return errcode;
            }
            memset(InOutBuf, 0, sizeof(InOutBuf));
            memcpy(InOutBuf, &outputSize, sizeof(DWORD));
            memcpy(InOutBuf+sizeof(DWORD), output, outputSize);
            free(output);
            break;
        }
        case COMMAND_DECRYPT_PUB: {
            RSA_PUBLIC_KEY pubkey;
            DWORD inputSize;
            BYTE *input;
            memcpy(&pubkey, InOutBuf+sizeof(int), sizeof(RSA_PUBLIC_KEY));
            memcpy(&inputSize, InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY), sizeof(int));
            input = malloc(inputSize);
            if (input == NULL) {
                syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
                return errno;
            }
            memcpy(input, InOutBuf+sizeof(int)+sizeof(RSA_PUBLIC_KEY)+sizeof(int), inputSize);
            DWORD outputSize = INPUT_BLOB_SIZE; // max to-be-encrypted data length.
            BYTE *output = malloc(outputSize);
            if ((errcode = decrypt_with_pubkey(&pubkey, input, inputSize, output, &outputSize)) != DONGLE_SUCCESS) {
                free(output);
                syslog(LOG_ERR, "decrypt_with_pubkey() failed: %x", errcode);
                return errcode;
            }
            memset(InOutBuf, 0, sizeof(InOutBuf));
            memcpy(InOutBuf, &outputSize, sizeof(DWORD));
            memcpy(InOutBuf+sizeof(DWORD), output, outputSize);
            free(output);
            break;
        }
        default: {
            if ((errcode = run_bin_file(InOutBuf, sizeof(InOutBuf))) != DONGLE_SUCCESS) {
                syslog(LOG_ERR, "run_bin_file() failed: %x", errcode);
                return errcode;
             }
        }
    }
    *out_size = INOUTBUF_LEN;
    memcpy(out, InOutBuf, *out_size);
    return 0;
}
