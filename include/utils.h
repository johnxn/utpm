#ifndef _UTILS_H
#define _UTILS_H

#include "tpm_structures.h"
#include "tpm_marshalling.h"
#include "hmac.h"
#include "sha1.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
UINT32 get_in_param_offset(TPM_COMMAND_CODE ordinal);


void compute_in_parm_digest(BYTE *digest, TPM_COMMAND_CODE ordinal, BYTE *ptr, UINT32 length);
void compute_auth_data(TPM_AUTH *auth);

void compute_shared_secret(TPM_SECRET secret, TPM_NONCE *nonceEvenOSAP, TPM_NONCE *nonceOddOSAP, TPM_SECRET sharedSecret);
void tpm_encrypt_auth_secret(TPM_SECRET plainAuth, TPM_SECRET secret, TPM_NONCE *nonce, TPM_ENCAUTH encAuth);


void printf_buf(char *head, void *buff, int size);
void printf_TPM_AUTH_REQ(BYTE **ptr, UINT32 *length);
void printf_TPM_AUTH_RES(BYTE **ptr, UINT32 *length);
void printf_TPM_REQUEST(BYTE *buf);
void printf_TPM_RESPONSE(BYTE *buf, TPM_COMMAND_CODE ordinal);

void printf_TPM_KEY_DATA(TPM_KEY_DATA *key);
void printf_sessions(TPM_SESSION_DATA *sessions);
void printf_TPM_SESSION_DATA(TPM_SESSION_DATA *session);
void printf_TPM_KEY(TPM_KEY *wrappedKey);
void printf_TPM_CERIFTY_INFO(TPM_CERTIFY_INFO *certInfo);
void printf_TPM_PCR_SELECTION(TPM_PCR_SELECTION *pcrSelection);
void printf_TPM_PCR_COMPOSITE(TPM_PCR_COMPOSITE *pcrComposite);
#endif /* _UTILS_H */

