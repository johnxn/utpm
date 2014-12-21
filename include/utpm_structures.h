#ifndef _UTPM_STRUCTURES_H
#define _UTPM_STRUCTURES_H

#include "tpm_structures.h"

typedef   TPM_RESULT          UTPM_RESULT;
typedef   TPM_DIGEST          UTPM_DIGEST;
typedef   TPM_PCRINDEX        UTPM_PCRINDEX;
typedef   TPM_RESOURCE_TYPE   UTPM_RESOURCE_TYPE;
typedef   TPM_HANDLE          UTPM_HANDLE;
typedef   TPM_STORE_PUBKEY    UTPM_STORE_PUBKEY;
typedef   TPM_SECRET          UTPM_SECRET;
typedef   TPM_KEY_HANDLE      UTPM_KEY_HANDLE;
typedef   TPM_KEY             UTPM_KEY;
typedef   TPM_ENTITY_TYPE     UTPM_ENTITY_TYPE;
typedef   TPM_AUTHHANDLE      UTPM_AUTHHANDLE;
typedef   TPM_NONCE           UTPM_NONCE;
typedef   TPM_KEY_USAGE       UTPM_KEY_USAGE;

#define   UTPM_RT_KEY    TPM_RT_KEY
#define   UTPM_RT_AUTH   TPM_RT_AUTH

#define   UTPM_KH_SRK     TPM_KH_SRK
#define   UTPM_KH_OWNER   TPM_KH_OWNER

#define   UTPM_KEY_SIGNING    TPM_KEY_SIGNING
#define   UTPM_KEY_STORAGE    TPM_KEY_STORAGE
#define   UTPM_KEY_BIND       TPM_KEY_BIND
#define   UTPM_KEY_IDENTITY   TPM_KEY_IDENTITY

#define UTPM_NON_FATAL                   0x00000800
#define UTPM_BASE                        0x00000000

#define sizeof_UTPM_KEY sizeof_TPM_KEY
#define free_UTPM_KEY free_TPM_KEY

#define utpm_unmarshal_TPM_KEY tpm_unmarshal_TPM_KEY
#define utpm_marshal_TPM_KEY tpm_marshal_TPM_KEY

#define UTPM_SUCCESS                     (UTPM_BASE + 0)
#define UTPM_AUTHFAIL                    (UTPM_BASE + 1)
#define UTPM_BADINDEX                    (UTPM_BASE + 2)
#define UTPM_BAD_PARAMETER               (UTPM_BASE + 3)
#define UTPM_AUDITFAILURE                (UTPM_BASE + 4)
#define UTPM_CLEAR_DISABLED              (UTPM_BASE + 5)
#define UTPM_DEACTIVATED                 (UTPM_BASE + 6)
#define UTPM_DISABLED                    (UTPM_BASE + 7)
#define UTPM_DISABLED_CMD                (UTPM_BASE + 8)
#define UTPM_FAIL                        (UTPM_BASE + 9)
#define UTPM_BAD_ORDINAL                 (UTPM_BASE + 10)
#define UTPM_INSTALL_DISABLED            (UTPM_BASE + 11)
#define UTPM_INVALID_KEYHANDLE           (UTPM_BASE + 12)
#define UTPM_KEYNOTFOUND                 (UTPM_BASE + 13)
#define UTPM_INAPPROPRIATE_ENC           (UTPM_BASE + 14)
#define UTPM_MIGRATEFAIL                 (UTPM_BASE + 15)
#define UTPM_INVALID_PCR_INFO            (UTPM_BASE + 16)
#define UTPM_NOSPACE                     (UTPM_BASE + 17)
#define UTPM_NOSRK                       (UTPM_BASE + 18)
#define UTPM_NOTSEALED_BLOB              (UTPM_BASE + 19)
#define UTPM_OWNER_SET                   (UTPM_BASE + 20)
#define UTPM_RESOURCES                   (UTPM_BASE + 21)
#define UTPM_SHORTRANDOM                 (UTPM_BASE + 22)
#define UTPM_SIZE                        (UTPM_BASE + 23)
#define UTPM_WRONGPCRVAL                 (UTPM_BASE + 24)
#define UTPM_BAD_PARAM_SIZE              (UTPM_BASE + 25)
#define UTPM_SHA_THREAD                  (UTPM_BASE + 26)
#define UTPM_SHA_ERROR                   (UTPM_BASE + 27)
#define UTPM_FAILEDSELFTEST              (UTPM_BASE + 28)
#define UTPM_AUTH2FAIL                   (UTPM_BASE + 29)
#define UTPM_BADTAG                      (UTPM_BASE + 30)
#define UTPM_IOERROR                     (UTPM_BASE + 31)
#define UTPM_ENCRYPT_ERROR               (UTPM_BASE + 32)
#define UTPM_DECRYPT_ERROR               (UTPM_BASE + 33)
#define UTPM_INVALID_AUTHHANDLE          (UTPM_BASE + 34)
#define UTPM_NO_ENDORSEMENT              (UTPM_BASE + 35)
#define UTPM_INVALID_KEYUSAGE            (UTPM_BASE + 36)
#define UTPM_WRONG_ENTITYTYPE            (UTPM_BASE + 37)
#define UTPM_INVALID_POSTINIT            (UTPM_BASE + 38)
#define UTPM_INAPPROPRIATE_SIG           (UTPM_BASE + 39)
#define UTPM_BAD_KEY_PROPERTY            (UTPM_BASE + 40)
#define UTPM_BAD_MIGRATION               (UTPM_BASE + 41)
#define UTPM_BAD_SCHEME                  (UTPM_BASE + 42)
#define UTPM_BAD_DATASIZE                (UTPM_BASE + 43)
#define UTPM_BAD_MODE                    (UTPM_BASE + 44)
#define UTPM_BAD_PRESENCE                (UTPM_BASE + 45)
#define UTPM_BAD_VERSION                 (UTPM_BASE + 46)
#define UTPM_NO_WRAP_TRANSPORT           (UTPM_BASE + 47)
#define UTPM_AUDITFAIL_UNSUCCESSFUL      (UTPM_BASE + 48)
#define UTPM_AUDITFAIL_SUCCESSFUL        (UTPM_BASE + 49)
#define UTPM_NOTRESETABLE                (UTPM_BASE + 50)
#define UTPM_NOTLOCAL                    (UTPM_BASE + 51)
#define UTPM_BAD_TYPE                    (UTPM_BASE + 52)
#define UTPM_INVALID_RESOURCE            (UTPM_BASE + 53)
#define UTPM_NOTFIPS                     (UTPM_BASE + 54)
#define UTPM_INVALID_FAMILY              (UTPM_BASE + 55)
#define UTPM_NO_NV_PERMISSION            (UTPM_BASE + 56)
#define UTPM_REQUIRES_SIGN               (UTPM_BASE + 57)
#define UTPM_KEY_NOTSUPPORTED            (UTPM_BASE + 58)
#define UTPM_AUTH_CONFLICT               (UTPM_BASE + 59)
#define UTPM_AREA_LOCKED                 (UTPM_BASE + 60)
#define UTPM_BAD_LOCALITY                (UTPM_BASE + 61)
#define UTPM_READ_ONLY                   (UTPM_BASE + 62)
#define UTPM_PER_NOWRITE                 (UTPM_BASE + 63)
#define UTPM_FAMILYCOUNT                 (UTPM_BASE + 64)
#define UTPM_WRITE_LOCKED                (UTPM_BASE + 65)
#define UTPM_BAD_ATTRIBUTES              (UTPM_BASE + 66)
#define UTPM_INVALID_STRUCTURE           (UTPM_BASE + 67)
#define UTPM_KEY_OWNER_CONTROL           (UTPM_BASE + 68)
#define UTPM_BAD_COUNTER                 (UTPM_BASE + 69)
#define UTPM_NOT_FULLWRITE               (UTPM_BASE + 70)
#define UTPM_CONTEXT_GAP                 (UTPM_BASE + 71)
#define UTPM_MAXNVWRITES                 (UTPM_BASE + 72)
#define UTPM_NOOPERATOR                  (UTPM_BASE + 73)
#define UTPM_RESOURCEMISSING             (UTPM_BASE + 74)
#define UTPM_DELEGATE_LOCK               (UTPM_BASE + 75)
#define UTPM_DELEGATE_FAMILY             (UTPM_BASE + 76)
#define UTPM_DELEGATE_ADMIN              (UTPM_BASE + 77)
#define UTPM_TRANSPORT_NOTEXCLUSIVE      (UTPM_BASE + 78)
#define UTPM_OWNER_CONTROL               (UTPM_BASE + 79)
#define UTPM_DAA_RESOURCES               (UTPM_BASE + 80)
#define UTPM_DAA_INPUT_DATA0             (UTPM_BASE + 81)
#define UTPM_DAA_INPUT_DATA1             (UTPM_BASE + 82)
#define UTPM_DAA_ISSUER_SETTINGS         (UTPM_BASE + 83)
#define UTPM_DAA_UTPM_SETTINGS            (UTPM_BASE + 84)
#define UTPM_DAA_STAGE                   (UTPM_BASE + 85)
#define UTPM_DAA_ISSUER_VALIDITY         (UTPM_BASE + 86)
#define UTPM_DAA_WRONG_W                 (UTPM_BASE + 87)
#define UTPM_BAD_HANDLE                  (UTPM_BASE + 88)
#define UTPM_BAD_DELEGATE                (UTPM_BASE + 89)
#define UTPM_BADCONTEXT                  (UTPM_BASE + 90)
#define UTPM_TOOMANYCONTEXTS             (UTPM_BASE + 91)
#define UTPM_MA_TICKET_SIGNATURE         (UTPM_BASE + 92)
#define UTPM_MA_DESTINATION              (UTPM_BASE + 93)
#define UTPM_MA_SOURCE                   (UTPM_BASE + 94)
#define UTPM_MA_AUTHORITY                (UTPM_BASE + 95)
#define UTPM_PERMANENTEK                 (UTPM_BASE + 97)
#define UTPM_BAD_SIGNATURE               (UTPM_BASE + 98)
#define UTPM_NOCONTEXTSPACE              (UTPM_BASE + 99)
#define UTPM_RETRY                       (UTPM_BASE + UTPM_NON_FATAL)
#define UTPM_NEEDS_SELFTEST              (UTPM_BASE + UTPM_NON_FATAL + 1)
#define UTPM_DOING_SELFTEST              (UTPM_BASE + UTPM_NON_FATAL + 2)
#define UTPM_DEFEND_LOCK_RUNNING         (UTPM_BASE + UTPM_NON_FATAL + 3)


#endif /* _UTPM_STRUCTURES_H */
