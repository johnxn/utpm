#ifndef __REQUEST_LENGTH_H
#define __REQUEST_LENGTH_H
#define LENGTH_OSAP  (2 + /*tag*/ \
                    4 + /*size */ \
                    4 + /*ordinal*/ \
                    2 + /*entityType*/ \
                    4 + /*entityValue*/ \
                    20) /*nonceOddOSAP*/
 
#define LENGTH_CREATE_WRAPPEDKEY (2 + /*tag*/ \
                           4 + /*size*/ \
                           4 + /*ordinal*/ \
                           4 + /*parentHandle*/ \
                           20 + /*dataUsageAuth*/ \
                           20 + /*dataMigrationAuth*/ \
                           2 + /*keyInfo.tag*/ \
                           2 + /*keyInfo.fill*/ \
                           2 + /*keyInfo.keyUsage*/ \
                           4 + /*keyInfo.keyFlags*/ \
                           1 + /*keyInfo.authDataUsage*/ \
                           4 + /*keyInfo.algorithmParms.algorithmID*/ \
                           2 + /*keyInfo.algorithmParms.encScheme*/ \
                           2 + /*keyInfo.algorithmParms.sigScheme*/ \
                           4 + /*keyInfo.algorithmParms.parmSize*/ \
                           4 + /*keyInfo.algorithmParms.rsa.keyLength*/ \
                           4 + /*keyInfo.algorithmParms.rsa.numPrimes*/ \
                           4 + /*keyInfo.algorithmParms.rsa.exponentSize*/ \
                           4 + /*keyInfo.PCRInfoSize*/ \
                           4 + /*keyInfo.pubKey.keyLength*/ \
                           4 + /*keyInfo.encDataSize*/ \
                           4 + /*authHandle*/ \
                           20 + /*nonceOdd*/ \
                           1 + /*continueAuthSession*/ \
                           20)

#define LENGTH_LOAD_KEY (2 + /*tag*/ \
                           4 + /*size*/ \
                           4 + /*ordinal*/ \
                           4 + /*parentHandle*/ \
                           sizeof_TPM_KEY((*inKey)) + \
                           4 + /*authHandle*/ \
                           20 + /*nonceOdd*/ \
                           1 + /*continueAuthSession*/ \
                           20) /*pubAuth*/

#define LENGTH_UNBIND (2 + /*tag*/ \
                           4 + /*size*/ \
                           4 + /*ordinal*/ \
                           4 + /*keyHandle*/ \
                           4 + /*inDataSize*/ \
                           inDataSize + /*inData*/ \
                           4 + /*authHandle*/ \
                           20 + /*nonceOdd*/ \
                           1 + /*continueAuthSession*/ \
                           20) /*pubAuth*/

 #define LENGTH_SIGN (2 + /*tag*/ \
                           4 + /*size*/ \
                           4 + /*ordinal*/ \
                           4 + /*keyHandle*/ \
                           4 + /*areaToSignSize*/ \
                           areaToSignSize + /*areaToSign*/ \
                           4 + /*authHandle*/ \
                           20 + /*nonceOdd*/ \
                           1 + /*continueAuthSession*/ \
                           20) /*pubAuth*/
 
#define LENGTH_FLUSH (2 + /*tag*/ \
                           4 + /*size */ \
                           4 + /*ordinal*/ \
                           4 + /*handle*/ \
                           4) /*resourceType*/

#define LENGTH_OWNERSHIP  (2 + /*tag*/ \
                           4 + /*size */ \
                           4 + /*ordinal*/ \
                           2 + /*protocolID*/ \
                           4 + /*encOwnerAuthSize*/ \
                           256 + /*encOwnerAuth*/ \
                           4 + /*encSrkAuthSize*/ \
                           256 + /*encSrkAuth*/ \
                           2 + /*srkParams.tag*/ \
                           2 + /*srkParams.fill*/ \
                           2 + /*srkParams.keyUsage*/ \
                           4 + /*srkParams.keyFlags*/ \
                           1 + /*srkParams.authDataUsage*/ \
                           4 + /*srkParams.algorithmParms.algorithmID*/ \
                           2 + /*srkParams.algorithmParms.encScheme*/ \
                           2 + /*srkParams.algorithmParms.sigScheme*/ \
                           4 + /*srkParams.algorithmParms.parmSize*/ \
                           4 + /*srkParams.algorithmParms.rsa.keyLength*/ \
                           4 + /*srkParams.algorithmParms.rsa.numPrimes*/ \
                           4 + /*srkParams.algorithmParms.rsa.exponentSize*/ \
                           4 + /*srkParams.PCRInfoSize*/ \
                           4 + /*srkParams.pubKey.keyLength*/ \
                           4 + /*srkParams.encDataSize*/ \
                           4 + /*authHandle*/ \
                           20 + /*nonceOdd*/ \
                           1 + /*continueAuthSession*/ \
                           20) /*ownerAuth*/

#endif
