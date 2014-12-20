
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "Dongle_CORE.h"
#include "Dongle_API.h"

#include <unistd.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>




int     Count;
DONGLE_INFO * pKEYList=NULL;
//
DONGLE_HANDLE  hKey=NULL;

static int O_flag = 0;
static int uq_flag[64];
static int index_num;

void ShowMainCmdMenu()
{	
	printf("\r\nDONGLE TEST MAIN MENU:");
	printf("\r\n=================================================================\r\n");
	printf(	"  [E]mum         [O]pen              [C]lose         [L]EDControl     \n"
			"  [G]enRandom    [F]ileTest          Enc[R]yptTest   [M]emoryTest     \n"
			"  [U]pdateTest   Au[T]horityTest     [V]erifyPIN     Mother[S]onTest  \n"
			"  Change[P]IN    SetUser[I]D         See[d]Test      RunE[x]e         \n"
			"  [Q]uit 													\n"
		  );
}

void ShowFileCmdMenu()
{
	printf("\r\nDONGLE FILE TEST  MENU:");
	printf("\r\n=================================================================\r\n");
	printf(	"  [C]reatFiles         [L]istFiles            [D]leteFiles         \n"
			"  [W]riteFiles         [R]eadFiles            E[X]it        \n"
		);		
}

void ShowEncryptCmdMenu()
{
	printf("\r\nDONGLE ENCRYPT TEST  MENU:");
	printf("\r\n=================================================================\r\n");
	printf(	"  [R]SA         [E]CC        [T]DES              \n"
		    "  [H]ASH        E[X]it        \n"
		);		
}

void ShowMotherSonCmdMenu()
{	
	printf("\r\nDONGLE Mother Son TEST  MENU:");
	printf("\r\n=================================================================\r\n");
	printf(	"  [G]enMother   [I]nitSon        E[X]it        \n" );		
}

char WaitForUserInput()
{
	char  ic;
	char  temp;
	//
	printf("\nPlease Input selection:");
	fflush(stdin);
	//
	ic = getchar();
	temp = getchar();
	//
	fflush(stdin);

	//
	return ic;
}

void StrPrintf(LPCTSTR fmt, ...)
{
	va_list vals;
    char buf[1024];
	//
	memset(buf, 0, sizeof(buf));
	//	
	va_start(vals, fmt); 	
	vsprintf(buf, fmt, vals);
	va_end(vals);
	//
//	strcat(buf, "\n");
	//
	printf(buf);
}

DWORD showRet(const char *name , DWORD dwRet)
{
	if (DONGLE_SUCCESS != dwRet)
	{
		StrPrintf("\r\n%s retcode=%08X\r\n",name, dwRet);
	}
	else
	{
		StrPrintf("\r\n%s success\r\n",name, dwRet);
	}
	return dwRet;
	
}

void SaveBinFile(char* pname, BYTE* pbuf, int len)
{
	FILE*  pf;  
	//
	pf = fopen(pname, "wb");
	//
	if(pf) 
	{
		fwrite(pbuf, len, 1, pf);
		//
		fclose(pf);
	}
}

//
void ReadBinFile(char* pname, BYTE* pbuf, int len)
{
	FILE* pf;
	//
	pf = fopen(pname, "rb");
	//
	if(pf) 
	{
		fread(pbuf, len, 1, pf);
		//
		fclose(pf);
	}
}

void ShowBinHex(unsigned char* pBin, int len)
{
	// Show 16 bytes each line.
	int  i, j ,k, kk;
	int  lLines = len / 16;
	int  lCharInLastLine = 0;
	//
	if(0 != len % 16)
	{
		lCharInLastLine = len - lLines * 16;
	}

	for(i = 0; i < lLines; ++i)
	{
		for(j = 0; j < 16; ++j)
		{
			printf("%02X ", pBin[16 * i + j]);

			if(j == 7)
				printf("- ");
		}

		printf("    ");

/*		for(j = 0; j < 16; ++j)
		{
			if(isprint(pBin[16 * i + j]))
				printf("%c", pBin[16 * i + j]);
			else
				printf(".");
		}*/

		printf("\n");
	}

	if(0 != lCharInLastLine)
	{
		for(j = 0; j < lCharInLastLine; ++j)
		{
			printf("%02X ", pBin[16 * i + j]);

			if(j == 7 && lCharInLastLine > 8)
				printf("- ");
		}

		k = 0;

		k += ((16 - lCharInLastLine) * 3);

		if(lCharInLastLine <= 8)
		{
			k += 2;
		}

		for(kk = 0; kk < k; ++kk)
			printf(" ");

		printf("    ");

	/*	for(j = 0; j < lCharInLastLine; ++j)
		{
			if(isprint(pBin[16 * i + j]))
				printf("%c", pBin[16 * i + j]);
			else
				printf(".");
		}*/

		printf("\n");
	}
	printf("\n");
}


void DongleEnum()
{
	int   i;
	DWORD dwRet;
	
	//
	dwRet = Dongle_Enum(NULL, &Count);

	if( dwRet != 0 || Count == 0 )
	{
		StrPrintf("ROCKEY-ARM not found, Dongle_Enum(1) = %08X\r\n", dwRet);
		return;
	}

	//
	pKEYList = malloc( sizeof(DONGLE_INFO) * Count);
	dwRet = Dongle_Enum(pKEYList, &Count);  
	//
	if( dwRet != 0 )
	{
		StrPrintf("ROCKEY-ARM not found, Dongle_Enum(2) = %08X\r\n", dwRet);
		return;
	}
	//
	for( i=0; i<Count; i++)
	{
		StrPrintf("======KEY: %d======\r\n", i);
		StrPrintf("Version:%04X\r\n", pKEYList[i].m_Ver);
        StrPrintf("BirthDay: ");
		ShowBinHex(pKEYList[i].m_BirthDay, 8); 
		StrPrintf("Agent:  %08X\r\n", pKEYList[i].m_Agent);
		StrPrintf("PID:    %08X\r\n", pKEYList[i].m_PID);
		StrPrintf("UserID: %08X\r\n", pKEYList[i].m_UserID);
		StrPrintf("Mother: %08X\r\n", pKEYList[i].m_IsMother);		
		StrPrintf("HID: ");
		ShowBinHex(pKEYList[i].m_HID, 8);

	}
	//
    StrPrintf("The number of Rockey-ARM : %d \n", i);
	//

	free(pKEYList);

}



void OpenDongle()
{
	int   index;
    DWORD retcode;
	char  buff[16];

	//
	if(Count > 1)
	{
		memset(buff, 0, sizeof(buff));
		printf("Please Input key's index need to open <0-%d>: ", Count-1);
		fflush(stdin);
		gets(buff);
		//
	    index = atoi(buff);
	}
	else
	{
        index = 0;
	}
	//
	retcode = Dongle_Open(&hKey, index);
	if(DONGLE_SUCCESS == retcode)
	{
		O_flag = 1;
		index_num = index;
	}
	// 
	showRet("Dongle_Open()" , retcode);

}

void CloseDongle()
{
	DWORD retcode;

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		retcode = Dongle_ResetState(hKey);
		showRet("Dongle_ResetState()" , retcode);

		retcode = Dongle_Close(hKey);
		if(DONGLE_SUCCESS == retcode)
			O_flag = 0;
		showRet("Dongle_Close()" , retcode); 
	}
}

void SetUserID()
{
	DWORD  retcode;

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		retcode = Dongle_SetUserID(hKey, 0x18000001);
		showRet("Dongle_SetUserID()" , retcode);
	}
}

void  SeedTest()
{
	int    i;
	DWORD  retcode;
	BYTE   tmpbuf[256];
	BYTE   outbuf[16];

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		memset(tmpbuf, 0, sizeof(tmpbuf));
		printf("Set Seed Limit Count press 1, Run Seed press 0: ");
		fflush(stdin);
		gets(tmpbuf);
		//
		i = atoi(tmpbuf);
		//
		if(i == 1)
		{
		   memset(tmpbuf, 0, sizeof(tmpbuf));
		   printf("Please input the Count to Limit: ");
		   fflush(stdin);
		   gets(tmpbuf);
		   //
		   i = atoi(tmpbuf);
		   //
		   retcode = Dongle_LimitSeedCount(hKey, i);
		   showRet("Dongle_LimitSeedCount()" , retcode);
		}
		else if(i == 0)
		{
			memset(tmpbuf, 0, sizeof(tmpbuf));
			printf("Please input the Seed <1-250>: ");
			fflush(stdin);
			gets(tmpbuf);
			//
			i = strlen(tmpbuf);
			//
			if(i < 1 || i > 250)
			{
				printf("Seed len must at <1-250>");
				return;
			}
			//
			memset(outbuf, 0, sizeof(outbuf));
			//
			retcode = Dongle_Seed(hKey, tmpbuf, i, outbuf);
			showRet("Dongle_Seed()" , retcode);
			//
			ShowBinHex(outbuf, 16);
		}
	}
}

void DongleGenRandom()
{
	DWORD retcode;
	BYTE   bybuff[128];
	int   len_need;

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		memset(bybuff, 0, sizeof(bybuff));
		printf("Please Input len needed <1-128>: ");
		fflush(stdin);
		gets((char*)bybuff);
		//
		len_need = atoi((char*)bybuff);
		//
		memset(bybuff, 0, sizeof(bybuff));
		//
		retcode = Dongle_GenRandom(hKey , len_need, bybuff); 
		showRet("Dongle_GenRandom()", retcode);
		//
		ShowBinHex(bybuff, len_need);
	}
}

void DongleLEDControl()
{
	DWORD retcode;

	
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		printf("led  will  off => on => wink \n");

		retcode = Dongle_LEDControl(hKey , LED_OFF);//灭

		showRet("Dongle_LEDControl(LED_OFF)" , retcode); 

		usleep(1000);

		retcode = Dongle_LEDControl(hKey , LED_ON);//亮

		showRet("Dongle_LEDControl(LED_ON)" , retcode);

		usleep(1000);

		retcode = Dongle_LEDControl(hKey , LED_BLINK);//闪

		showRet("Dongle_LEDControl(LED_BLINK)" , retcode);

	}
}

void  RSATestIt(WORD fileid, PRIKEY_FILE_ATTR* pPFA)
{
	int   i, inlen, outlen;
	DWORD retcode;
	BYTE  inbuf[256];
	BYTE  outbuf[256];
	RSA_PUBLIC_KEY  pub_key;
    RSA_PRIVATE_KEY pri_key;

	//
	memset(&pub_key, 0, sizeof(pub_key));
	memset(&pri_key, 0, sizeof(pri_key));
	//
	inlen = (pPFA->m_Size / 8) - 11;
	//
    memset(inbuf, 0, sizeof(inbuf));	
	//
	for(i=0; i<inlen; i++)
	{
        inbuf[i] = i;
	}
	//创建私钥文件	
    retcode = Dongle_CreateFile(hKey, FILE_PRIKEY_RSA, fileid, pPFA);
	showRet("Dongle_CreateFile()", retcode); 
	if(retcode != 0 && retcode != DONGLE_FILE_EXIST) return;
	
	StrPrintf("Begin to generate the key pair ......\n");
	//产生公私钥对
	retcode = Dongle_RsaGenPubPriKey(hKey, fileid, &pub_key, &pri_key);
	showRet("Dongle_RsaGenPubPriKey()", retcode); 
	if(retcode != 0) return;
	
	StrPrintf("Generate %d keys to success!\r\n", pub_key.bits);

    //对于1024位的公私钥生成个文件出来作为远程升级公私钥测试用
	if(pub_key.bits == 1024)
	{
       SaveBinFile("PubKey.bin", (BYTE*)&pub_key, sizeof(pub_key));
	   SaveBinFile("PriKey.bin", (BYTE*)&pri_key, sizeof(pri_key));
	}
    //
	StrPrintf("Plaintext data: \n");
    ShowBinHex(inbuf, inlen); 
	
	//私钥加密(签名)
	memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPri(hKey, fileid, FLAG_ENCODE, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPri(FLAG_ENCODE)", retcode); 
	if(retcode != 0) return;

	StrPrintf("Private key encryption result: \n");
	ShowBinHex(outbuf, outlen);

	//公钥解密(验签)
	memset(inbuf, 0, sizeof(inbuf));
	inlen = outlen;
	memcpy(inbuf, outbuf, inlen);
    memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPub(hKey, FLAG_DECODE, &pub_key, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPub(FLAG_DECODE)", retcode); 
	if(retcode != 0) return;

	StrPrintf("Public key to decrypt the result: \n");
	ShowBinHex(outbuf, outlen);

	//公钥加密
    memset(inbuf, 0, sizeof(inbuf));
	inlen = outlen;
	memcpy(inbuf, outbuf, inlen);
    memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPub(hKey, FLAG_ENCODE, &pub_key, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPub(FLAG_ENCODE)", retcode); 
	if(retcode != 0) return;

	StrPrintf("Public key encryption result: \n");
	ShowBinHex(outbuf, outlen);

	//私钥解密
	memset(inbuf, 0, sizeof(inbuf));
	inlen = outlen;
	memcpy(inbuf, outbuf, inlen);
    memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPri(hKey, fileid, FLAG_DECODE, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPri(FLAG_DECODE)", retcode);
	if(retcode != 0) return;
    //

	StrPrintf("Private key to decrypt the result: \n");
	ShowBinHex(outbuf, outlen);
}

void  RSATest()
{
	PRIKEY_FILE_ATTR pfa;
	//===============================


	//========1024位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_RSA;
	pfa.m_Size = 1024;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	RSATestIt(0x1001, &pfa);

    //========2048位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_RSA;
	pfa.m_Size = 2048;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	RSATestIt(0x1002, &pfa);

	
}

void  ECCTestIt(WORD fileid, PRIKEY_FILE_ATTR* pPFA)
{
	int   len_hash;
	DWORD retcode;
	ECCSM2_PUBLIC_KEY  pub_key;
    ECCSM2_PRIVATE_KEY pri_key;
	BYTE  hash[32];
	BYTE  sign[64];

	//
	retcode = Dongle_CreateFile(hKey, FILE_PRIKEY_ECCSM2, fileid, pPFA);
	showRet("Dongle_CreateFile()", retcode); 
	if(retcode != 0 && retcode != DONGLE_FILE_EXIST) return;
	//
    retcode = Dongle_EccGenPubPriKey(hKey, fileid, &pub_key, &pri_key);
	showRet("Dongle_EccGenPubPriKey()", retcode);
	if(retcode != 0) return;
	//

	StrPrintf("Public key: \r\n");
	ShowBinHex((unsigned char*)pub_key.XCoordinate, 64);
	

	StrPrintf("Private key: \r\n");
	ShowBinHex((unsigned char*)pri_key.PrivateKey, 32);
	//
    memset(hash, 0, sizeof(hash));
	memset(sign, 0, sizeof(sign));
	//
	len_hash = 16;
	memcpy(hash, "\x47\xED\x73\x3B\x8D\x10\xBE\x22\x5E\xCE\xBA\x34\x4D\x53\x35\x86", 16);
	StrPrintf("Hash: \r\n");
	ShowBinHex(hash, 32);
	//
	retcode = Dongle_EccSign(hKey, fileid, hash, len_hash, sign);
	showRet("Dongle_EccSign()", retcode);
	if(retcode != 0) return;
	
	StrPrintf("Sign(R:S): \r\n");
	ShowBinHex(sign, 64);
	//
	retcode = Dongle_EccVerify(hKey, &pub_key, hash, len_hash, sign);
	showRet("Dongle_EccVerify()", retcode);
}

void  ECCTest()
{
	PRIKEY_FILE_ATTR pfa;


    //========256位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_ECCSM2;
	pfa.m_Size = 256;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	ECCTestIt(0x2001, &pfa);
	
    //========192位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_ECCSM2;
	pfa.m_Size = 192;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	ECCTestIt(0x2002, &pfa);
}

void TDESTest()
{
    int   i;
	DWORD retcode;
	BYTE  tmpbuf[128];

	//	
    for(i=0; i<sizeof(tmpbuf); i++)
	{
		tmpbuf[i] = i;
	}
	//
	StrPrintf("Plaintext : \r\n");
	ShowBinHex(tmpbuf, sizeof(tmpbuf));
	//
    retcode = Dongle_TDES(hKey, 0x0004, FLAG_ENCODE, tmpbuf, tmpbuf, sizeof(tmpbuf));
	//
    showRet("Dongle_TDES ENCODE" , retcode); 
	//
	StrPrintf("Encrypted: \r\n");
	ShowBinHex(tmpbuf, sizeof(tmpbuf));
	//============	
    retcode = Dongle_TDES(hKey, 0x0004, FLAG_DECODE, tmpbuf, tmpbuf, sizeof(tmpbuf));
    //
    showRet("Dongle_TDES DECODE" , retcode); 
	//
	StrPrintf("Decrypted: \r\n");
	ShowBinHex(tmpbuf, sizeof(tmpbuf));	
}

//==================================
#define		MAXSIZE		8
#define     PARAMNUM    8
//
#define     TYPE_DOUBLE     0
#define     TYPE_INTEGER    1
#define     TYPE_FLOAT      2
#define     TYPE_LONG       3
#define		TYPE_BYTE		4

//
typedef struct
{
	union
	{
	   BYTE	   buffer[8];	//数据
	   double  m_double;	   
	   float   m_float;
	   int     m_int;
	   BYTE    m_long[8];
	   BYTE    m_byte;
	};
    //
	DWORD	type;			//数据类型
}Param;
//
typedef struct
{
	Param data[MAXSIZE];
	int	top;
}COS_Stack;
//
typedef struct
{
    Param      InputParam[PARAMNUM];
	Param	   Constant[PARAMNUM];
    COS_Stack  InStatck;
}InParam;       //输入参数
//
typedef struct
{
    Param      OutputParam[PARAMNUM];
    COS_Stack  OutStatck;
}OutParam;      //输出参数

/*
void ReverseDouble(double num, BYTE* pbuf)
{
	DWORD*  pd;
	DWORD*  presult;
	//
	pd      = (DWORD*) &num;
	presult = (DWORD*) pbuf;
	//
	presult[0] = pd[1];
	presult[1] = pd[0];
}
*/

double ReverseDouble(double num)
{
	double  result;
    DWORD*  pd;
	DWORD*  presult;
	//
	pd      = (DWORD*) &num;
	presult = (DWORD*) &result;
	//
	presult[0] = pd[1];
	presult[1] = pd[0];
	//
	return result;
}

void HASHTest()
{
	int   i;
	DWORD dwRet;
	BYTE  tmpbuf[128];
	BYTE  hash[20];
	//
    for(i=0; i<sizeof(tmpbuf); i++)
	{
       tmpbuf[i] = i;
	}
	//
	memset(hash, 0, sizeof(hash));
	//
	dwRet = Dongle_HASH(hKey, FLAG_HASH_MD5,  tmpbuf, sizeof(tmpbuf), hash);
	showRet("Dongle_HASH(FLAG_HASH_MD5)" , dwRet);
	//
	StrPrintf("HASH_MD5: \r\n");
	ShowBinHex(hash, 16);
	//=================
	memset(hash, 0, sizeof(hash));
	//
    dwRet = Dongle_HASH(hKey, FLAG_HASH_SHA1, tmpbuf, sizeof(tmpbuf), hash);
	showRet("Dongle_HASH(FLAG_HASH_SHA1)" , dwRet);
	//
	StrPrintf("HASH_SHA1: \r\n");
	ShowBinHex(hash, 20);
}

void encrypttest()
{
	char   bInput;

	
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		while(1)
		{
			ShowEncryptCmdMenu();
			//
			bInput = WaitForUserInput();
			//
			if (Count <= 0 && !(bInput =='X' || bInput =='x') )
			{
				printf("no key \n");
				return;
			}
			//
			switch( bInput )
			{
				case 'R':
				case 'r':
				{
					RSATest();
					break;
				} 
				case 'E':
				case 'e':
				{
					ECCTest();
					break;
				} 
				case 'T':
				case 't':
				{
					TDESTest();
					break;
				} 
				case 'H':
				case 'h':
				{
					HASHTest();
					break;
				} 
				case 'X':
				case 'x':
				{
					return;
				}
				default:
				{
					printf("\r\n unknown command!\r\n");
					break;
				}
			
			}
		}
	}
}

void DongleListFile(DONGLE_HANDLE handle, int file_type)
{
	DWORD  retcode;
	int    nLen;
	int    ntypeLen;
	char   strtype[26];
	BYTE   pList[1024];
	int    i;
	BYTE   *plistnode=NULL;
	DATA_FILE_LIST * pDataFileList;
	PRIKEY_FILE_LIST * pPriKeyFileList;
	KEY_FILE_LIST * pXesKeyFileList;
	EXE_FILE_LIST * pXExeList;


	switch(file_type)
	{
	   case  FILE_DATA:       
	   {
		   ntypeLen = sizeof(DATA_FILE_LIST);
		   strcpy(strtype,"FILE_DATA");
		   break;
	   }
       case  FILE_PRIKEY_RSA: 
	   case  FILE_PRIKEY_ECCSM2: 
	   {
		   ntypeLen = sizeof(PRIKEY_FILE_LIST);
		   strcpy(strtype,"FILE_PRIKEY (RSA or ECC)");
		   break;			   
	   }
	   case  FILE_KEY:     
	   {
		   ntypeLen = sizeof(KEY_FILE_LIST);
		   strcpy(strtype,"FILE_KEY");
		   break;			  
	   }
	   case  FILE_EXE:     
	   {
		   ntypeLen = sizeof(EXE_FILE_LIST);
		   strcpy(strtype,"FILE_EXE");
		   break;			  
	   }
	   default: 
	   {
		   return;
	   }
    }
    //
	nLen =sizeof(pList);
	//
	memset(pList, 0, sizeof(pList));
    //
	retcode = Dongle_ListFile(handle , file_type , pList,  &nLen);
	if( DONGLE_SUCCESS != retcode || nLen == 0) 
	{
		printf("\r\nDongle_ListFile(%s) retcode=%08X\r\n", strtype , retcode);
		//
		return;
	}
	//
	printf("\r\n=========DONGLE_ListFile(%s) ===============\r\n", strtype);
    //
	for (i=0 ; i< (nLen/ntypeLen) ; i++)
	{
			plistnode= (BYTE*)pList+ (i*ntypeLen);
			//
			if (ntypeLen == sizeof(DATA_FILE_LIST))
			{
				pDataFileList = (DATA_FILE_LIST *)plistnode;
				printf("m_FILEID: %04X\r\nm_atrr.m_Size: %d\r\nm_atrr.m_Lic.m_Read_Priv: %d\r\nm_atrr.m_Lic.m_WritePriv: %d\r\n",
					pDataFileList->m_FILEID,
					pDataFileList->m_attr.m_Size,
					pDataFileList->m_attr.m_Lic.m_Read_Priv,
					pDataFileList->m_attr.m_Lic.m_Write_Priv);
			}
			else if (ntypeLen == sizeof(PRIKEY_FILE_LIST))
			{
				pPriKeyFileList = (PRIKEY_FILE_LIST *)plistnode;
				printf("m_FILEID: %04X\r\nm_attr.m_Type: %d\r\nm_attr.m_Size: %d\r\nm_attr.m_Lic.m_Count: %d\r\nm_attr.m_Lic.m_Priv: %d\r\nm_attr.m_Lic.m_IsDecOnRAM: %d\r\nm_attr.m_Lic.m_IsReset: %d\r\n",
					pPriKeyFileList->m_FILEID,
					pPriKeyFileList->m_attr.m_Type,
					pPriKeyFileList->m_attr.m_Size,
					pPriKeyFileList->m_attr.m_Lic.m_Count,
					pPriKeyFileList->m_attr.m_Lic.m_Priv,
					pPriKeyFileList->m_attr.m_Lic.m_IsDecOnRAM,
					pPriKeyFileList->m_attr.m_Lic.m_IsReset);
			}
			else if (ntypeLen == sizeof(KEY_FILE_LIST))
			{
				pXesKeyFileList = (KEY_FILE_LIST *)plistnode;
				printf("m_FILEID :%04X\r\nm_attr.m_Size: %d\r\nm_attr.m_Lic.m_Priv_Enc: %d\r\n",
					pXesKeyFileList->m_FILEID,
					pXesKeyFileList->m_attr.m_Size,
					pXesKeyFileList->m_attr.m_Lic.m_Priv_Enc);
			}
			else if (ntypeLen == sizeof(EXE_FILE_LIST))
			{
				pXExeList = (EXE_FILE_LIST *)plistnode;
				//
				printf("m_DIRID :%04X\r\nm_Size: %d \r\n",
					pXExeList->m_FILEID,
					pXExeList->m_attr.m_Len);
			}
	}	
}


void Creatfiles()
{
	DWORD  retcode;
	DATA_FILE_ATTR DataFileAttr={0x00};
	PRIKEY_FILE_ATTR PrikeyFileAttr={0x00};
	KEY_FILE_ATTR XesKeyFileAttr={0x00};
	EXE_FILE_ATTR    ExeFileAttr={0x00};

	//
	DataFileAttr.m_Size = 300;
    retcode = Dongle_CreateFile(hKey, FILE_DATA, 0x0001 , &DataFileAttr);
	
	showRet("Dongle_CreateFile(FILE_DATA)" , retcode); 
	//
	PrikeyFileAttr.m_Size = 1024;
	PrikeyFileAttr.m_Type = FILE_PRIKEY_RSA;
	PrikeyFileAttr.m_Lic.m_Count      = -1; //不限制次数
    PrikeyFileAttr.m_Lic.m_IsDecOnRAM =  0; //不在内存中递减
	PrikeyFileAttr.m_Lic.m_IsReset    =  0; //用户态调用后不复位
	PrikeyFileAttr.m_Lic.m_Priv       =  0; //最小调用权限为匿名
	retcode = Dongle_CreateFile(hKey, FILE_PRIKEY_RSA, 0x0002 , &PrikeyFileAttr);
	
	showRet("Dongle_CreateFile(FILE_PRIKEY_RSA)" , retcode); 
	//
	PrikeyFileAttr.m_Size = 192;
	PrikeyFileAttr.m_Type = FILE_PRIKEY_ECCSM2;
    PrikeyFileAttr.m_Lic.m_Count      = -1; //不限制次数
    PrikeyFileAttr.m_Lic.m_IsDecOnRAM =  0; //不在内存中递减
	PrikeyFileAttr.m_Lic.m_IsReset    =  0; //用户态调用后不复位
	PrikeyFileAttr.m_Lic.m_Priv       =  0; //最小调用权限为匿名
	retcode = Dongle_CreateFile(hKey, FILE_PRIKEY_ECCSM2, 0x0003 , &PrikeyFileAttr);
	
	showRet("Dongle_CreateFile(FILE_PRIKEY_ECCSM2)" , retcode); 	
	//
	XesKeyFileAttr.m_Size = 16;
    XesKeyFileAttr.m_Lic.m_Priv_Enc = 0; //匿名调用权限
	retcode = Dongle_CreateFile(hKey, FILE_KEY, 0x0004 , &XesKeyFileAttr);
	
	showRet("Dongle_CreateFile(FILE_KEY)" , retcode); 
	//
	ExeFileAttr.m_Len  = 1024;
	
	printf("Temporarily unable to create an executable file\n");
	showRet("Dongle_CreateFile(FILE_EXE)" , retcode); 

}

void Deletefiles()
{
	DWORD  retcode;


	retcode = Dongle_DeleteFile(hKey,FILE_DATA,0x0001);

	showRet("Dongle_DeleteFile(FILE_DATA)" , retcode); 
	
	retcode = Dongle_DeleteFile(hKey,FILE_PRIKEY_RSA,0x0002);
	
	showRet("Dongle_DeleteFile(FILE_PRIKEY_RSA)" , retcode); 
	
	retcode = Dongle_DeleteFile(hKey,FILE_PRIKEY_ECCSM2,0x0003);
	
	showRet("Dongle_DeleteFile(FILE_PRIKEY_ECCSM2)" , retcode);
	
	retcode = Dongle_DeleteFile(hKey,FILE_KEY,0x0004);
	
	showRet("Dongle_DeleteFile(FILE_KEY)" , retcode);
	
}

void WriteFiles()
{
	DWORD  retcode;
	HANDLE hFile;
	FILE * File;
	int   FileSize;
	DWORD  bytesread;
	BYTE   FileBuff[1024];
	

	File = fopen("test.dat", "r");
	if(File == NULL)
	{
		perror("open file test.dat error");
		return;
	}

	fseek(File, 0L, SEEK_END);  
    FileSize = ftell(File);  

	if(FileSize > 300)
	{
		printf("\r\nFile size too large!\r\n");
		fclose(File);
		return;
	}

	fread(FileBuff, 1, FileSize, File);

	fclose(File);
    //
	retcode = Dongle_WriteFile(hKey, FILE_DATA,  0x0001 , 0x0000 , FileBuff, FileSize);
	
	showRet("Dongle_WriteFile(FILE_DATA)" , retcode);
}

void ReadFiles()
{
	DWORD  retcode;
	int    FileSize=10;
	BYTE   FileBuff[1024];

	
	retcode = Dongle_ReadFile(hKey, FILE_DATA,  0x0001,  FileBuff, FileSize);
	
	showRet("Dongle_ReadFile(FILE_DATA)" , retcode);
}


void filetest()
{
	char   bInput;


	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		while(1)
		{
			ShowFileCmdMenu();
		//
			bInput = WaitForUserInput();
		//
			if (Count <= 0 && !(bInput =='X' || bInput =='x') )
			{
				printf("no key \n");
				return;
			}
			//
			switch( bInput )
			{
				case 'L':
				case 'l':
				{
					printf("now ListFile\r\n");
					DongleListFile(hKey , FILE_DATA);
					DongleListFile(hKey , FILE_PRIKEY_RSA);
					DongleListFile(hKey , FILE_PRIKEY_ECCSM2);
					DongleListFile(hKey , FILE_KEY);
					DongleListFile(hKey , FILE_EXE);
					break;
				} 
				case 'C':
				case 'c':
				{
					Creatfiles();
					break;
				} 
				case 'D':
				case 'd':
				{
					Deletefiles();
					break;
				}
				case 'W':
				case 'w':
				{
					WriteFiles();
					break;
				}
				case 'R':
				case 'r':
				{
					ReadFiles();
					break;
				}
				case 'X':
				case 'x':
				{
					return;
				}
				default:
				{
					printf("\r\n unknown command!\r\n");
					break;
				}
			
			}
		}
	}

}

void memorytest()
{
	DWORD retcode;
	int   offset;
	int   len;
	int i=0;
	char  buf[16];
	BYTE  bin_buf[128];	

	//
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		memset(buf, 0, sizeof(buf));
		printf("Please Input Offset <0-7167>: ");
		fflush(stdin);
		gets(buf);
		//	
		offset = atoi(buf);
		//
		memset(buf, 0, sizeof(buf));
		printf("Please Input Len <1-128>: ");
		fflush(stdin);
		gets(buf);
		//	
		len = atoi(buf);
		//
		printf("Gen data for write: \r\n");
		for( i=0; i<len; i++)
		{
			bin_buf[i] = i;
		}
		ShowBinHex(bin_buf, len);
		//	
		retcode = Dongle_WriteData(hKey, offset, bin_buf, len);	
		showRet("Dongle_WriteData()" , retcode);
		
		memset(bin_buf, 0, sizeof(bin_buf));
		retcode = Dongle_ReadData(hKey, offset, bin_buf, len);
		showRet("Dongle_ReadData()" , retcode);
		ShowBinHex(bin_buf, len);
		
	}
}

//公钥
static BYTE s_byte_n[128] = {
		    //麻宝华工具生成
	    0xC5,0x6D,0x9E,0x1C,0x52,0x08,0x18,0x11,
		0x3F,0xE6,0x75,0x3D,0x80,0xA5,0xA9,0xC8,
		0x65,0xD8,0x0F,0xBE,0x90,0xD1,0x3E,0xA0,
		0x29,0x91,0xF2,0x39,0xEC,0x4E,0x6C,0x1F,
		0xC6,0x1D,0x3A,0xB1,0x43,0xDF,0x63,0xEA,
		0x22,0x65,0x23,0x8A,0x8E,0x9D,0x2A,0x54,
		0x54,0xFE,0xC8,0x04,0x31,0xF0,0xBC,0xE7,
		0xD9,0x62,0xD7,0x83,0x56,0x09,0xC9,0x36,
		0xB0,0xB5,0x45,0xB1,0xF7,0xD6,0xC5,0xFF,
		0x41,0xED,0x8C,0x94,0xF3,0xD2,0x05,0x1F,
		0x44,0x4F,0x9C,0xB7,0x1C,0xAE,0x05,0xF5,
		0x1E,0x76,0xF7,0x21,0x9B,0x3C,0x06,0x53,
		0xC4,0x6A,0x77,0xE7,0x99,0xE2,0x58,0x21,
		0x70,0x39,0x29,0xEB,0x01,0x9C,0xB9,0x07,
		0x31,0xBE,0xEA,0xB0,0xD0,0x6C,0x5C,0x71,
		0x6C,0xB9,0xA2,0xB1,0xF3,0xE0,0x91,0xED 

};

//私钥
static BYTE s_byte_d[128] = {
        //麻宝华工具生成
	    0x27,0x10,0x0C,0x53,0xA0,0x2B,0x77,0xCF, 
		0x99,0xEC,0x18,0x50,0x65,0xEE,0xE1,0x4C, 
		0x04,0x52,0x9E,0xB2,0xDE,0xE6,0x77,0xD4, 
		0xAA,0xC4,0xF4,0xBF,0x5F,0x31,0x19,0x15, 
		0xA4,0x56,0x4E,0x31,0x9A,0xB3,0x4D,0x8A, 
		0x9A,0xE9,0x96,0x01,0xA9,0x3C,0x11,0x8F, 
		0x04,0x0E,0x31,0x37,0x1B,0x46,0x7D,0xAA, 
		0x06,0x0A,0x17,0x88,0x25,0xF2,0xE3,0xBB, 
		0xB4,0x06,0x56,0xFC,0x48,0x4B,0x5F,0xE4, 
		0x50,0x2E,0x97,0xBB,0x86,0x05,0x32,0x36, 
		0xFF,0x30,0xAA,0x1A,0x68,0x87,0x6A,0xC0, 
		0xF0,0xC3,0xFA,0x2B,0x9E,0x6A,0xBF,0x27, 
		0xB9,0x4E,0xE7,0xA5,0xCF,0xB7,0x77,0xC1, 
		0x60,0xE7,0x80,0x06,0x90,0x72,0x41,0x49, 
		0x03,0x24,0x27,0x7B,0xD1,0x71,0xB6,0x7F, 
        0x1E,0x2F,0xCF,0xAB,0x71,0x4B,0xFD,0x65
};

void UpdateFromPubKey(DONGLE_HANDLE hSon)
{


}

void UpdateFromMotherKey(DONGLE_HANDLE hMother, DONGLE_HANDLE hSon)
{
    DWORD  retcode;
	BYTE OutData[1024]={0};
	int  OutLen = 1024;
	BYTE buf[128];
	int i;
	EXE_FILE_ATTR  xfa;
    //
	for (i=0 ;i < 128 ; i++)
	{
		buf[i]= i;
	}

	//
	retcode = Dongle_Update(hSon , OutData ,OutLen);
	showRet("Dongle_Update()" , retcode);
	//写入文件
    retcode = Dongle_MakeUpdatePacketFromMother(hMother, 
		NULL, 
		UPDATE_FUNC_WriteFile, 
		FILE_EXE, 
		0x3A89, 
		0, 
		buf, 
		128, 
		OutData,
		&OutLen);
    
    showRet("Dongle_MakeUpdatePacketFromMother()" , retcode);
	if ( DONGLE_SUCCESS != retcode)  return;
	//
	retcode = Dongle_Update(hSon, OutData ,OutLen);
	showRet("Dongle_Update()" , retcode);
}

void SetUpdateKey()
{
	DWORD  retcode;
    RSA_PRIVATE_KEY  UPriKey;
	//
	ReadBinFile("PriKey.bin", (BYTE*)&UPriKey, sizeof(RSA_PRIVATE_KEY));
	//
	retcode = Dongle_SetUpdatePriKey(hKey, &UPriKey);
	showRet("Dongle_SetUpdatePriKey()" , retcode);
}


void updatetest()
{
	int       i, index, Count;
	int       num_mother, mother_index, num_son, son_index;
	DWORD     retcode;
	DONGLE_HANDLE hMother, hSon;	
	BYTE      buff[1024];
	//====================
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		memset(buff, 0, sizeof(buff));
		printf("for update test press 1, for set update key press 0: ");
		fflush(stdin);
		gets(buff);
		//	
		i = atoi(buff);
		//
		if(i == 0)
		{
			SetUpdateKey();
			return;
		}
		//
		Dongle_Enum(NULL, &Count);
		if( Count == 0)
		{
			printf("ROCKEY-ARM not found\n");
			return;
		}
		//
		pKEYList = malloc(sizeof(DONGLE_INFO) * Count);
		Dongle_Enum(pKEYList, &Count);        
		//
	    num_mother = 0;
		num_son    = 0;
		//
		for( i=0; i<Count; i++)
		{
			StrPrintf("======KEY: %d======\r\n", i);
			StrPrintf("Version:%04X\r\n", pKEYList[i].m_Ver);
			StrPrintf("Agent:  %08X\r\n", pKEYList[i].m_Agent);
			StrPrintf("PID:    %08X\r\n", pKEYList[i].m_PID);
			StrPrintf("Mother: %08X\r\n", pKEYList[i].m_IsMother);
			StrPrintf("HID: ");
			ShowBinHex(pKEYList[i].m_HID, 8);
			//
			if(pKEYList[i].m_IsMother)
			{
				num_mother ++;
				//
				mother_index = i;
			}
			else
			{
			    num_son ++;
				//
		        son_index = i;
			}
		}
		//
		free(pKEYList);		
		//
		if(num_son > 1)
		{
			memset(buff, 0, sizeof(buff));
			printf("Please Input son key's index need to Init <0-%d>: ", Count-1);
			fflush(stdin);
			gets(buff);
			//	
			index = atoi(buff);
		}
		else
		{
			index = son_index;
		}
		//
		retcode = Dongle_Open(&hSon, index);
		showRet("Dongle_Open(hSon)" , retcode);
		if(retcode != DONGLE_SUCCESS) return;
		//
		if(num_mother != 1)
		{
			StrPrintf("UpdateFromPubKey!\r\n");
			//
			UpdateFromPubKey(hSon);
			//
			Dongle_Close(hSon);
		}
		else
		{
			retcode = Dongle_Open(&hMother, mother_index);
			showRet("Dongle_Open(Mother)" , retcode);
			if(retcode != DONGLE_SUCCESS) return;
			//
			StrPrintf("UpdateFromMotherKey!\r\n");
			//
		    UpdateFromMotherKey(hMother, hSon);
			//关闭锁
			Dongle_Close(hMother);
		    Dongle_Close(hSon);
		}

	}
}	

void GenMother()
{
	int       i, index, Count, RemainCount;
	DWORD     retcode;
	DONGLE_HANDLE hMother;	
	BYTE      buff[32];
	char      Pswdbuf[32];
	MOTHER_DATA  md;

	//
	Dongle_Enum(NULL, &Count);
	if( Count == 0)
	{
		printf("ROCKEY-ARM not found\n");
		return;
	}
	//
	pKEYList = malloc( sizeof(DONGLE_INFO) * Count);
	Dongle_Enum(pKEYList, &Count);        
	//
	for( i=0; i<Count; i++)	
	{
		StrPrintf("======KEY: %d======\r\n", i);
		StrPrintf("Version:%04X\r\n", pKEYList[i].m_Ver);
		StrPrintf("Agent:  %08X\r\n", pKEYList[i].m_Agent);
		StrPrintf("PID:    %08X\r\n", pKEYList[i].m_PID);
		StrPrintf("Mother: %08X\r\n", pKEYList[i].m_IsMother);
		StrPrintf("HID: ");
		ShowBinHex(pKEYList[i].m_HID, 8);
	}
	//
	free(pKEYList);
	//
	if(Count > 1)
	{
		memset(buff, 0, sizeof(buff));
		printf("Please Input key's index need to Gen Mother KEY <0-%d>: ", Count-1);
		fflush(stdin);
		gets(buff);
		//	
		index = atoi(buff);
	}
	else
	{
        index = 0;
	}
	//
	retcode = Dongle_Open(&hMother, index);
	showRet("Dongle_Open()" , retcode);
	//校验管理员密码
	memset(Pswdbuf, 0, sizeof(Pswdbuf));
    printf("Please Input Admin PIN <16>: ");
	fflush(stdin);
	gets(Pswdbuf);
	//
	retcode = Dongle_VerifyPIN(hMother,FLAG_ADMINPIN ,Pswdbuf, &RemainCount);
	printf("Dongle_VerifyPIN(FLAG_ADMINPIN), retcode=%08X, RemainCount=%d\r\n", retcode, RemainCount);
	//产生出母锁
	memset(&md, 0, sizeof(md));
    md.m_Count = -1; //不限次
	md.m_Son.m_AdminTryCount = 6;
	md.m_Son.m_UserTryCount  = 6;
	strcpy(md.m_Son.m_UserPIN, "87654321");
	strcpy(md.m_Son.m_SeedForPID, "I have a dream");
	md.m_Son.m_SeedLen = 14;
	//
	ReadBinFile("PriKey.bin", (BYTE*)&md.m_Son.m_UpdatePriKey, sizeof(RSA_PRIVATE_KEY));
	//
	md.m_Son.m_UserID_Start = 0x81000001;
	//
	retcode = Dongle_GenMotherKey(hMother, &md);
	showRet("Dongle_GenMotherKey()" , retcode);
	//
	Dongle_ResetState(hMother);
	showRet("Dongle_ResetState()" , retcode);
	//关闭锁
	Dongle_Close(hMother);
	showRet("Dongle_Close()" , retcode);
}

void InitSon()
{
	int       i, index, Count, len;
	int       num_mother, mother_index, num_son, son_index;
	DWORD     retcode;
	DONGLE_HANDLE hMother, hSon;	
	BYTE      buff[1024];
	BYTE      Request[16];

	//
	Dongle_Enum(NULL, &Count);
	if( Count == 0)
	{
		printf("ROCKEY-ARM not found\n");
		return;
	}
	//
	pKEYList = malloc( sizeof(DONGLE_INFO) * Count);
	Dongle_Enum(pKEYList, &Count);        
	//
    num_mother = 0;
	num_son    = 0;
	//
	for( i=0; i<Count; i++)
	{
		StrPrintf("======KEY: %d======\r\n", i);
		StrPrintf("Version:%04X\r\n", pKEYList[i].m_Ver);
		StrPrintf("Agent:  %08X\r\n", pKEYList[i].m_Agent);
		StrPrintf("PID:    %08X\r\n", pKEYList[i].m_PID);
		StrPrintf("Mother: %08X\r\n", pKEYList[i].m_IsMother);
		StrPrintf("HID: ");
		ShowBinHex(pKEYList[i].m_HID, 8);
		//
		if(pKEYList[i].m_IsMother)
		{
			num_mother ++;
			//
			mother_index = i;
		}
		//
        if(pKEYList[i].m_PID == CONST_PID)
		{
			num_son ++;
			//
			son_index = i;
		}
	}
	//
	free(pKEYList);
	//
	if(num_mother != 1)
	{
        if(num_mother == 0)
		{
            StrPrintf("Mother Key not found!\r\n");
		}
		else
		{
            StrPrintf("Too many Mother Key, only one is allowed!\r\n"); 
		}
		//
		return;
	}
	//
	retcode = Dongle_Open(&hMother, mother_index);
	showRet("Dongle_Open(Mother)" , retcode);
	if(retcode != DONGLE_SUCCESS) return;
	//
	if(num_son > 1)
	{
		memset(buff, 0, sizeof(buff));
		printf("Please Input son key's index need to Init <0-%d>: ", Count-1);
		fflush(stdin);
		gets(buff);
		//	
		index = atoi(buff);
	}
	else
	{
        index = son_index;
	}
	//
	retcode = Dongle_Open(&hSon, index);
	showRet("Dongle_Open(Son)" , retcode);
	//
	memset(Request, 0, sizeof(Request));
	memset(buff, 0, sizeof(buff));
	//
	retcode = Dongle_RequestInit(hSon, Request);
	showRet("Dongle_RequestInit(Son)" , retcode);
	if(retcode != 0) return;
	//
	len = sizeof(buff);
	retcode = Dongle_GetInitDataFromMother(hMother, Request, buff, &len);
	showRet("Dongle_GetInitDataFromMother()" , retcode);
	if(retcode != 0) return;
	//
	retcode = Dongle_InitSon(hSon, buff, len);
	showRet("Dongle_InitSon()" , retcode);
	if(retcode != 0) return;
	//关闭锁
	Dongle_Close(hMother);
	Dongle_Close(hSon);
}

void MotherSonTest()
{
	char   bInput;

	//
	while(1)
	{
		ShowMotherSonCmdMenu();
		//
		bInput = WaitForUserInput();
		//
		if (Count <= 0 && !(bInput =='X' || bInput =='x') )
		{			
			return;
		}
		//
		switch( bInput )
		{
		case 'G':
		case 'g':
			{
				GenMother();		
				break;
			} 
		case 'I':
		case 'i':
			{		
				InitSon();
				break;
			} 
		case 'X':
		case 'x':
			{
				return;
			}
		default:
			{
				printf("\r\n unknown command!\r\n");
				break;
			}			
		}
	}
}

void authoritytest()
{
	int    i;
	DWORD  retcode;
	char   User_PIN2[16]="87654321";
	int    RemainCount;   
	BYTE   Seedbuf[256];
	char   PIDbuf[16];
    char   AdminPswdbuf[32];

	//	
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		memset(Seedbuf, 0, sizeof(Seedbuf));
		printf("for test press 1, for rfs press 0: ");
		fflush(stdin);
		gets(Seedbuf);
		//	
		i = atoi(Seedbuf);
		//

		if(i == 1)
		{
			retcode = Dongle_VerifyPIN(hKey,FLAG_ADMINPIN ,CONST_ADMINPIN, &RemainCount );
			if(DONGLE_SUCCESS != retcode) 
			{
				printf("\r\nDongle_VerifyPIN(FLAG_ADMINPIN) retcode=%08X, RemainCount=%d\r\n", retcode, RemainCount);
				return;
			}
			//
			for(i=0; i<250; i++)
			{
				Seedbuf[i] = i;
			}
			//
			memset(PIDbuf, 0, sizeof(PIDbuf));
			memset(AdminPswdbuf, 0, sizeof(AdminPswdbuf));
			retcode = Dongle_GenUniqueKey(hKey, 64, Seedbuf, PIDbuf, AdminPswdbuf);
			//
			showRet("Dongle_GenUniqueKey()" , retcode);
			printf("PID: %s\r\n",PIDbuf);
			printf("AdminPswd: %s\r\n",AdminPswdbuf);
			//
			retcode = Dongle_VerifyPIN(hKey,FLAG_ADMINPIN ,AdminPswdbuf, &RemainCount);
			if(DONGLE_SUCCESS != retcode) 
			{
				printf("\r\nDongle_VerifyPIN(FLAG_ADMINPIN) retcode=%08X, RemainCount=%d\r\n", retcode, RemainCount);
				return;
			}
			printf("test end!\r\n");
		}
		else if(i == 0)
		{	
		   //
		   retcode = Dongle_RFS(hKey);
		   showRet("Dongle_RFS()" , retcode);
		   //
		   uq_flag[index_num] = FALSE;
		   printf("please reenum, open the key!\r\n");
		}
		else
		{
	       printf("please input 0 or 1!\r\n");
		}
	}
}


void VerifyPin()
{
	int    i;
	DWORD  retcode;
    char   Pswdbuf[32];
	int    RemainCount;   
	//
	BYTE   Seedbuf[256];
	char   PIDbuf[16];
    char   AdminPswdbuf[32];


	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		retcode = Dongle_ResetState(hKey);
		showRet("Dongle_ResetState()" , retcode);
	    //
		printf("VerifyPin password: input  1(admin), 0 (user) \r\n");
		fflush(stdin);
		gets(Pswdbuf);
		//	
		i = atoi(Pswdbuf);

		if(i == 0)
		{
			printf("Please Input User PIN <1-16>: ");
			fflush(stdin);
			gets(Pswdbuf);
			//
		    retcode = Dongle_VerifyPIN(hKey,FLAG_USERPIN, Pswdbuf, &RemainCount);
			printf("Dongle_VerifyPIN(FLAG_USERPIN), retcode=%08X, RemainCount=%d\r\n", retcode, RemainCount);	       
		}
		else if (i == 1)
		{
			printf("Please Input Admin PIN <16>: ");
			fflush(stdin);
			gets(Pswdbuf);
			//
			retcode = Dongle_VerifyPIN(hKey,FLAG_ADMINPIN ,Pswdbuf, &RemainCount);
			printf("Dongle_VerifyPIN(FLAG_ADMINPIN), retcode=%08X, RemainCount=%d\r\n", retcode, RemainCount);				

		}
		else 
		{	
	     printf("please input 0 or 1!\r\n");
		}
	}
}

void ChangePIN()
{

	int    i;
	DWORD  retcode;
	char   buff[16];
    char   OldPswdbuf[32];
	char   NewPswdbuf[32];
	int    RemainCount; 


	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		printf("Change password: input  1(admin), 0 (user) \r\n");
		fflush(stdin);
		gets(buff);
		//	
		i = atoi(buff);
		
		if(i == 0)
		{
			printf("Please Input Old User PIN <1-16>: ");
			fflush(stdin);
			gets(OldPswdbuf);
			
			printf("Please Input New User PIN <1-16>: ");
			fflush(stdin);
			gets(NewPswdbuf);
			
			printf("Please Input Try User Count <0-255>: ");
		
			fflush(stdin);
			gets(buff);
			//	
			RemainCount = atoi(buff);

			retcode = Dongle_ChangePIN(hKey,FLAG_USERPIN, OldPswdbuf, NewPswdbuf, RemainCount);
			printf("Dongle_ChangePIN(FLAG_USERPIN), retcode=%08X\r\n", retcode);	       
		}
		else if (i == 1)
		{
			printf("Please Input Old Admin PIN <1-16>: ");
			fflush(stdin);
			gets(OldPswdbuf);
		
			printf("Please Input New Admin PIN <1-16>: ");
			fflush(stdin);
			gets(NewPswdbuf);
		
			printf("Please Input Try Admin Count <0-255>: ");
		
			fflush(stdin);
			gets(buff);
		//	
			RemainCount = atoi(buff);

			retcode = Dongle_ChangePIN(hKey,FLAG_ADMINPIN, OldPswdbuf, NewPswdbuf, RemainCount);
			printf("Dongle_ChangePIN(FLAG_ADMINPIN), retcode=%08X\r\n", retcode);	  
				
		}
		else 
		{	
			printf("please input 0 or 1!\r\n");
		}

		printf("Reset User password input  1(yes), 0 (no) \r\n");
		fflush(stdin);
		gets(buff);
		//	
		i = atoi(buff);
		
		if(i == 1)
		{
			printf("Please Input Admin  PIN <1-16>: ");
			fflush(stdin);
			gets(OldPswdbuf);
			retcode = Dongle_ResetUserPIN(hKey,OldPswdbuf);
			printf("Dongle_ResetUserPIN(), retcode=%08X\r\n", retcode);	       
		}

	}
}

void DownExe()
{
	size_t   bytesread;
	int      len_File;
	WORD	 len_CPO;
	WORD     dirid, fileid;
	DWORD    retcode;
	BYTE     tmpbuf[1024];
	int      RemainCount;
	char     AdminPswdbuf[32];
	double	 dwParam, result;
	int		 i, len_CPI;
	InParam	 IP;
    OutParam OP;
	EXE_FILE_INFO exeFileInfo;

	FILE * File;
	
	
	fileid   = 0x1010;
	//
	len_CPO  = sizeof(OP);
	//
	memset(tmpbuf, 0, sizeof(tmpbuf));
	memset(&IP, 0, sizeof(IP));
	memset(&OP, 0, sizeof(OP));
	
	File = fopen("Project1.bin", "r");
	if(File == NULL)
	{
		perror("open file test.dat error");
		return;
	}

	fseek(File, 0L, SEEK_END);  
    len_CPI = ftell(File);  

	if(len_CPI > sizeof(tmpbuf))
	{
		fclose(File);
		return;
	}

	bytesread = fread(&IP, 1, len_CPI, File);
	fclose(File);

	memset(&exeFileInfo, 0, sizeof(EXE_FILE_INFO));
	exeFileInfo.m_dwSize = len_CPI;
	exeFileInfo.m_pData  = tmpbuf;
	exeFileInfo.m_Priv = 0;
	exeFileInfo.m_wFileID = fileid;
	retcode = Dongle_DownloadExeFile(hKey, &exeFileInfo, 1);
	showRet("Dongle_DownloadExeFile", retcode);

		
}

void RunExe()
{
	DWORD  ret;
	int retcode;
	int fileid = 0x1010;
	unsigned char str[1024];

	DownExe();
	
	ret = Dongle_RunExeFile(hKey, fileid, str, 1024, &retcode);
	
	showRet("Dongle_RunExeFile", ret);
}



//================================================
int  main(int argc, char* argv[])
{ 
	int    i;
    DWORD  retcode;
	char   bInput;
	BYTE   tmpbuf[512];
	

    while(1)
	{
		ShowMainCmdMenu();
		//
		bInput = WaitForUserInput();
		//
		if (Count <= 0 && !(bInput =='E' || bInput =='e' || bInput =='Q' || bInput =='q') )
		{
			printf("no key please input 'E' or 'e' to Enum\n");
			continue;
		}
		//
		switch( bInput )
		{
		    case 'E':
		    case 'e':
			{
				DongleEnum();			
				break;
			} 
			case 'O':
			case 'o':
			{		
				OpenDongle()	;
				break;
			} 
			case 'C':
			case 'c':
			{
				CloseDongle();
				break;
			} 
			case 'D':
			case 'd':
			{
        		SeedTest();
				break;
			}
			case 'G':
			case 'g':
			{
				DongleGenRandom();
				break;
			} 
			case 'I':
			case 'i':
			{
        		SetUserID();
				break;
			}
			case 'L':
			case 'l':
			{
				DongleLEDControl();
				break;
			} 
			case 'F':
			case 'f':
			{
				filetest();
				break;
			}
			case 'q':
			case 'Q':
			{
				goto END;
			}
			case 'R':
			case 'r':
			{
				encrypttest();
				break;
			}
			case 'S':
			case 's':
			{
        		MotherSonTest();
				break;
			}
			case 'T':
			case 't':
			{
				authoritytest();
				break;
			}
			case 'M':
			case 'm':
			{
				memorytest();
				break;
			}
			case 'U':
			case 'u':
			{
				updatetest();
				break;
			}
			case 'V':
			case 'v':
			{
				VerifyPin();
				break;
			}
			case 'P':
			case 'p':
			{
				ChangePIN();
				break;
			}
			case 'x':
			case 'X':
			{
				RunExe();
				break;
			}
			default:
			{
				printf(" \n unknown command! \n");
				break;
			}

		}
	}
 
END:
	
	return 0;
}
