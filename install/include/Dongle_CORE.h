/*
  Rockey ARM加密锁 APDU 接口库
 */

#ifndef  __DONGLE_CORE_HEADER_H
#define  __DONGLE_CORE_HEADER_H

#include "Dongle_API.h"
#include "usb.h"
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>


#define TRUE   1
#define FALSE  0



//通用
#define ARM_SUCCESS           0x9000  //操作成功
#define ARM_INVALID_INS       0x6C00  //无效的INS
#define ARM_INVALID_P1        0x6C01  //无效的P1
#define ARM_INVALID_P2        0x6C02  //无效的P2
#define ARM_INVALID_LEN       0x6C03  //无效的LEN(即p3,p4)
#define ARM_INVALID_PARAM     0x6C04  //无效的参数(如:数据中的一些参数)
#define ARM_FAILED            0x6C05  //操作失败
#define ARM_EXPIRE            0x6C06  //已过期(仅时钟锁)

//读写数据
#define ARM_READ_ERR          0x6B00  //读数据错误
#define ARM_WRITE_ERR         0x6B01  //写数据错误

//文件系统
#define ARM_DIR_EXIST         0x6A80  //文件夹已存在
#define ARM_DIR_NOTFOUND      0x6A81  //文件夹不存在
#define ARM_FILE_EXIST        0x6A82  //文件已存在
#define ARM_FILE_NOTFOUND     0x6A83  //文件不存在
//#define ARM_FILE_OFFSET_ERR   0x6A84  //文件偏移错误
//#define ARM_FILE_SIZE_ERR     0x6A85  //文件长度错误
#define ARM_FILE_CFILE_ERR    0x6A86  //创建文件失败
#define ARM_FILE_READ_ERR     0x6A87  //读文件失败
#define ARM_FILE_WRITE_ERR    0x6A88  //写文件失败
#define ARM_FILE_DFILE_ERR    0x6A89  //删文件失败
#define ARM_FILE_CDIR_ERR     0x6A8A  //创建文件夹失败
#define ARM_FILE_DDIR_ERR     0x6A8B  //删除文件夹失败
#define ARM_FILE_TOOLARGE     0x6A8C  //文件太大

//权限相关
#define ARM_NOT_INITED        0x6980  //尚未初始化
#define ARM_ALREADY_INITED    0x6981  //已初始化过了
#define ARM_ADMINPIN_NOTCHECK 0x6982  //管理员PIN没有校验
#define ARM_USERPIN_NOTCHECK  0x6983  //用户PIN没有校验
#define ARM_PIN_BLOCKED       0x6984  //PIN码已被锁定
#define ARM_RUN_LIMITED       0x6985  //运行已受限(如:私钥运算、种子码运算)
#define ARM_INITSON_ERR       0x6986  //初始化子锁失败
#define ARM_NOTMOTHER_ERR     0x6987  //不是母锁


//密锁错误
#define RY_PIN_ERROR         0x6800  //PIN码错误,低位指示剩余次数

//===================================================
#define APDU_COMMAND_SIZE	      8
#define MAX_PACKET_SIZE		 APDU_COMMAND_SIZE+1024 //APDU的最大长度


#define MAX_PINLEN               16 //用户PIN码的最大长度

//保留的文件或文件夹ID
#define DIRID_3F00           0x3F00
#define DIRID_0000           0x0000
#define DIRID_FFFF           0xFFFF

#define DIRID_MIN            0x0001
#define DIRID_MAX            0x3EFF

#define LED_GENRANDOM             3 //LED无关,产生随机数

#define CHANGE_USERPIN            0 //更改用户PIN
#define CHANGE_ADMINPIN           1 //更改管理员PIN
#define RESET_USERPIN             2 //重置用户PIN

#define INIT_PID_ADMINPIN         0 //产生产品ID and 产生管理员密码
#define INIT_RFS                  1 //恢复到出厂设置
#define INIT_INTERFACE            2 //设置USB界面

#define FLAG_RSA1024              0
#define FLAG_RSA2048              1
#define FLAG_ECC192               2
#define FLAG_ECC256               3

//设备类型
#define DEVICE_TYPE_HID           0
#define DEVICE_TYPE_CCID          1


//以下数据结构全部为4字节对齐
#pragma pack(1)

//文件数据结构 (本结构总长为1024字节)
typedef struct
{  
	 unsigned short  m_dirid;                                        //文件夹ID
     unsigned short  m_offset;                                       //偏移地址
     unsigned short  m_len;                                          //访问长度
} FileAccess;

//更改密码的数据结构 (对于更改开发商密码这种情况,PIN码必须是16位, 用户密码不要求)
typedef struct
{
	unsigned short  m_TryCount;             //允许的重试次数 (取值范围为1-255, 其中255表示无限制)
	unsigned char	m_OldPinLen;            //旧密码长度
	unsigned char	m_OldPin[MAX_PINLEN+4]; //加4是为了可直接0终止字串进行比较,无需再拷出来
	unsigned char	m_NewPinLen;            //新密码长度
	unsigned char	m_NewPin[MAX_PINLEN+4]; //加4是为了可直接0终止字串进行比较,无需再拷出来

}CHANGE_PIN;


//连接信息
typedef struct
{
	unsigned int   m_Flag;              //全0标志
	unsigned char   m_Random[64];        //随机数
	unsigned char   m_CommKey[8];        //通讯密钥
	DONGLE_INFO     m_KI;                //加密锁信息

} COMM_INFO;

typedef struct {
    ECCSM2_PRIVATE_KEY Prikey;
	ECCSM2_PUBLIC_KEY  Pubkey;
} ECCKEYPAIR;

//远程升级包头包数据结构(128字节)
typedef struct
{       
	unsigned int   m_flag;       //升级包的合法性标志位(RSA解密完后,此标志必须为0,表示此升级包合法)	
	unsigned char   m_HID[8];     //此升级包对应的硬件ID, FFFFFFFFFFFFFFFF表示不限制硬件ID
	unsigned int   m_UTC;        //此升级包的时间戳
	unsigned short  m_func;       //此升级包的功能号
	unsigned short  m_fchild;     //子功能号:  0擦除  1数据  2地址表
	unsigned short  m_ftype;      //文件类型,比如: FILE_PRIKEY
	unsigned short  m_fileid;     //文件ID
	unsigned short  m_offset;     //写文件时的偏移 (仅用于UPDATE_FUNC_WriteFile功能)
	unsigned short  m_len;        //写文件时的长度 (仅用于UPDATE_FUNC_WriteFile功能)
	unsigned char   m_key[16];    //解密扩展数据的RC4密钥
	unsigned int   m_CRC32;      //扩展数据区的明文数据CRC
	unsigned char   m_data[80];   //头部自带数据块

} HeaderPacket;

//远程升级包包数据结构(1024字节)
typedef struct
{  
    HeaderPacket    m_Header;     //头部 128字节
	unsigned char   m_Data[896];  //扩展数据区 (仅用于UPDATE_FUNC_WriteFile功能)

}UpdatePacket;


//需要发给空锁的初始化数据
typedef struct
{
	unsigned int  m_SeedLen;                 //种子码长度
	BYTE   m_SeedForPID[256];         //产生产品ID和管理员密码的种子码 (最长250个字节)
	char   m_UserPIN[18];             //用户密码(16个字符的0终止字符串)
	BYTE   m_UserTryCount;            //用户密码允许的最大错误重试次数
	BYTE   m_AdminTryCount;           //管理员密码允许的最大错误重试次数
	BYTE   m_UpdatePriKey[4+128+128]; //远程升级私钥 (pke(4字节)+私钥dd（128字节)+公钥nn(128字节))
	unsigned int  m_UserID;                  //用户ID

} COS_SON_DATA;

//母锁数据
typedef struct
{
	COS_SON_DATA  m_Son;               //子锁初始化数据
	int      m_Count;                 //可产生子锁初始化数据的次数 (-1表示不限制次数, 递减到0时会受限)
	BYTE      m_Reserve[12];           //保留,用于16字节对齐

} COS_MOTHER_DATA;


//EXE文件块结构 (长8字节)
typedef struct
{
	unsigned short  m_FILEID;    //文件ID
	unsigned short  m_Priv;      //调用权限: 0为最小匿名权限  1为最小用户权限  2为最小管理员权限
	unsigned short  m_Offset;    //偏移地址
	unsigned short  m_Len;       //文件长度
	
}EXE_BLOCK;

//COS命令接口
//-------------------------------------------------------------------
#define APDU_INS_GET_COMMKEY      0x10     //取通信密钥和KEY的信息
/*
例: p1=0, P2=0, p3=128, buffer=128字节的通讯公钥解密的16字节随机数, 返回64字节的通讯私钥加密的COMM_INFO数据结构
*/

#define APDU_INS_RESET_STATE      0x11     //复位安全状态到匿名
/*
例: p1=0, P2=0, p3=0        ->复位到匿名
*/

#define APDU_INS_LED_RANDOM       0x12     //产生随机数或LED控制
/*
例: p1=LED_GENRANDOM, p2=need_len, p3=0	
	此时p2的范围:1-128	
    p1=LED_ON, P2=0, p3=0
*/

#define APDU_INS_SET_USERID       0x13     //设置用户ID
/*
例: p1=0, P2=0, p3=4, buffer=用户ID
*/

#define APDU_INS_SET_SEEDCOUNT    0x14     //设置种子码可调次数
/*
例: p1=0, P2=0, p3=4, buffer=种子码算法可调次数
*/

#define APDU_INS_INIT_RFS         0x15     //初始化KEY 或 恢复出厂设置
/*
例: p1=INIT_PID_ADMINPIN,  p2=0, p3=len_seed, buffer=seed
	此时p3的范围:1-250
	p1=INIT_RFS,           p2=0, p3=0
*/
//-------------------------------------------------------------------
#define APDU_INS_VERFY_PIN		  0x20     //校验用户PIN 或 管理员PIN
/*
例: 
	p1=FLAG_USERPIN,  P2=0, p3=len, buffer=pindata
	此时p3的范围:1-16
	p1=FLAG_ADMINPIN, P2=0, p3=16,  buffer=pindata
	此时p3必须为16	
*/

#define APDU_INS_CHANGEPIN        0x21     //更改用户PIN 或 重置用户PIN
/*
例: 
	p1=CHANGE_USERPIN, P2=0, p3=sizeof(CHANGE_PIN), buffer=CHANGE_PIN数据结构
	此时p3必须为sizeof(CHANGE_PIN)
	p1=RESET_USERPIN,  P2=0, p3=16, buffer=AdminPin
	此时p3必须为16
*/

#define APDU_INS_SETMODULE        0x22     //设置模块字
/*
例:
p1=0, p2=0, p3=sizeof(MODULE_BLOCK), buf=MODULE_BLOCK数据结构
*/


#define APDU_INS_GETMODULE        0x23     //读取模块字
/*
例:
p1=0, p2=0, p3=sizeof(MODULE_BLOCK), buf=MODULE_BLOCK数据结构
*/

//-------------------------------------------------------------------
#define APDU_INS_FILE_CREATE      0x30     //创建文件
/*
例: p1=FILE_DATA,   p2=文件ID, p3=sizeof(DATA_FILE_ATTR),   buffer=DATA_FILE_ATTR结构
	p1=FILE_PRIKEY, p2=文件ID, p3=sizeof(PRIKEY_FILE_ATTR), buffer=PRIKEY_FILE_ATTR结构
	p1=FILE_KEY,    p2=文件ID, p3=sizeof(XKEY_FILE_ATTR), buffer=KEY_FILE_ATTR结构
注:
	  1. 不使用与可执行程序
	  2. 文件夹ID的取值范围:0x0000-0xEFFF
*/

#define APDU_INS_FILE_READ        0x31     //读文件或者数据区
/*
例：p1=FILE_DATA,   p2=文件ID, p3=sizeof(FileAccess),   buffer=FileAccess结构
注：
    1.只有FILE_DATA的文件才有读的可能性,其他类型的文件均不可读
    2.当文件ID=0xFFFF时,表示访问的是根目录下的数据区(文件)
*/

#define APDU_INS_FILE_WRITE       0x32     //写文件或数据区
/*
例: p1=FILE_DATA,   p2=文件ID, p3=sizeof(FileAccess),   buffer=FileAccess结构
	p1=FILE_PRIKEY, p2=文件ID, p3=sizeof(FileAccess),   buffer=FileAccess结构
	p1=FILE_KEY,    p2=文件ID, p3=sizeof(FileAccess),   buffer=FileAccess结构
	
注：
    当p1=FILE_DATA, p2文件ID=0xFFFF时,表示访问的是根目录下的直读数据区(文件)	  
*/

#define APDU_INS_FILE_DELETE      0x33     //删除文件 或 删除文件夹
/*
例: p1=FILE_DATA,   p2=文件ID,   p3=0 (删除单个文件)
	p1=FILE_PRIKEY, p2=文件ID,   p3=0 (删除单个文件)
	p1=FILE_XESKEY, p2=文件ID,   p3=0 (删除单个文件)
	p1=FILE_X86EXE, p2=文件夹ID, p3=0 (删除文件夹)
*/

#define APDU_INS_FILE_LIST        0x34     //列文件
/*
例: p1=FILE_DATA,   p2=0,   p3=0 (列出数据文件的ID),  返回的数据为DATA_FILE_LIST  结构
	p1=FILE_PRIKEY, p2=0,   p3=0 (列出私钥文件的ID),  返回的数据为PRIKEY_FILE_LIST结构
	p1=FILE_AESKEY, p2=0,   p3=0 (列出密钥文件的ID),  返回的数据为XESKEY_FILE_LIST结构
	p1=FILE_X86EXE, p2=0,   p3=0 (列出x86文件夹的ID), 返回的数据为X86_DIR_LIST    结构
*/
//-------------------------------------------------------------------
#define APDU_INS_RSA_GEN_KEY      0x40     //RSA产生公私钥对
/*
例: p1=0, p2=文件ID, p3=0
*/  

#define APDU_INS_RSA_RUN_PRI      0x41     //RSA运行私钥算法
/*
例: p1=FLAG_ENCODE, p2=密钥文件ID, p3=len, buffer=数据
*/

#define APDU_INS_RSA_RUN_PUB      0x42     //RSA运行公钥算法
/*
例: p1=FLAG_ENCODE, p2=0,  p3=len,  buffer=数据
*/

#define APDU_INS_ECC_GEN_KEY      0x43     //ECC产生公私钥对
/*
例: p1=0, p2=文件ID, p3=0
*/  

#define APDU_INS_ECC_RUN_PRI      0x44     //ECC运行私钥算法
/*
例: p1=FLAG_ENCODE, p2=密钥文件ID, p3=len, buffer=数据
*/

#define APDU_INS_ECC_RUN_PUB      0x45     //ECC运行公钥算法
/*
例: p1=FLAG_ENCODE, p2=0,  p3=len, buffer=数据
*/

#define APDU_INS_SM2_GEN_KEY      0x83     //SM2产生公私钥对
/*
例: p1=0, p2=文件ID, p3=0
*/ 

#define APDU_INS_SM2_RUN_PRI      0x84     //SM2运行私钥算法
/*
例: p1=FLAG_ENCODE, p2=密钥文件ID, p3=len, buffer=数据
*/

#define APDU_INS_SM2_RUN_PUB      0x85     //SM2运行公钥算法
/*
例: p1=FLAG_ENCODE, p2=0,  p3=len, buffer=数据
*/

#define APDU_INS_RUN_SM3          0x86     //运行SM3 HASH算法
/*
例: p1=FLAG_ENCODE, p2=0,  p3=len, buffer=数据
*/

#define APDU_INS_SHARE_MEMORY     0x87	   //读写共享内存
/*
例: get: p1=0, p2=0,  p3=0, buffer=
例: set: p1=1, p2=0,  p3=len, buffer=数据
*/

#define APDU_INS_EXPIRE_TIME      0x88     //实时钟与到期时间
/* 
例: set_expiretime: p1=0, p2=0, buffer=abs UTC
例: set_expiretime: p1=0, p2=1, buffer=hours
例: get_expiretime:	p1=1, p2=0 
例: get_realtime:   p1=2, p2=0
*/

//=========SM4及TDES算法只支持ECB模式==========

#define APDU_INS_RUN_SM4          0x46     //运行SM4算法
/*
例: p1=FLAG_ENCODE, p2=密钥文件ID, p3=len, buffer=数据
*/

#define APDU_INS_RUN_TDES         0x47     //运行TDES算法
/*
例: p1=FLAG_ENCODE, p2=密钥文件ID, p3=len, buffer=数据
*/

#define APDU_INS_RUN_SEED         0x48     //运行种子码算法
/*
例: p1=0, p2=0, p3=len_seed, buffer=seed_data
*/

#define APDU_INS_DOWNLOAD_EXE     0x49     //下载可执行文件
/*
例: p1=0, p2=0,      p3=0,   buffer=   擦除Flash
例: p1=1, p2=offset, p3=len, buffer=   写Flash
例: p1=2, p2=0,      p3=len, buffer=   写地址表文件
*/

#define APDU_INS_RUN_EXE          0x4A     //运行可执行文件
/*
例: p1=0, p2=文件ID, p3=len, buffer=数据
*/

//-------------------------------------------------------------------
#define APDU_INS_GEN_MOTHER       0x50     //产生母锁
/*
例: p1=0, p2=0, p3=sizeof(MOTHER_DATA), buffer=MOTHER_DATA数据结构	
*/

#define APDU_INS_REQUESTINIT      0x51     //空锁请求初始化 及 初始化空锁
/*
例: p1=0, p2=0, p3=0  (返回16字节的请求数据)
	p1=1, p2=0, p3= sizeof(SON_DATA), buffer=SON_DATA数据结构
*/

#define APDU_INS_GENSONDATA       0x52     //母锁产生子锁初始化数据
/*
例: p1=0, p2=0, p3=16, buffer=空锁请求数据
*/
//-------------------------------------------------------------------
#define APDU_INS_SETUPDATEPRIKEY  0x60     //写入远程升级私钥
/*
例: p1=0, p2=0, p3=len_pri, buffer=远程升级私钥
*/

#define APDU_INS_UPDATE           0x61     //从母锁产生升级包 或 升级子锁数据
/*
例: p1=0, p2=0, p3=sizeof(UpdatePacket), buffer=UpdatePacket数据结构	->从母锁产生升级包
	p1=1, p2=0, p3=sizeof(UpdatePacket), buffer=UpdatePacket数据结构	->升级子锁数据 
*/
//-------------------------------------------------------------------

#define APDU_INS_CLRCOS           0x70     //清除COS 或 初始化COS
/*
例: 
p1=0, p2=0, p3=8                ->清COS(8字节清cos密码)
p1=0, p2=1, p3=16               ->更改清COS密码(8字节原密码+8字节新密码)
p1=1, p2=0, p3=sizeof(INIT_COS) ->buffer中为初始化COS所需要的参数结构INIT_COS
p1=1, p2=1, p3=0                ->硬件完好性检查 + COS完整性检查
*/

#define APDU_COMMAND_SIZE	 8
#define MAX_DATA_SIZE        1024
#define HID_INT_BUFF_SIZE    58  //64-6

typedef struct
{
	BYTE id;
	BYTE uc0PacketSizeH;   //  数据包长度_高字节
    BYTE uc1PacketSizeL;   //  数据包长度_低字节
	// 
    BYTE uc2BlockOffsetH;  //  数据块偏移_高字节
    BYTE uc3BlockOffsetL;  //  数据块偏移_低字节
	// 
    BYTE uc4BlockSizeH;    //  数据块长度_高字节
    BYTE uc5BlockSizeL;    //  数据块长度_低字节
	
    BYTE uc6Buffer[HID_INT_BUFF_SIZE];//  存放数据块
}HID_INT_BUFFER;

#define MAX_PATH 1024
typedef struct 
{
	HANDLE m_handle;
	WORD   m_VID;
	WORD   m_PID;
	WORD   m_VER;
	char   m_ProductName[128];
	char   m_ManufactName[128];
	char   m_SerialNumber[128];
	char   m_PATH[MAX_PATH];

}HID_DEVICE_INFO;

typedef struct
{
	BYTE		cla;
	BYTE		ins;
	WORD		p1;
	WORD		p2;
	WORD		len;
	BYTE		buffer[MAX_PACKET_SIZE - APDU_COMMAND_SIZE];
	WORD		sendlen; //定义为发送数据的总长度
	WORD		recvlen; //定义为接收到数据的长度

} APDUEx, *pAPDUEx;

typedef struct
{
	DONGLE_HANDLE*          paddr;          //句柄地址
	HANDLE			handle;		    //打开后的设备真正的ccid的句柄
	BYTE					key[16];		//通讯密钥

} Device_Descript;

typedef struct
{
	DONGLE_HANDLE*          paddr;           //句柄地址
	HANDLE				    handle;			 //打开后的设备真正的hid的句柄
	BYTE					key[16];		 //通讯密钥	
} Device_Descript_HID;


//设备上下文结构
typedef struct
{
	WORD              m_Type;                //设备协议类型
	struct usb_device*  dev;
	usb_dev_handle*	  m_HidHandle;			//打开后的HID句柄
	usb_dev_handle*   m_Handle;              //打开后的CCID句柄
//    HANDLE		      m_Mutex;          			 //互斥器				
	char              m_DevPath[MAX_PATH];   //设备路径
	DONGLE_INFO       m_KeyInfo;             //KEY的信息

} RY_CONTEXT;


struct ET_Device_Descript
{
	char	  device_path[256];
	struct usb_device*  dev;
	usb_dev_handle*	device_handle;
	unsigned short	  ver;
	unsigned char      custom[4];
	unsigned char      sn[8];
	unsigned char      key[8];
	char    IsChecked;
	unsigned char      tmpdevpin[24];
};


typedef struct
{
	WORD  sw1_sw2;
	unsigned int error_code;

} COS_Error;

//COS初始化数据结构
typedef struct
{
    unsigned char   m_CosPswd[8];    // 清COS密码
	unsigned short  m_PID_HID;		 // USB  HID设备的PID (刚下完的COS中默认值为0x0209)
	unsigned short  m_PID_CCID;		 // USB CCID设备的PID (刚下完的COS中默认值为0x020A)
	unsigned int   m_HardwareType;	 // 0xFF表示标准版, 0x00为时钟锁,0x01为带时钟的U盘锁,0x02为标准U盘锁
	unsigned int   m_RealTime;      // 当前实时钟,用于设置锁内实时钟
	unsigned int   m_AgentID;       // 代理商ID
	unsigned char   m_HwSerial[8];   // 硬件ID
	unsigned char   m_BirthDay[8];   // 出厂日期
	unsigned char   m_Pri_nn[128];   // 通讯公钥n
	unsigned char   m_Pri_dd[128];   // 通讯私钥d

} INIT_COS;

struct Endpoint
{
	unsigned int in;
	unsigned int out;
};

DWORD FT_SCardTransmit(RY_CONTEXT* handle, pAPDUEx apdu);

DWORD FT_Enum(DONGLE_INFO * pKEYList, int * pCount);

DWORD FT_Open(RY_CONTEXT** phandle, int index);

DWORD FT_Close(RY_CONTEXT* handle);

DWORD FT_GenRandom(RY_CONTEXT* handle, int len,  unsigned char * pbuf);

DWORD FT_ResetState(RY_CONTEXT* handle);

DWORD FT_LEDControl(RY_CONTEXT* handle, int flag);

DWORD FT_SwitchProtocol(RY_CONTEXT *handle, int flag);

DWORD FT_CreateFile(RY_CONTEXT* handle, int file_type, WORD fileid, void* pFileAttr);

DWORD FT_WriteFile(RY_CONTEXT* handle, int file_type, WORD fileid, WORD offset, BYTE* pData, int len);

DWORD FT_DownloadExeFile(RY_CONTEXT *handle, EXE_FILE_INFO *pExeFileInfo, int count);

DWORD FT_RunExeFile(RY_CONTEXT *handle, WORD fileid, BYTE *pInOut, WORD wInOutLen, int *pMainRet);

DWORD FT_ReadFile(RY_CONTEXT* handle, WORD fileid, WORD offset, BYTE* pData, int Len);

DWORD FT_DeleteFile(RY_CONTEXT* handle, int file_type, WORD fileid);

DWORD FT_ListFile(RY_CONTEXT* handle, int file_type, void* pList, int * pLen);

DWORD FT_GenUniqueKey(RY_CONTEXT* handle,int seedLen, BYTE* pSeed, char* pPIDstr, char* pAdminPINstr);

DWORD FT_ChangePIN(RY_CONTEXT* handle, int flag, char* pOldPIN, char* pNewPIN, int TryCount);

DWORD FT_ResetUserPIN(RY_CONTEXT* handle, char* pAdminPIN);

DWORD FT_VerifyPin(RY_CONTEXT* handle, int Flags, char* pPIN, int* pRemainCount);

DWORD FT_SetUserID(RY_CONTEXT* handle, DWORD UserID);

DWORD FT_SetDeadline(RY_CONTEXT* handle, DWORD dwSeconds);

DWORD FT_GetDeadline(RY_CONTEXT* handle, DWORD* pdwSeconds);

DWORD FT_GetUTCTime(RY_CONTEXT* handle, DWORD* pdwTime);

DWORD FT_ReadData(RY_CONTEXT* handle, int offset, BYTE* pData, int Len);

DWORD FT_WriteData(RY_CONTEXT* handle, int offset, BYTE* pData, int Len);

DWORD FT_ReadShareMemory(RY_CONTEXT* handle, BYTE* pData);

DWORD FT_WriteShareMemory(RY_CONTEXT* handle, BYTE* pData, int Len);

DWORD FT_RsaGenPubPriKey(RY_CONTEXT* handle, WORD fileid, RSA_PUBLIC_KEY* pPubBakup, RSA_PRIVATE_KEY* pPriBakup);

DWORD FT_RsaPri(RY_CONTEXT* handle, WORD fileid, int flag, BYTE* pData, int len, BYTE* pOut, int* pOutLen);

DWORD FT_RsaPub(RY_CONTEXT* handle, int flag, RSA_PUBLIC_KEY* pPubKey, BYTE* pData, int len, BYTE* pOut, int* pOutLen);

DWORD FT_EccGenPubPriKey(RY_CONTEXT* handle, WORD fileid, ECCSM2_PUBLIC_KEY* pPubBakup, ECCSM2_PRIVATE_KEY* pPriBakup);

DWORD FT_EccPri(RY_CONTEXT* handle, WORD fileid, BYTE* pHash, int len_Hash, BYTE* pOut);

DWORD FT_EccPub(RY_CONTEXT* handle, ECCSM2_PUBLIC_KEY* pPubKey, BYTE* pHash, int len_Hash, BYTE* pSign);

DWORD FT_SM2GenPubPriKey(RY_CONTEXT* handle, WORD fileid, ECCSM2_PUBLIC_KEY* pPubBakup, ECCSM2_PRIVATE_KEY* pPriBakup);

DWORD FT_SM2Pri(RY_CONTEXT* handle, WORD fileid, BYTE* pHash, int len_Hash, BYTE* pOut);

DWORD FT_SM2Pub(RY_CONTEXT* handle, ECCSM2_PUBLIC_KEY* pPubKey, BYTE* pHash, int len_Hash, BYTE* pSign);

DWORD FT_TDES(RY_CONTEXT* handle, WORD fileid, int flag, BYTE* pData, int len);

DWORD FT_SM4(RY_CONTEXT* handle, WORD fileid, int flag, BYTE* pData, int len);

DWORD FT_HASH(RY_CONTEXT* handle, int flag, BYTE* pData, int len, BYTE* pHash);

DWORD FT_GenMotherKey(RY_CONTEXT* handle, MOTHER_DATA* pData);

DWORD FT_RequestInit(RY_CONTEXT* handle, BYTE* pData);

DWORD FT_GetInitDataFromMother(RY_CONTEXT* handle, BYTE* pRequest, BYTE* pInitData, int * pLen);

DWORD FT_InitSon(RY_CONTEXT* handle, BYTE* pInitData, int Len);

DWORD FT_SetUpdatePriKey(RY_CONTEXT* handle, RSA_PRIVATE_KEY* pPriKey);

DWORD FT_MakeUpdatePacket(RY_CONTEXT* handle, BYTE* pLicSN, int func, int ftype, WORD fileid, int offset, BYTE* pbuf, int len, RSA_PUBLIC_KEY* pUPubKey, BYTE* pOutData, int* pOutLen);

DWORD FT_MakeUpdatePacketFromMother(RY_CONTEXT* handle, BYTE* pLicSN, int func, int ftype, WORD fileid, int offset, BYTE* pbuf, int len, BYTE* pOutData, int* pOutLen);

DWORD FT_Update(RY_CONTEXT* handle, BYTE* pData, int Len);

DWORD FT_LimitSeedCount(RY_CONTEXT* handle, int count);

DWORD FT_Seed(RY_CONTEXT* handle, BYTE* pSeed, int len_Seed, BYTE* pOut, WORD wMark);

DWORD FT_RFS(RY_CONTEXT* handle);

#endif
