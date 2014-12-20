import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample10
{
    public Sample10()
	{
	}
    public static void main(final String args[]) throws IOException
    {
	   byte [] dongleInfo = new byte [100];
	   int [] count = new int[1];
	   int [] handle = new int [1];
	   int nRet = 0;
	   
       Dongle dongle = new Dongle();	   
	   //枚举锁
       nRet = dongle.Dongle_Enum(dongleInfo, count);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_Enum error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }	   
	   System.out.printf("Enum Dongle ARM count: [%d] .\n", count[0]); 
	   
	   //打开第一把锁
	   nRet = dongle.Dongle_Open(handle, 0);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_Open error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Open Dongle ARM success[handle=0x%08X]. \n",handle[0]);
	   
	   //验证开发商密码
	   int []nRemain = new int[1];
       String strPin = "FFFFFFFFFFFFFFFF"; //默认开发商密码
	   nRet = dongle.Dongle_VerifyPIN(handle[0], dongle.FLAG_ADMINPIN, strPin, nRemain);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_VerifyPIN error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Verify admin pin success. \n");
	   
	   //创建SM2私钥
	   byte [] prikeyLic  = new byte[1024];
	   int []prikeyLicLen = new int[1];
	   int callCount = 0xFFFFFFFF;//调用次数，0xFFFFFFFF表示不限制
	   byte callPriv = 1;// 最小调用权限：0为最小匿名权限  1为最小用户权限  2为最小开发商权限
	   byte isDecOnRAM = 0;//是否在加密锁内存中递减
	   byte isReset = 0;//执行完之后是否回到匿名态
	   nRet = dongle.Convert_PRIKEY_LIC_To_Buffer(callCount, callPriv, isDecOnRAM, isReset, prikeyLic, prikeyLicLen);//构造权限结构
	   System.out.printf("Convert_PRIKEY_LIC_To_Buffer return: 0x%08X [prikeyliclen=%d].\n", nRet, prikeyLicLen[0]);
	   short type = (short)Dongle.FILE_PRIKEY_ECCSM2;
	   short size = (short)0x8100;//SM2的size必须为这个值
	   byte [] attrBuffer = new byte[1024];
	   int [] attrBufferLen = new int[1];
	   nRet = dongle.Convert_PRIKEY_FILE_ATTR_To_Buffer(type, size, prikeyLic, prikeyLicLen[0], attrBuffer, attrBufferLen);//构造属性结构
	   System.out.printf("Convert_PRIKEY_FILE_ATTR_To_Buffer return: 0x%08X [attrBufferLen=%d].\n", nRet, attrBufferLen[0]);	 
	   nRet = dongle.Dongle_CreateFile(handle[0], Dongle.FILE_PRIKEY_ECCSM2, 0x3333, attrBuffer);//创建文件
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_CreateFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Create SM2 private key success. \n");
	   
	   //生成ECC私钥
	   byte [] sm2Pubkey = new byte[1024];
	   byte [] sm2Prikey = new byte[1024];
	   int [] sm2PubLen = new int[1];
	   int [] sm2PriLen = new int [1];
	   nRet = dongle.Dongle_SM2GenPubPriKey(handle[0], 0x3333, sm2Pubkey, sm2PubLen, sm2Prikey, sm2PriLen);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SM2GenPubPriKey error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Gen SM2 public key and private key success. \n");
	   
	   //将公钥和私钥写到文件中去
	   FileOutputStream fos;
       fos = new FileOutputStream("3333.EccSm2pub");
       fos.write(sm2Pubkey, 0, sm2PubLen[0]);
       fos.close();
	   
	   fos = new FileOutputStream("3333.EccSm2pri");
       fos.write(sm2Prikey, 0, sm2PriLen[0]);
       fos.close();
	   
	   //SM2签名和验签
	   //1、SM2签名
	   byte [] hashdata = new byte[32];//256长度的hash不超过256/8=32，192长度的hash不超过192/8=24
	   byte [] outdata = new byte[64];//签名数据必为64
	   nRet = dongle.Dongle_GenRandom(handle[0], 32, hashdata);//获取随机数作为hash值
	   System.out.printf("Dongle_GenRandom as hash data return: 0x%08X .\n", nRet);
	   nRet = dongle.Dongle_SM2Sign(handle[0],0x3333,hashdata, 32, outdata);
	   System.out.printf("Dongle_SM2Sign return: 0x%08X .\n", nRet);
	   //2、SM2验签
	   nRet = dongle.Dongle_SM2Verify(handle[0],sm2Pubkey,hashdata, 32, outdata);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SM2Verify error. error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("SM2 public key verify success. \n");
	   
	   //删除ECC私钥文件
	   nRet = dongle.Dongle_DeleteFile(handle[0], Dongle.FILE_PRIKEY_ECCSM2, 0x3333);
       if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_DeleteFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Delete SM2 private key success. \n");	
	   
	   //关闭加密锁
	   nRet = dongle.Dongle_Close(handle[0]);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	      System.out.printf("Dongle_Close error. error code: 0x%08X \n", nRet);
		  return;
	   }
	   System.out.printf("Close Dongle ARM success. \n");
       	   
    }    
}
