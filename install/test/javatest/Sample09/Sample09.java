import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample09
{
    public Sample09()
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
	   
	   //创建ECC私钥
	   byte [] prikeyLic  = new byte[1024];
	   int []prikeyLicLen = new int[1];
	   int callCount = 0xFFFFFFFF;//调用次数，0xFFFFFFFF表示不限制
	   byte callPriv = 1;// 最小调用权限：0为最小匿名权限  1为最小用户权限  2为最小开发商权限
	   byte isDecOnRAM = 0;//是否在加密锁内存中递减
	   byte isReset = 0;//执行完之后是否回到匿名态
	   nRet = dongle.Convert_PRIKEY_LIC_To_Buffer(callCount, callPriv, isDecOnRAM, isReset, prikeyLic, prikeyLicLen);//构造权限结构
	   System.out.printf("Convert_PRIKEY_LIC_To_Buffer return: 0x%08X [prikeyliclen=%d].\n", nRet, prikeyLicLen[0]);
	   short type = (short)Dongle.FILE_PRIKEY_ECCSM2;
	   short size = 256;//也可以是192
	   byte [] attrBuffer = new byte[1024];
	   int [] attrBufferLen = new int[1];
	   nRet = dongle.Convert_PRIKEY_FILE_ATTR_To_Buffer(type, size, prikeyLic, prikeyLicLen[0], attrBuffer, attrBufferLen);//构造属性结构
	   System.out.printf("Convert_PRIKEY_FILE_ATTR_To_Buffer return: 0x%08X [attrBufferLen=%d].\n", nRet, attrBufferLen[0]);	 
	   nRet = dongle.Dongle_CreateFile(handle[0], Dongle.FILE_PRIKEY_ECCSM2, 0x2222, attrBuffer);//创建文件
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_CreateFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Create ECC private key success. \n");
	   
	   //生成ECC私钥
	   byte [] eccPubkey = new byte[1024];
	   byte [] eccPrikey = new byte[1024];
	   int [] eccPubLen = new int[1];
	   int [] eccPriLen = new int [1];
	   nRet = dongle.Dongle_EccGenPubPriKey(handle[0], 0x2222, eccPubkey, eccPubLen, eccPrikey, eccPriLen);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_EccGenPubPriKey error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Gen ECC public key and private key success. \n");
	   
	   //将公钥和私钥写到文件中去
	   FileOutputStream fos;
       fos = new FileOutputStream("2222.EccSm2pub");
       fos.write(eccPubkey, 0, eccPubLen[0]);
       fos.close();
	   
	   fos = new FileOutputStream("2222.EccSm2pri");
       fos.write(eccPrikey, 0, eccPriLen[0]);
       fos.close();
	   
	   //ECC签名和验签
	   //1、ECC签名
	   byte [] hashdata = new byte[32];//256长度的hash不超过256/8=32，192长度的hash不超过192/8=24
	   byte [] outdata = new byte[64];//签名数据必为64
	   nRet = dongle.Dongle_GenRandom(handle[0], 32, hashdata);//获取随机数作为hash值
	   System.out.printf("Dongle_GenRandom as hash data return: 0x%08X .\n", nRet);
	   nRet = dongle.Dongle_EccSign(handle[0],0x2222,hashdata, 32, outdata);
	   System.out.printf("Dongle_EccSign return: 0x%08X .\n", nRet);
	   //2、ECC验签
	   nRet = dongle.Dongle_EccVerify(handle[0],eccPubkey,hashdata, 32, outdata);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_EccVerify error. error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("ECC public key verify success. \n");
	   
	   //删除ECC私钥文件
	   nRet = dongle.Dongle_DeleteFile(handle[0], Dongle.FILE_PRIKEY_ECCSM2, 0x2222);
       if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_DeleteFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Delete ECC private key success. \n");	
	   
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
