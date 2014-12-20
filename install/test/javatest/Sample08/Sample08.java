import java.io.*;
import java.io.IOException;
import com.feitian.rockeyarm.Dongle;
public class Sample08
{
    public Sample08()
	{
	}
    public static void main(final String args[]) throws IOException
    {
	   byte [] dongleInfo = new byte [100];
	   int [] count = new int[1];
	   int [] handle = new int [1];
	   int nRet = 0;
	   int i = 0;
	   
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
	   
	   //创建RSA私钥
	   byte [] prikeyLic  = new byte[1024];
	   int []prikeyLicLen = new int[1];
	   int callCount = 0xFFFFFFFF;//调用次数，0xFFFFFFFF表示不限制
	   byte callPriv = 1;// 最小调用权限：0为最小匿名权限  1为最小用户权限  2为最小开发商权限
	   byte isDecOnRAM = 0;//是否在加密锁内存中递减
	   byte isReset = 0;//执行完之后是否回到匿名态
	   nRet = dongle.Convert_PRIKEY_LIC_To_Buffer(callCount, callPriv, isDecOnRAM, isReset, prikeyLic, prikeyLicLen);//构造权限结构
	   System.out.printf("Convert_PRIKEY_LIC_To_Buffer return: 0x%08X [prikeyliclen=%d].\n", nRet, prikeyLicLen[0]);
	   short type = (short)Dongle.FILE_PRIKEY_RSA;
	   short size = 1024;//此处也可以2048
	   byte [] attrBuffer = new byte[1024];
	   int [] attrBufferLen = new int[1];
	   nRet = dongle.Convert_PRIKEY_FILE_ATTR_To_Buffer(type, size, prikeyLic, prikeyLicLen[0], attrBuffer, attrBufferLen);//构造属性结构
	   System.out.printf("Convert_PRIKEY_FILE_ATTR_To_Buffer return: 0x%08X [attrBufferLen=%d].\n", nRet, attrBufferLen[0]);	 
	   nRet = dongle.Dongle_CreateFile(handle[0], Dongle.FILE_PRIKEY_RSA, 0x1111, attrBuffer);//创建文件
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_CreateFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Create RSA private key success. \n");
	   
	   //生成RSA公钥和私钥
	   byte [] rsaPubkey = new byte[1024];
	   byte [] rsaPrikey = new byte[1024];
	   int []rsaPubLen = new int[1];
	   int []rsaPriLen = new int [1];
	   nRet = dongle.Dongle_RsaGenPubPriKey(handle[0], 0x1111, rsaPubkey, rsaPubLen, rsaPrikey, rsaPriLen);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_RsaGenPubPriKey error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Gen RSA public key and private key success. \n");
	   
	   //将公钥和私钥写到文件中去
	   FileOutputStream fos;
       fos = new FileOutputStream("1111.Rsapub");
       fos.write(rsaPubkey, 0, rsaPubLen[0]);
       fos.close();
	   
	   fos = new FileOutputStream("1111.Rsapri");
       fos.write(rsaPrikey, 0, rsaPriLen[0]);
       fos.close();
	   
	   //用RSA进行加解密
	   //RSA私钥加密公钥解密
	   //加密数据长度每次只能是密钥长度(1024/8 - 11 = 117或者2048/8 -11 = 245)
	   byte [] m = new byte[117];
	   byte [] temp = new byte[117];
	   //解密出的数据长度为 1024/8 = 128 或者 2048/8 = 256
	   byte [] c = new byte[128];
	   int []outLen = new int[1];
	   outLen[0] = 128;
	   for(i = 0; i < 117; i++) m[i] = temp[i] = (byte)i;
	   //1.私钥加密
	   nRet = dongle.Dongle_RsaPri(handle[0],0x1111,Dongle.FLAG_ENCODE,m,117,c,outLen);
	   
	   for(i = 0; i < 117; i++) m[i] = (byte)0;
	   int []outLen2 = new int[1];
	   outLen2[0] = 117;
	   //2.公钥解密
	   nRet = dongle.Dongle_RsaPub(handle[0],Dongle.FLAG_DECODE,rsaPubkey,c,outLen[0],m,outLen2);
	   
	   int isSame = 1;
	   for(i = 0; i < 117; i++)
	   { 
	      if(m[i] != temp[i])
		  {
		     isSame = 0;
			 break;
		  }
	   }
	   if(isSame == 1)
	     System.out.printf("RSA prikey encode and public decode is correct.\n");
	   else 
	     System.out.printf("RSA prikey encode and public decode is error.\n");
	 
	   //RSA公钥加密私钥解密
	   //1.公钥加密
	   for(i = 0; i < 117; i++) m[i] = temp[i] = (byte)i;
	   outLen[0] = 128;
	   nRet = dongle.Dongle_RsaPub(handle[0],Dongle.FLAG_ENCODE,rsaPubkey,m,117,c,outLen);
	   //2.私钥解密
	   outLen2[0] = 117;
	   nRet = dongle.Dongle_RsaPri(handle[0],0x1111,Dongle.FLAG_DECODE,c,outLen[0],m, outLen2);
	 
	   isSame = 1;
	   for(i = 0; i < 117; i++)
	   { 
	      if(m[i] != temp[i])
		  {
		    isSame = 0;
		    break;
		  }
	   }
	   if(isSame == 1)
	     System.out.printf("RSA public encode and prikey decode is correct.\n");
	   else
	     System.out.printf("RSA public encode and prikey decode is error.\n");
	   
	   //删除RSA私钥文件
	   nRet = dongle.Dongle_DeleteFile(handle[0], Dongle.FILE_PRIKEY_RSA, 0x1111);
       if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_DeleteFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Delete RSA private key success. \n");	   
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
