import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample11
{
    public Sample11()
	{
	}
    public static void main(final String args[]) 
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
	   
	   //创建3DES/SM4密钥
	   byte []key = new byte[16];//密钥长度必须为16位
	   nRet = dongle.Dongle_GenRandom(handle[0], 16, key);//获取随机数作密钥值
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_GenRandom error. error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Gen key success. \n");
	   int nEncPriv = 1;//加密权限：0为最小匿名权限  1为最小用户权限  2为最小开发商权限
	   byte [] keyLic = new byte[1024];
	   int [] keyLicLen = new int [1];
	   int size = 16;
 	   nRet = dongle.Convert_KEY_LIC_To_Buffer(nEncPriv, keyLic, keyLicLen);//构造权限结构
	   System.out.printf("Convert_KEY_LIC_To_Buffer return: 0x%08X [keyLicLen=%d].\n", nRet, keyLicLen[0]);
	   byte [] attrBuffer = new byte[1024];
	   int [] attrBufferLen = new int[1];
	   attrBufferLen[0] = 1024;
	   nRet = dongle.Convert_KEY_FILE_ATTR_To_Buffer(size, keyLic, keyLicLen[0], attrBuffer, attrBufferLen);//构造属性结构
	   System.out.printf("Convert_KEY_FILE_ATTR_To_Buffer return: 0x%08X [attrBufferLen=%d].\n", nRet, attrBufferLen[0]);	
	   nRet = dongle.Dongle_CreateFile(handle[0], Dongle.FILE_KEY, 0x6666, attrBuffer);//创建文件
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_CreateFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Create 3DES/SM4 key success. \n");
	   
	   //3DES加解密
	   byte []m = new byte[1024];
	   byte []c = new byte[1024];
	   byte []temp = new byte[1024];
	   for(i = 0; i < 1024; i++) m[i] = temp[i] = (byte)i;
	   nRet = dongle.Dongle_TDES(handle[0], 0x6666, Dongle.FLAG_ENCODE, m, c, 1024);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_TDES encode error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("3DES encode success. \n");
	   
	   for(i = 0; i < 1024; i++) m[i] = (byte)0;
	   nRet = dongle.Dongle_TDES(handle[0], 0x6666, Dongle.FLAG_DECODE, c, m, 1024);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_TDES encode error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("3DES encode success. \n");
	   
	   //检查3DES加解密结果是否正确
	   int isSame = 1;
	   for(i = 0; i < 1024; i++)
	   { 
	      if(m[i] != temp[i])
		  {
		     isSame = 0;
			 break;
		  }
	   }
	   if(isSame == 1)
	     System.out.printf("3DES encode and decode is correct.\n");
	   else 
	     System.out.printf("3DES encode and decode is error.\n");
	   
	   //SM4加密和解密
	   for(i = 0; i < 1024; i++) m[i] = temp[i] = (byte)i;
	   nRet = dongle.Dongle_SM4(handle[0], 0x6666, Dongle.FLAG_ENCODE, m, c, 1024);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SM4 encode error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("SM4 encode success. \n");
	   
	   for(i = 0; i < 1024; i++) m[i] = (byte)0;
	   nRet = dongle.Dongle_SM4(handle[0], 0x6666, Dongle.FLAG_DECODE, c, m, 1024);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SM4 encode error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("SM4 encode success. \n");
	   
	   //检查SM4加解密结果是否正确
	   isSame = 1;
	   for(i = 0; i < 1024; i++)
	   { 
	      if(m[i] != temp[i])
		  {
		     isSame = 0;
			 break;
		  }
	   }
	   if(isSame == 1)
	     System.out.printf("3DES encode and decode is correct.\n");
	   else 
	     System.out.printf("3DES encode and decode is error.\n");
	   
	   //删除密钥文件
	   nRet = dongle.Dongle_DeleteFile(handle[0], Dongle.FILE_KEY, 0x6666);
       if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_DeleteFile error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Delete 3DES/SM4 key success. \n");	
	   
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
