import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample12
{
    public Sample12()
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
	   System.out.printf("Enum count: [%d] .\n", count[0]); 
	   
	   //打开第一把锁
	   nRet = dongle.Dongle_Open(handle, 0);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_Open error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Open success[handle=0x%08X]. \n",handle[0]);
	   
	   //HASH运算
	   byte [] md5 = new byte[16];
	   byte [] sha1 = new byte[20];
	   byte [] sm3 = new byte[32];
	   
	   byte [] data = new byte[1024];
	   for(i = 0; i < 1024; i++) data[i] = (byte)i;
	   //MD5
	   nRet = dongle.Dongle_HASH(handle[0],Dongle.FLAG_HASH_MD5, data, 1024, md5);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_HASH[MD5] error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("MD5  data: ");
       for(i = 0; i < 16; i++) System.out.printf("%02X ", md5[i]);	   
	   System.out.printf("\n");
	   
	   //SHA1
	   nRet = dongle.Dongle_HASH(handle[0],Dongle.FLAG_HASH_SHA1, data, 1024, sha1);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_HASH[SHA1] error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("SHA1 data: ");
       for(i = 0; i < 20; i++) System.out.printf("%02X ", sha1[i]);	   
	   System.out.printf("\n");
	   
	   //SM3
	   nRet = dongle.Dongle_HASH(handle[0],Dongle.FLAG_HASH_SM3, data, 1024, sm3);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_HASH[SM3] error . error code: 0x%08X .\n", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("SM3  data: ");
       for(i = 0; i < 32; i++) System.out.printf("%02X ", sm3[i]);	   
	   System.out.printf("\n");
	   
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
