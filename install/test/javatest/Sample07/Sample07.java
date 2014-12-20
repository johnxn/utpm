import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample07
{
    public Sample07()
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
	   //写内存区 32个字节
	   byte []memoryData  = new byte[32];
	   for(i = 0; i < 32; i++) memoryData[i] = (byte)i;
	   nRet = dongle.Dongle_WriteShareMemory(handle[0], memoryData, 32);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_WriteShareMemory error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Write share memory success. \n");
	   
	   //读内存区 32个字节
	   for(i = 0; i < 32; i++) memoryData[i] = (byte)0;
	   nRet = dongle.Dongle_ReadShareMemory(handle[0], memoryData);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ReadShareMemory error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Read share memory data: \n");	   
	   for(i = 0; i < 32; i++)
	   {
	      System.out.printf("%02X ", memoryData[i]);
		  if(i == 15) System.out.printf("\n");
	   }
	   System.out.printf("\n");
	   
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
	   
	   //读写数据区（8k） 数据区的前4k(0~4095)空间为 匿名、用户和开发商可读可写，后4k(4096~8191)为开发商可读可写，用户和匿名只能读。
	   //写数据区
	   byte []dataSec = new byte[8192];
	   for(i = 0; i < 32; i++) dataSec[i] = (byte)0x33;
	   nRet = dongle.Dongle_WriteData(handle[0], 0, dataSec, 8192);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_WriteData error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Write data section success. \n");
	   
	   //读数据区
	   for(i = 0; i < 32; i++) dataSec[i] = (byte)0;
	   nRet = dongle.Dongle_ReadData(handle[0], 0, dataSec, 8192);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ReadData error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Read data section success. \n");
	   
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
