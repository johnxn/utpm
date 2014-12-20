import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample02
{
    public Sample02()
	{
	}
    public static void main(final String args[]) 
    {
	   //byte [] dongleInfo = new byte [1024];
	   int [] count = new int[1];
	   int [] handle = new int [1];
	   int nRet = 0;
       Dongle dongle = new Dongle();
	   //枚举锁
       nRet = dongle.Dongle_Enum(null, count);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_Enum error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }	   
	   System.out.printf("Enum Dongle ARM count: [%d] .\n", count[0]);
     	 
	   //打开锁
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
	   
	   //创建数据文件
	   byte []licBuffer = new byte[100];
	   byte []attrBuffer = new byte[200];
	   int []licBufferLen = new int[1];
	   int []attrBufferLen = new int[1];
	   nRet = dongle.Convert_DATA_LIC_To_Buffer((short)0, (short)1, licBuffer, licBufferLen);
	   nRet = dongle.Convert_DATA_FILE_ATTR_To_Buffer(1024, licBuffer, licBufferLen[0], attrBuffer, attrBufferLen);
	   nRet = dongle.Dongle_CreateFile(handle[0], dongle.FILE_DATA, 0x1100, attrBuffer);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_CreateFile error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Create data file success. \n");
	   
	   //写文件
	   byte []data = new byte[1024];
	   for(int i = 0; i <1024; i++) data[i] = 0x11;
	   nRet = dongle.Dongle_WriteFile(handle[0],dongle.FILE_DATA,0x1100,0,data, 1024);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_WriteFile error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Write data file success. \n");
	   
	   //读文件
	   byte []outData = new byte[1024];
	   nRet = dongle.Dongle_ReadFile(handle[0], 0x1100, 0, outData, 1024);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ReadFile error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Read data file success. \n");
	   System.out.printf("Read Data: \n");
	   for(int i = 0; i< 1024;i++)
	   {
	      System.out.printf("%02X ", outData[i]);
		  if((i+1)%25 == 0) System.out.printf("\n");
	   }
	   System.out.printf("\n");
	   
	   //列数据文件
	   byte []fileList = new byte[1024];
	   int []fileListLen = new int[1];
	   fileListLen[0] = 1024;
	   nRet = dongle.Dongle_ListFile(handle[0], dongle.FILE_DATA, fileList, fileListLen);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ListFile error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("List data file success. [len=%d] \n", fileListLen[0]);
	   int index = 0;
	   while(true)
	   {	  
          short []fileID = new short[1];
          int  []fileSize = new int[1];
          short []readPriv = new short[1];
          short []writePriv = new short[1];		  
	      nRet = dongle.Get_DATA_FILE_LIST_Info(fileList, fileListLen[0], index, fileID, fileSize, readPriv, writePriv);
		  if(nRet != Dongle.DONGLE_SUCCESS)
		  {
		     if(nRet == Dongle.DONGLE_INVALID_PARAMETER)
			 {			    
				break;
			 }
			 else
			 {
 		       System.out.printf("Get_DATA_FILE_LIST_Info . error code: 0x%08X.\n ", nRet);
			   dongle.Dongle_Close(handle[0]);
			   return;
			 }
		  }
		  System.out.printf("  >>FileID   :%04X.\n", fileID[0]);
		  System.out.printf("  >>FileSize :%04d.\n", fileSize[0]);
		  System.out.printf("  >>ReadPriv :%X.   (0为最小匿名权限  1为最小用户权限  2为最小开发商权限)\n", readPriv[0]);
		  System.out.printf("  >>WritePriv:%X.   (0为最小匿名权限  1为最小用户权限  2为最小开发商权限)\n", writePriv[0]);
		  System.out.printf("****************\n");
		  index++;
	   }
	   
	   //删除文件
	   nRet = dongle.Dongle_DeleteFile(handle[0], dongle.FILE_DATA, 0x1100);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_DeleteFile error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Delete data file [0x1100] success. \n");
	   
	   nRet = dongle.Dongle_Close(handle[0]);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	      System.out.printf("Dongle_Close error. error code: 0x%08X \n", nRet);
		  return;
	   }
	   System.out.printf("Close Dongle ARM success. \n");
       	   
    }    
}

