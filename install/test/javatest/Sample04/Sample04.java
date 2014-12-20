import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample04
{
    public Sample04()
	{
	}
    public static void main(final String args[]) 
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
	   nRet = dongle.Dongle_VerifyPIN(handle[0], Dongle.FLAG_ADMINPIN, strPin, nRemain);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_VerifyPIN error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Verify admin pin success. \n");
	   
	   //唯一化锁
	   byte []seed = new byte[32];
	   String []newPid = new String[1];
	   String []newAdminPin = new String[1];
	   for(int i = 0; i < 32; i++) seed[i] = (byte)0x11;
	   nRet = dongle.Dongle_GenUniqueKey(handle[0], 32, seed, newPid, newAdminPin);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_GenUniqueKey error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Gen unique key success. newPid=%s , newAdminPin=%s\n", newPid[0], newAdminPin[0]);
	   
	   //验证用户PIN码
	   String userPin = "12345678";
	   int []nRemainCount = new int[1];
	   nRet = dongle.Dongle_VerifyPIN(handle[0], Dongle.FLAG_USERPIN, userPin, nRemainCount);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_VerifyPIN userpin error [remainCount: %d]. error code: 0x%08X .\n ", nRemainCount[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Verify user pin success. \n");
	   
	   //清除安全状态，回到匿名态
	   nRet = dongle.Dongle_ResetState(handle[0]);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ResetState error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Reset Cos state success. \n");
	   
	   //再次验证开发商PIN
	   nRet = dongle.Dongle_VerifyPIN(handle[0], Dongle.FLAG_ADMINPIN, newAdminPin[0], nRemain);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_VerifyPIN error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Verify admin pin success again. \n");
	   
	   //一键恢复出厂设置
	   nRet = dongle.Dongle_RFS(handle);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_RFS error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("RFS success again. \n");
	   
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
