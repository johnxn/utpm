import java.io.*;
import com.feitian.rockeyarm.Dongle;
//说明：应该先唯一化锁之后才能运行该示例，否则无法修改用户PIN码
//唯一化锁的示例程序，请参考Sample04
public class Sample05
{//该实例需要一把经过初始化后的锁才能正常运行
    public Sample05()
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
	   nRet = dongle.Dongle_VerifyPIN(handle[0], dongle.FLAG_ADMINPIN, strPin, nRemain);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_VerifyPIN error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Verify admin pin success. \n");
	   
	   //修改用户PIN码 “87654321”
	   String strOldUserPin = "12345678";
	   String strNewUserPin = "87654321";
	   int nTryCount = 0xFF;//表示用户PIN不限制重试次数
	   nRet = dongle.Dongle_ChangePIN(handle[0], Dongle.FLAG_USERPIN, strOldUserPin, strNewUserPin, nTryCount);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ChangePIN error . error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Change user pin success. \n");
	   
	   //清除安全状态，回到匿名态
	   nRet = dongle.Dongle_ResetState(handle[0]);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ResetState error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Reset Cos state success. \n");
	   
	   //验证旧的用户PIN =>失败
	   nRet = dongle.Dongle_VerifyPIN(handle[0], dongle.FLAG_USERPIN, strOldUserPin, nRemain);
	   System.out.printf("Verify user pin return: 0x%08X [remain:%d].\n ", nRet, nRemain[0]);
	   //验证新的用户PIN =>成功
	   nRet = dongle.Dongle_VerifyPIN(handle[0], dongle.FLAG_USERPIN, strNewUserPin, nRemain);
	   System.out.printf("Verify user pin return: 0x%08X [remain:%d].\n ", nRet, nRemain[0]);
	   
	   //再次验证开发商密码
       strPin = "FFFFFFFFFFFFFFFF"; //默认开发商密码
	   nRet = dongle.Dongle_VerifyPIN(handle[0], dongle.FLAG_ADMINPIN, strPin, nRemain);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_VerifyPIN error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Verify admin pin success again. \n");
	   
	   //重设用户PIN码（必须为开发商权限）
	   nRet = dongle.Dongle_ResetUserPIN(handle[0], strPin);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ResetUserPIN error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Reset user pin success again. \n");
	   
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
