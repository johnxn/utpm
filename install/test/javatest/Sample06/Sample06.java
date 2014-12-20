import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import com.feitian.rockeyarm.Dongle;

public class Sample06
{
    public Sample06()
	{
	}
    public static void main(final String args[]) throws Exception
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
	   
	   //获取锁内时间
	   int []utcTime = new int[1];
	   nRet = dongle.Dongle_GetUTCTime(handle[0], utcTime);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_GetUTCTime error [remain cout: %d]. error code: 0x%08X .\n ", nRemain[0], nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   //转换为本地时间显示
	   long time = (long)utcTime[0];//  System.currentTimeMillis()/1000
	   Date date = new Date(time);
	   Calendar cal = Calendar.getInstance();
	   cal.setTime(date);
	   System.out.printf("Time is: %04d-%02d-%02d %02d:%02d:%02d. \n", cal.get(Calendar.YEAR), (cal.get(Calendar.MONTH) + 1),
	   cal.get(Calendar.DATE), cal.get(Calendar.HOUR_OF_DAY), cal.get(Calendar.MINUTE), cal.get(Calendar.SECOND));
	 
	   //设置到期时间
	   SimpleDateFormat foo = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
	   //1、到期小时数
	   int deadlineTime = 24;//设置小时数（取值范围在1~65535）
	   nRet = dongle.Dongle_SetDeadline(handle[0], deadlineTime);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SetDeadline error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Set Deadlin [hour:24] success .\n ");	   
	   //2、到期日期 2015-4-23 17:30:01
	   Date d1 = foo.parse("2015-04-23 17:30:01");
	   deadlineTime = (int)d1.getTime();
	   nRet = dongle.Dongle_SetDeadline(handle[0], deadlineTime);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SetDeadline error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Set Deadlin [date: 2015-4-23 17:30:01] success .\n ");	 
	   //3、取消期限限制
	   deadlineTime = 0xFFFFFFFF;//只有此值表示取消时间限制
	   nRet = dongle.Dongle_SetDeadline(handle[0], deadlineTime);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_SetDeadline error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Cancel Deadlin success .\n ");
	   
	   //获取到期时间
	   int []dtime = new int[1];
	   nRet = dongle.Dongle_GetDeadline(handle[0], dtime);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_GetDeadline error. error code: 0x%08X .\n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   //System.out.printf("Get Deadlin [date: 2015-4-23 17:30:01] success .\n ");
	   if(dtime[0] == 0xFFFFFFFF)
	   {
	     System.out.printf("No time limited. \n");
	   }
	   else
	   {
	     if(dtime[0] > 1 && dtime[0] < 65535)
		 {//代表小时数
            System.out.printf("the deadline time is hour [%d]. \n", dtime[0]);		 
		 }
		 else
		 {//代表日期
		    time = (long)utcTime[0];//  System.currentTimeMillis()/1000
	        date = new Date(time);
	        cal = Calendar.getInstance();
	        cal.setTime(date);
	        System.out.printf("the deadline time is date [%04d-%02d-%02d %02d:%02d:%02d]. \n", cal.get(Calendar.YEAR), (cal.get(Calendar.MONTH) + 1),
	        cal.get(Calendar.DATE), cal.get(Calendar.HOUR_OF_DAY), cal.get(Calendar.MINUTE), cal.get(Calendar.SECOND));
		 }
	   }   
	   
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
