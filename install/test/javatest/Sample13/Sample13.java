import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample13
{//空锁不能进行种子码运算(pid = FFFFFFFF 的锁为空锁)
    public Sample13()
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
	   
	   //限制种子码运算次数 本例中为3次
	   nRet = dongle.Dongle_LimitSeedCount(handle[0], 3);
	   System.out.printf("Dongle_LimitSeedCount[3 times] return 0x%08X. \n", nRet);
	   
	   //种子码运算，运算4次肯定最后一次出错
	   byte []seed = new byte[250];//最大长度不能超过250个字节
	   byte []outData = new byte[16];//输出长度固定为16个字节
	   for(i = 0; i < 250; i++) seed[i] = (byte)i;
	   for(i = 0; i < 4; i++)
	   {
     	  nRet = dongle.Dongle_Seed(handle[0], seed, 250, outData);
		  System.out.printf("Dongle_Seed[index=%d] return 0x%08X. \n", i, nRet);
	   }
	   
	   //取消种子码运算限制 必须为0xFFFFFFFF
	   nRet = dongle.Dongle_LimitSeedCount(handle[0], 0xFFFFFFFF);
	   System.out.printf("Dongle_LimitSeedCount[0xFFFFFFFF] return 0x%08X. \n", nRet);
	   
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
