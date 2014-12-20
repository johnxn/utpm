import java.io.*;
import com.feitian.rockeyarm.Dongle;
public class Sample14
{
    public Sample14()
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
	   System.out.printf("Enum Dongle count: [%d] .\n", count[0]); 
	   
	   //记录锁的信息
	   short []ver = new short [1];
	   short []type = new short [1];
	   byte []birthday = new byte [8];
	   int []agent = new int[1];
	   int []pid = new int[1];
	   int []uid = new int[1];
	   byte []hid = new byte[8];
	   int []isMother = new int[1];
	   int []devType = new int[1];
	   nRet = dongle.GetDongleInfo(dongleInfo, 0, ver, type, birthday, agent, pid, uid, hid, isMother, devType);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("GetDongleInfo error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   
	   //打开第一把锁
	   nRet = dongle.Dongle_Open(handle, 0);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_Open error. error code: 0x%08X .\n ", nRet);
		 return ;
	   }
	   System.out.printf("Open Dongle success[handle=0x%08X]. \n",handle[0]);
	   
	   //LED灯的控制
	   nRet = dongle.Dongle_LEDControl(handle[0], Dongle.LED_OFF);//LED 灯关
	   System.out.printf("Dongle_LEDControl[Off]. return: 0x%08X\n", nRet);

	   nRet = dongle.Dongle_LEDControl(handle[0], Dongle.LED_BLINK);//LED 灯闪
	   System.out.printf("Dongle_LEDControl[Blink]. return: 0x%08X\n", nRet);
	   
	   nRet = dongle.Dongle_LEDControl(handle[0], Dongle.LED_ON);//LED 灯开
	   System.out.printf("Dongle_LEDControl[On]. return: 0x%08X\n", nRet);
	
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
	   
	   //切换通讯协议
	   if(devType[0] == Dongle.PROTOCOL_HID)
	      nRet = dongle.Dongle_SwitchProtocol(handle, Dongle.PROTOCOL_CCID);
	   else if(devType[0] == Dongle.PROTOCOL_CCID)
	      nRet = dongle.Dongle_SwitchProtocol(handle, Dongle.PROTOCOL_HID);
	   System.out.printf("Dongle_SwitchProtocol[%d]. return: 0x%08X\n", devType[0], nRet);
	   
	   //关闭加密锁
	   nRet = dongle.Dongle_Close(handle[0]);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	      System.out.printf("Dongle_Close error. error code: 0x%08X \n", nRet);
		  return;
	   }
	   System.out.printf("Close Dongle success. \n");
       	   
    }    
}
