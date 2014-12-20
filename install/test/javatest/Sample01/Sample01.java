import java.io.*;
import com.feitian.rockeyarm.Dongle;

public class Sample01
{
    public Sample01()
	{
	}
    public static void main(final String args[]) 
    {
	   byte [] dongleInfo = new byte [1024];
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

	   int index = 0;//找到的第1把锁
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
	   System.out.printf("Cos Version: %02d.%02d.\n", (ver[0] & 0xFF00)>>8, (ver[0] & 0x00FF));
	   System.out.printf("Dongle type: 0x%02X.(0xFF表示标准版, 0x00为时钟锁,0x01为带时钟的U盘锁,0x02为标准U盘锁)\n", type[0]);
	   System.out.printf("Dongle birthday: 20%02X-%02X-%02X %02X:%02X:%02X. \n", birthday[0], birthday[1], birthday[2]
	   , birthday[3], birthday[4], birthday[5]);
	   System.out.printf("Dongle agent id: 0x%08X.\n", agent[0]);
	   System.out.printf("Dongle pid: 0x%08X.\n", pid[0]);
	   System.out.printf("Dongle uid: 0x%08X.\n", uid[0]);
	   System.out.printf("Dongle hid: %02X%02X%02X%02X%02X%02X%02X%02X .\n", hid[0], hid[1], hid[2], hid[3], hid[4], hid[5], hid[6], hid[7]);
	   System.out.printf("Dongle isMother: 0x%02X. (0x01表示是母锁, 0x00表示不是母锁)\n", isMother[0]);
	   System.out.printf("Dongle devType: 0x%02X. (0x01表示是HID设备, 0x00是CCID设备).\n", devType[0]);
	   	 
	   //打开第一把锁
	   nRet = dongle.Dongle_Open(handle, 0);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_Open error. error code: 0x%08X. \n ", nRet);
		 return ;
	   }
	   System.out.printf("Open Dongle ARM success[handle=0x%08X]. \n",handle[0]);
	   
	   //重设COS安全状态
	   nRet = dongle.Dongle_ResetState(handle[0]);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Dongle_ResetState error. error code: 0x%08X. \n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("Reset COS State success. \n");
	   
	   //获取随机数
	   byte []random = new byte[16];
	   nRet = dongle.Dongle_GenRandom(handle[0], 16, random);
	   if(nRet != Dongle.DONGLE_SUCCESS)
	   {
	     System.out.printf("Get random error. error code: 0x%08X. \n ", nRet);
		 dongle.Dongle_Close(handle[0]);
		 return ;
	   }
	   System.out.printf("The Random data: ");
	   for(int i = 0; i < 16; i++)
	   {
	      System.out.printf("%02X ", random[i]);
	   }
	   System.out.printf(".\n");
	   
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

