#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termios.h>
#include <linux/usbdevice_fs.h>
#include <sys/time.h>

#include <asm/types.h>
#include <sys/socket.h>//该头文件需要放在netlink.h前面防止编译出现__kernel_sa_family未定义
#include <linux/netlink.h>
#include "msg_queue.h"
#include "common.h"
#include "thread.h"
#include "common/inc/utils.h"
#include "cmdtable.h"
#include "child_process.h"
#include "logfile.h"
#include "ZW_class_cmd.h"
#include "ZW_serialAPI.h"
#include "ZWave.h"

#include "openssl/aes.h"
#include "openssl/rand.h"

/* ************************************************************************************
 * 宏定义
 * ***********************************************************************************/
#define BUF_SIZE	                            256
#define ZW_SENSOR_MAX_NUM			          	232
#define CAN_NO_RESPONSE                         0x00
#define NEED_RESPONSE                           0x01
#define NODES_BUF_LEN                           29    /* 从controller中获取node列表 */

/* ************************************************************************************
 * 结构体变量
 * ***********************************************************************************/
/* sensor信息 */
typedef struct s_zw_defination
{
	unsigned char sensor_ID[5];//4字节home ID+1字节Node ID,sensor_ID[4] = nodeID!
	unsigned char sensor_kind;
	unsigned char sensor_state;
	unsigned char sensor_flag;
	time_t sensor_time;
}  zw_defination;

/* IPU存储的节点信息 */
struct SlaveNode
{
	unsigned char home_ID[4];
	zw_defination node_inf[ZW_SENSOR_MAX_NUM];
	short int num;
} *SlaveNodeInf;

/* APPS——>IPU要删除的sensor */
struct ZW_delete_sensor
{
	unsigned char hope_sensor[5];
	unsigned char delete_sensor[5];
	int flag;
} zw_delete_sensor;

/* 重发处理数据结构,要初始化为0，其实全局变量会自动初始化为0 */
struct ZW_resend
{
	int flag;
	int num;
	int step;
	struct timespec time;
} zw_resend;

/* 上报云端结构体 */
struct ZW_cloud
{
	unsigned char sensor_ID[5];
	unsigned char message;
	unsigned char flag;
} zw_cloud;

/* 电量获取结构体 */
struct ZW_battery
{
	unsigned char nodeID[50];
	unsigned char flag;
	unsigned char num;
} zw_battery;

/* 临时变量！！ */
struct ZW_temp_node
{
	unsigned char nodeID;
	unsigned char flag;
} zw_temp_node;

/* **************************************************************************************
 * 全局变量
 * **************************************************************************************/
struct timespec zw_busying_time;/* IPU处于组网和撤网时间判断，防止其长时间处于此状态 */
struct timespec zw_cloud_time;/* IPU从云端获取sensor列表计时 */
struct timespec current_time = {0,0};/* 当前时间 */
unsigned char zw_port_name[20];/* 存储port */
int serial_num = 0;
int zw_controller_state = DONGLE_STATE_NO;/* ZW controller所处的状态 */
int zw_start_step = STEP_OPEN_CONTROLLER;/* 开机流程 */
int zw_fd = -1;/*文件描述符*/
int zw_remoteMsgId,zw_localMsgId;/* 共享队列 */
unsigned char RecvBuffer[BUF_SIZE];
unsigned char txBuf[BUF_SIZE];
unsigned char txOptions;//发送串口的标志位，只有0x13指令使用
int zw_set_sensor_number = 0;/* 当前配置的sensor索引 */
int zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_CLOSE;/* 是否开启加速模式，即select时间的变更 */
int zw_clear_mode = ZW_CLOSE_MODE;/* 清除模式，为了与正常模式劈开 */
unsigned char zw_bulb_color[3];
/* ZW controller 升级使用 */
int double80 = 0;
int dayin = 0;
unsigned char txbuff[10];
unsigned char rxbuff[5];
/* openssl AES加密技术 */
unsigned char plaintext_ke[19] = {0, 0x98, 0x06, 1, 1, 1, 1, 1,
		                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
unsigned char plaintext_ka[48];
unsigned char zw_text_in[48];
unsigned char ciphertext_ke[19];
unsigned char zw_text_out[48];
unsigned char ciphertext_ka[48];
unsigned char zw_AE[8];
int zw_num = 0;
unsigned char zw_ofb_flag = 0;
unsigned char zw_IV_tem[16];

unsigned char zw_IV[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x5e, 0x01, 0x42, 0xa1, 0x14, 0xab, 0x6f, 0x0d};
unsigned char zw_Ka[16] = {0x9A, 0xDA, 0xE0, 0x54, 0xF6, 0x3D, 0xFA, 0xFF, 0x5E, 0xA1, 0x8E, 0x45, 0xED, 0xF6, 0xEA, 0x6F};
unsigned char zw_Ke[16] = {0x85, 0x22, 0x71, 0x7D, 0x3A, 0xD1, 0xFB, 0xFE, 0xAF, 0xA1, 0xCE, 0xAA, 0xFD, 0xF5, 0x65, 0x65};
unsigned char zw_Ka_new[16] = {0x1F, 0xCE, 0xDB, 0x21, 0xCE, 0x0B, 0xDC, 0x7A, 0x43, 0xF6, 0xEE, 0xBA, 0xEB, 0x2A, 0x08, 0xD4};
unsigned char zw_Ke_new[16] = {0xDD, 0xF3, 0xB7, 0xD8, 0x9E, 0x65, 0x42, 0x6E, 0x99, 0x56, 0xB7, 0xB8, 0x75, 0x5C, 0x13, 0x0D};
AES_KEY zw_key_ke,zw_key_ka;

/* 测试使用 */
int test_1 = 0;/* 测试close后重新打开 */
int test_2 = 0;/* 测试，新的文件秒数服 */
int test_3 = 1;/* 测试，升级完成后，重新打开文件 */
struct timespec time1,time2;
time_t time3;
struct timeval time4;
/* 插、拔判断，不使用 */
int sockfd;
struct sockaddr_nl sa;
struct iovec data[2];
int fd1,fd2;
int num = 0;

/* ****************************************************************************************
 * 各种二维表
 * ***************************************************************************************/
/* 区分sensor种类 */
unsigned short ZwaveTable[10][2] = {{ZW_WATER_SENSOR, ZW_SENSOR_NOTHING},{ZW_MULTI_SENSOR, 2},{ZW_SMOKE_SENSOR, ZW_SENSOR_NOTHING},
		{ZW_DOOR_LOCK_SENSOR,0},{ZW_LED_BULB_SENSOR,ZW_SENSOR_NOTHING},{ZW_PANIC_BUTTON_CONTROLLER,1},{0xFF,ZW_SENSOR_NOTHING},{0x0080,1},
		{0xFF,ZW_SENSOR_NOTHING},{0xFF,ZW_SENSOR_NOTHING}};

void ZW_send_command_to_controller(unsigned char serial_cmd, unsigned char serial_cmd_mode, unsigned char flag, unsigned char node_ID,
		unsigned char zwaveCmdClass, unsigned char zwaveCmd, unsigned char func_ID);
int ZW_write(unsigned char *tx_buf,int length, int node_ID, int func_ID);
void ZW_process_data_from_controller(unsigned char * data);
void ZW_closeDongle();
int ZW_delete_node(unsigned char nodeid);
void ZW_send_to_Child(int cmd, unsigned char state, unsigned char nodeID, unsigned char sensorKind);

/**

     @brief test

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_test()
{
#if 0
	unsigned char kn[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
	unsigned char in_ke[16] = {};
	unsigned char out_ke[16];
	memset(in1, );
	AES_set_encrypt_key(zw_Ka, 8*sizeof(zw_Ka), &zw_key_ka);


	printf("sx:aes-ke!!!!!!!!!!!!!!!!!!!!\n");
	memset(plaintext_ka, 0, 48);

	/* 使用Ke加密，有用数据 */
	/* zw_IV保证不变 */
	memcpy(zw_IV_tem, zw_IV, 16);
	AES_set_encrypt_key(zw_Ke, 8*sizeof(zw_Ke), &zw_key_ke);
	AES_ofb128_encrypt(plaintext_ke, ciphertext_ke, 19, &zw_key_ke, zw_IV_tem, &zw_num);
	zw_num = 0;

	/* 使用Ka加密，生成AE
	 * 比较！ */
	printf("sx:aes-ka!!!!!!!!!!!!!!!!!!!!\n");
	memcpy(plaintext_ka, zw_IV, 16);
	plaintext_ka[16] = 0x81;
	plaintext_ka[17] = 0x01;
	plaintext_ka[18] = SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4];
	plaintext_ka[19] = 0x13;
	memcpy(plaintext_ka + 20, ciphertext_ke, 19);
	memset(zw_IV_tem, 0, 16);/* 文档上这么写？？？ */
	AES_set_encrypt_key(zw_Ka, 8*sizeof(zw_Ka), &zw_key_ka);
	AES_cbc_encrypt(plaintext_ka, ciphertext_ka, 48, &zw_key_ka, zw_IV_tem, AES_ENCRYPT);

	ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
			COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 2);

#endif
	return -1;
}

/**

     @brief 分析解密后的数据

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_security_data_analysis(int length)
{
	if(zw_text_out[1] == COMMAND_CLASS_ALARM)
	{
		if(zw_text_out[2] == ALARM_REPORT)
		{
			if(zw_text_out[3] == 0x19)
			{
				printf("@@@@ APPS open the door @@@@\n");
				ZW_send_to_Child(ZW_YALE_DOOR_LOCK, 0, 32, 4);/* *, state, nodeID, sensor_kind */
			}else if(zw_text_out[3] == 0x18)
			{
				printf("@@@@ APPS close the door @@@@\n");
				ZW_send_to_Child(ZW_YALE_DOOR_LOCK, 0, 32, 4);
			}else if(zw_text_out[3] == 0x13)
			{
				if(zw_text_out[4] == 0x00)
				{
					printf("@@@@ master open the door @@@@\n");
				}
				else
				{
					printf("@@@@ user %d open the door @@@@\n",zw_text_out[4]);
				}
			}else if(zw_text_out[3] == 0x16)
			{
				printf("@@@@ key or inside open the door @@@@\n");
			}else if(zw_text_out[3] == 0x15)
			{
				if(zw_text_out[4] == 0x01)
				{
					printf("@@@@  key or inside close the door @@@@\n");
				}else if(zw_text_out[4] == 0x02)
				{
					printf("@@@@ touch close the door @@@@\n");
				}
			}else if(zw_text_out[3] == 0x12)
			{
				if(zw_text_out[4] == 0x00)
				{
					printf("@@@@ master close the door @@@@\n");
				}
				else
				{
					printf("@@@@ user %d close the door @@@@\n",zw_text_out[4]);
				}
			}else if(zw_text_out[3] == 0x1b)
			{
				printf("@@@@  re-lock close the door @@@@\n");
			}
			else
			{
				printf("new new!\n");
			}
		}
	}else if(zw_text_out[1] == COMMAND_CLASS_CONFIGURATION)
	{
		if(zw_text_out[2] == CONFIGURATION_REPORT)
		{
			printf("@@@@ set the parameter the door @@@@\n");
			/* master 设置门锁 会主动上报
			 * APPS 设置会主动上报马？ */
		}
	}else if(zw_text_out[1] == COMMAND_CLASS_DOOR_LOCK)
	{
		if(zw_text_out[2] == DOOR_LOCK_OPERATION_REPORT)
		{
			printf("@@@@ get door lock state @@@@\n");
			printf("sx:0-close;2-open-----%d!\n",zw_text_out[5]);
			if(zw_text_out[5] == 0)
			{
				/* close */
				ZW_send_to_Child(ZW_YALE_DOOR_BACK_STATE, 2, 32, 4);/* *, state, nodeID, sensor_kind */
			}
			else
			{
				/* open */
				ZW_send_to_Child(ZW_YALE_DOOR_BACK_STATE, 1, 32, 4);/* *, state, nodeID, sensor_kind */
			}
		}

	}
}

/**

     @brief ofb加密解密过程

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_fob_encryption(unsigned long length, unsigned char *key)
{
	//printf("sx:aes-ke!!!!!!!!!!!!!!!!!!!!\n");
	unsigned char zw_ke[16];
	memcpy(zw_ke, key, 16);
	/* 使用Ke加密，有用数据 */
	/* zw_IV保证不变 */
	memcpy(zw_IV_tem, zw_IV, 16);
	AES_set_encrypt_key(zw_ke, 8*sizeof(zw_ke), &zw_key_ke);
	AES_ofb128_encrypt(zw_text_in, zw_text_out, length, &zw_key_ke, zw_IV_tem, &zw_num);
	zw_num = 0;
}

/**

     @brief cbc加密解密过程

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_cbc_encryption(int length, unsigned char *key)
{
	//printf("sx:aes-ka!!!!!!!!!!!!!!!!!!!!\n");
	unsigned char zw_ka[16];
	memcpy(zw_ka, key, 16);
	memcpy(plaintext_ka, zw_IV, 16);
	plaintext_ka[16] = 0x81;
	plaintext_ka[17] = 0x01;/* source nodeID */
	plaintext_ka[18] = SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4];//!!
	plaintext_ka[19] = length;
	memcpy(plaintext_ka + 20, zw_text_out, length);
	memset(zw_IV_tem, 0, 16);/* 文档上这么写？？？ */
	AES_set_encrypt_key(zw_ka, 8*sizeof(zw_ka), &zw_key_ka);
	AES_cbc_encrypt(plaintext_ka, ciphertext_ka, (20 + length), &zw_key_ka, zw_IV_tem, AES_ENCRYPT);
	memcpy(zw_AE, ciphertext_ka + (20 + length)/16*16, 8);
}

/**

     @brief 加密解密数据选择

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_fob_encryption_processing(unsigned char nodeID)
{
	/* note!!
	 * 这里的nodeID仅仅适用于case3.4 */
	switch(zw_ofb_flag)
	{
	/* ***************************
	 * 加密Kn
	 *  *************************/
	case 1:
		memset(zw_text_in, 0, 48);
		zw_text_in[0] = 0x00;
		zw_text_in[1] = 0x98;
		zw_text_in[2] = 0x06;
		memset(zw_text_in + 3, 1, 16);
		/* 进行加密 */
		ZW_fob_encryption(19, zw_Ke);
		/* 验证信息加密！ */
		ZW_cbc_encryption(19, zw_Ka);
		/* 发送加密数据 */
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 19, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 3);
		break;

	/* ***********************
	 * association
	 * 新的ke and ka
	 * **********************/
	case 2:
		//printf("SX:KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK\n");
		memset(zw_text_in, 0, 48);
		zw_text_in[0] = 0x00;
		zw_text_in[1] = 0x85;
		zw_text_in[2] = 0x01;
		zw_text_in[3] = 0x01;
		zw_text_in[4] = 0x01;
		/* 进行加密 */
		ZW_fob_encryption(5, zw_Ke_new);
		/* 验证信息加密！ */
		ZW_cbc_encryption(5, zw_Ka_new);
		/* 发送加密数据 */
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 5, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 10);
		break;
	/* ***********************
	 * APP open
	 * 新的ke and ka
	 * **********************/
	case 3:
		printf("SX:open door!!!\n");
		memset(zw_text_in, 0, 48);
		zw_text_in[0] = 0x00;
		zw_text_in[1] = 0x62;
		zw_text_in[2] = 0x01;
		zw_text_in[3] = 0x00;
		/* 进行加密 */
		ZW_fob_encryption(4, zw_Ke_new);
		/* 验证信息加密！ */
		ZW_cbc_encryption(4, zw_Ka_new);
		/* 发送加密数据 */
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 4, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 20);
		break;
	/* ***********************
	 * APP close
	 * 新的ke and ka
	 * **********************/
	case 4:
		printf("SX:close door!!!\n");
		memset(zw_text_in, 0, 48);
		zw_text_in[0] = 0x00;
		zw_text_in[1] = 0x62;
		zw_text_in[2] = 0x01;
		zw_text_in[3] = 0xFF;
		/* 进行加密 */
		ZW_fob_encryption(4, zw_Ke_new);
		/* 验证信息加密！ */
		ZW_cbc_encryption(4, zw_Ka_new);
		/* 发送加密数据 */
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 4, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 30);
		break;
	/* ***********************
	 * APP set --- relock open
	 * 新的ke and ka
	 * **********************/
	case 5:
		printf("SX:set re-lock!!!\n");
		memset(zw_text_in, 0, 48);
		zw_text_in[0] = 0x00;
		zw_text_in[1] = COMMAND_CLASS_CONFIGURATION;/* CC_CONFIGURATION*/
		zw_text_in[2] = CONFIGURATION_SET;
		zw_text_in[3] = 0x02;/* parameter num */
		zw_text_in[4] = 0x01;/* size */
		zw_text_in[5] = 0xFF;/* 0x00 -- disable;0xFF -- enable */

		/* 进行加密 */
		ZW_fob_encryption(6, zw_Ke_new);
		/* 验证信息加密！ */
		ZW_cbc_encryption(6, zw_Ka_new);
		/* 发送加密数据 */
		/* warming:serial_cmd_mode is the num encrypted text */
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 6, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 30);
		break;

		/* ***********************
		 * APP set --- door mode : 01 - all user code diable but the master
		 * 新的ke and ka
		 * **********************/
		case 6:
			printf("SX:set door mode 1!!!\n");
			memset(zw_text_in, 0, 48);
			zw_text_in[0] = 0x00;
			zw_text_in[1] = COMMAND_CLASS_CONFIGURATION;/* CC_CONFIGURATION*/
			zw_text_in[2] = CONFIGURATION_SET;
			zw_text_in[3] = 0x08;/* parameter num */
			zw_text_in[4] = 0x01;/* size */
			zw_text_in[5] = 0x01;/* 0x00 -- disable;0xFF -- enable */
			/* 进行加密 */
			ZW_fob_encryption(6, zw_Ke_new);
			/* 验证信息加密！ */
			ZW_cbc_encryption(6, zw_Ka_new);
			/* 发送加密数据 */
			ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 6, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 30);
			break;
		/* ***********************
		 * APP set --- door mode : 02 - all user code diable and APPS can not open the door
		 * 新的ke and ka
		 * **********************/
		case 7:
			printf("SX:set door mode 2!!!\n");
			memset(zw_text_in, 0, 48);
			zw_text_in[0] = 0x00;
			zw_text_in[1] = COMMAND_CLASS_CONFIGURATION;/* CC_CONFIGURATION*/
			zw_text_in[2] = CONFIGURATION_SET;
			zw_text_in[3] = 0x08;/* parameter num */
			zw_text_in[4] = 0x01;/* size */
			zw_text_in[5] = 0x02;/* 0x00 -- disable;0xFF -- enable */
			/* 进行加密 */
			ZW_fob_encryption(6, zw_Ke_new);
			/* 验证信息加密！ */
			ZW_cbc_encryption(6, zw_Ka_new);
			/* 发送加密数据 */
			ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 6, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 30);
			break;
		case 8:
			printf("SX:set door mode 0!!!\n");
			memset(zw_text_in, 0, 48);
			zw_text_in[0] = 0x00;
			zw_text_in[1] = COMMAND_CLASS_CONFIGURATION;/* CC_CONFIGURATION*/
			zw_text_in[2] = CONFIGURATION_SET;
			zw_text_in[3] = 0x08;/* parameter num */
			zw_text_in[4] = 0x01;/* size */
			zw_text_in[5] = 0x00;/* 0x00 -- disable;0xFF -- enable */
			/* 进行加密 */
			ZW_fob_encryption(6, zw_Ke_new);
			/* 验证信息加密！ */
			ZW_cbc_encryption(6, zw_Ka_new);
			/* 发送加密数据 */
			ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 6, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 30);
			break;

	/* get door state */
	case 9:
		printf("SX:get door state!!!\n");
		memset(zw_text_in, 0, 48);
		zw_text_in[0] = 0x00;
		zw_text_in[1] = 0x62;
		zw_text_in[2] = 0x02;
		/* 进行加密 */
		ZW_fob_encryption(3, zw_Ke_new);
		/* 验证信息加密！ */
		ZW_cbc_encryption(3, zw_Ka_new);
		/* 发送加密数据 */
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 3, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_SECURITY, SECURITY_MESSAGE_ENCAPSULATION, 20);
		break;

	default:
		printf("sx:nothing to encryption!\n");
		break;
	}
}

/**

     @brief 判断dongle的插入或者拔出

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_detect_port()
{
	fd_set fset;
	struct timeval tv;
	char * str1 = NULL;
	char * str2 = NULL;
	char * str3 = NULL;
	int loop_state = 0;


	if(zw_start_step == STEP_ERROR)
	{
		FD_ZERO(&fset);
		FD_SET(sockfd, &fset);
		tv.tv_sec  = 1;
		tv.tv_usec = 500000;
	}
	else
	{
		FD_ZERO(&fset);
		FD_SET(sockfd, &fset);
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	}

	while(1)
	{
		switch(select(sockfd + 1, &fset, NULL, NULL, &tv))
		{
		    case 0:
	    		return 0;
		    case -1:
		    	return -1;
		    default:
		 	   if(FD_ISSET(sockfd, &fset))
		 	   {
		 		   /* (1) 接收数据 */
		 		   readv(sockfd, data, 2);
		 		   /* (2) 准备好要分析的数据 */
		 		   str1 = data[0].iov_base;
		 		   //printf("sxsx:%s\n",str1);
		 		   //printf("sxsx:%d!\n",len);
		 		   /* (3) 开始分析数据 */
		 		   if((strncmp(str1, "add", 3) == 0) && (zw_start_step == STEP_ERROR))
		 		   {
		 			   /* 增加 */
		 			   /* 当一个设备插入后，会有很多信息上发，设标志位，局部循环 */
		 			   loop_state = 1;/* 开启局部循环 */
		 			   printf("SX:something in!!!!\n");
		 			   str2 = strstr(str1, "ttyUSB");
		 			   //printf("sx:Is ttyusb %s?\n",str2);
		 			   if(str2)
		 			   {
		 				   /* there is a ttyusb!! */
		 				   /*
		 				   if(num == 0)
		 				   {
			 					fd1 = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_NDELAY);
			 					if(fd1 > 0)
			 					{
			 						num++;
			 						printf("SX:fd1 open right!\n");
			 					}
			 					else
			 					{
			 						printf("SX:fd1 open failed!\n");
			 					}
		 				   }
		 				   else
		 				   {
		 					   num = 0;
		 					   fd2 = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_NDELAY);
			 					if(fd2 > 0)
			 					{
			 						num++;
			 						printf("SX:fd2 open right!\n");
			 					}
			 					else
			 					{
			 						printf("SX:fd2 open failed!\n");
			 					}
		 				   }
		 				   */

			 			   str3 = strstr(str2, "/ttyUSB");
			 			   if(str3)
			 			   {
			 				   printf("sxsx:the address is %s!\n",str3 + 1);
			 				   /* 这是ASCII码的0、1、2、3、4！！！！ */
			 				   serial_num = *(str3 + 7);
					 		   printf("sxsx:the port name is %d!\n",serial_num);
					 		   zw_start_step = STEP_OPEN_CONTROLLER;
				 			   //memcpy(zw_port_name, str3 + 1, 7);
					 		   //printf("sxsx:the port name is %s!\n",zw_port_name);
			 			   }
			 			   else
			 			   {
			 				   /* 无效信息，丢弃即可 */
			 				   printf("SX:str-3!\n");
			 			   }//str3
		 			   }
		 			   else
		 			   {
		 				   /* 无效信息，丢弃即可 */
		 				   printf("SX:str-2!\n");
		 			   }//str2
		 		   }else if((strncmp(str1, "remove", 6) == 0) && (zw_start_step != STEP_ERROR))
		 		   {
		 			   /* 删除 */
		 			   /* 当一个设备拔出后，会有很多信息上发，设标志位，局部循环 */
		 			   loop_state = 1;/* 开启局部循环 */
		 			   printf("SX:something out!!!!\n");
			 		   printf("sxsx:%s\n",str1);
		 			   str2 = strstr(str1, "ttyUSB");
		 			   if(str2)
		 			   {
		 				   /* there is a ttyusb!! */
			 			   str3 = strstr(str2, "/ttyUSB");
			 			   if(str3)
			 			   {
			 				   printf("sxsx:the address is %s!\n",str3 + 1);
				 			   //memcpy(zw_port_name, str3 + 1, 7);
					 		   //printf("sxsx:the port name is %s!\n",zw_port_name);
			 				   if(*(str3 + 7) == serial_num)
			 				   {
			 					   printf("SX:the dongle is out,now!\n");
			 					   /* 是这个dongle被拔出了 */
			 					   ZW_closeDongle();
			 				   }
			 				   else
			 				   {
			 					   /* 拔出的不是应用的dongle！ */
			 					   printf("SX:the dongle is not out!\n");
			 				   }
			 			   }
			 			   else
			 			   {
			 				   /* 无效信息，丢弃即可 */
			 				   printf("SX:str-3!\n");
			 			   }//str3
		 			   }
		 			   else
		 			   {
		 				   //失败?
		 				   printf("SX:str-2!\n");
		 			   }//str2
		 		   }
		 		   else
		 		   {
		 			   printf("SX:no hope kernel uploard!!\n");
		 		   }//add/remove
		 	   }//if(FD_ISSET(sockfd, &fset))
	 		   break;
		}//switch

		/*
		 * 当dongle拔出后，要经过很多条消息后才会遇到我们需要的消息，这样才会退出；
		 * 为了防止，dongle拔出后，IPU没有马上反应出来，后续对dongle继续操作！
		 * */
		if(loop_state == 1)
		{
			FD_ZERO(&fset);
			FD_SET(sockfd, &fset);
			tv.tv_sec  = 0;
			/* 这个时间对插入不行，对拔出可以！可以！ */
			tv.tv_usec = 50000;
			continue;
		}
	}//while
	return 0;
}

/**

     @brief 获取sensor的电量

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_get_sensor_battery()
{
	if((zw_controller_state == DONGLE_STATE_OK)&&(zw_battery.num != 0))
	{
		if(zw_battery.flag == ZW_BATTERY_FREE)
		{
			zw_battery.flag = ZW_BATTERY_BUSY;
			/* 发送该节点的电量获取命令 */
    		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, zw_battery.nodeID[zw_battery.num - 1],
    				COMMAND_CLASS_BATTERY, BATTERY_GET, ZW_GET_SENSOR_BATTERY);
		}
	}
}

/**

     @brief 辅助升级控制器，转化成ASCII码

     @author sunxun

     @remark 2015-7-1

     @note

*/
unsigned char hextoascii(unsigned char a,unsigned char b)
{
    unsigned char value;
        if(a<='9'&&a>='0'){
            a = a-48;
        }else if(a<='f'&&a>='a'){
            a = a-96+9;
        }else{
            a = a-64+9;
        }


        if(b<='9'&&b>='0'){
            b = b-48;
        }else if(b<='f'&&b>='a'){
            b = b-96+9;
        }else{
            b = b-64+9;
        }

    value = (a<<4)+b;
    return value;
}

/**

     @brief 辅助升级控制器，写入数据

     @author sunxun

     @remark 2015-7-1

     @note

*/
int update_write_to_ZW()
{
	int i;
	int ret;
    fd_set rfds;
    struct timeval tv;

    if(double80 == 0)
    {
        ret = write(zw_fd, txbuff, 4);
        if(ret == -1)
        {
            printf(" Write device error!\n");
        }
    }else
    {
        ret = write(zw_fd, txbuff, 8);
        if(ret == -1)
        {
            printf(" Write device error!\n");
        }
    }

    if(txbuff[0] == 0xFF)
    {
    	printf("jie shu le\n");
    	for(i=5 ; i>0 ; i--)
    	{
    		printf("%d\n",i);
    		sleep(1);
    	}
    	return 0;
    }

    FD_ZERO(&rfds);
    FD_SET(zw_fd, &rfds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    ret = select(zw_fd + 1, &rfds, NULL, NULL, &tv);
    if(ret == -1)
    {
        perror("select()");
    }
    else if(ret)
    {
    	if(double80 == 0)
    	{
            ret = read(zw_fd, rxbuff, 4);
            if(ret == -1)
            {
                printf(" read device error!\n");
            }
    	}else
    	{
            ret = read(zw_fd, rxbuff, 8);
            if(ret == -1)
            {
                printf(" read device error!\n");
            }
            tcflush(zw_fd, TCIOFLUSH);
            double80 = 0;
    	}
/*
         if(dayin == 2)
         {
             printf("%x ",rxbuff[0]);
             printf("%x ",rxbuff[1]);
             printf("%x ",rxbuff[2]);
             printf("%x\n",rxbuff[3]);
             dayin = 0;
         }
*/
    }
    else
    {
    	/* 需要重新烧写 */
    	printf("out of time!!\n");
    }
return 0;
}

/**

     @brief ZW controller升级镜像文件

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_controller_upgrade()
{
    int zw_update_state = ZW_UPDATE_OPEN;
    int zw_update_read_state = ZW_UPDATE_READ_NORMAL;//读取hex文件的状态

    unsigned char clean_num = 0;
    int clean_step = 0;
    int ceshi_step = 0;

//CRC
    unsigned char crc[4] = {0x10,0x98,0x58,0x17};

//read the HEX file!!
    FILE *fp = NULL;
    unsigned char *buf;
    unsigned char buff[100];
    int length = 0;
    int i;
    int l = 0;
    int index = 0;
    int write_step = 0;
    int write_last_step = 0;
    int addr = 0;
    unsigned char datakind = 0;
    char temp[15];
    int tempnum = 0;

    long int hex_h,hex_l;

    unsigned char hex_addr_curr[2];
    long int hex_catch_head = 0;
    long int hex_catch_tail = 0;
    long int hex_curr = 0;
    int catch_num = 0;//从零开始
    int addr_offset = 0;//2KB中的偏移量
    int flash_page = 0;
    int catch_state = 0;//抓捕器中是否有内容
    int zw_update_write_state = 1;
    int flash_addr = 0;
    int flash_next_page = 0;
    int num2 = 0;
    int num3 = 0;
    int num4 = 0;

    buf = malloc(sizeof(char)*2*1024);
    if(buf == NULL)
    {
    	printf("malloc wrong!!\n");
    	return -1;
    }

    fp = fopen("/usr/share/iSmart/zw.hex","r");
    if(fp == NULL)
    {
    	printf("open zw.hex file error!\n");
    	return -1;
    }

    while(1)
    {
    	if(zw_update_state == ZW_UPDATE_OPEN)
    	{
        	txbuff[0] = 0xAC;
        	txbuff[1] = 0x53;
        	txbuff[2] = 0xAA;
        	txbuff[3] = 0x55;
        	dayin = 1;
        	update_write_to_ZW();
        	zw_update_state = ZW_UPDATE_ERASE;
    	}else if(zw_update_state == ZW_UPDATE_ERASE)
    	{
       		if(clean_num < 64)
        	{
        		if(clean_step == 0)
       			{
       	        	txbuff[0] = 0x0B;
       	        	txbuff[1] = clean_num;//
       	        	txbuff[2] = 0xFF;
       	        	txbuff[3] = 0xFF;
       	        	clean_step = 1;
       			}else
       			{
                	txbuff[0] = 0x7F;
       	        	txbuff[1] = 0xFE;
       	        	txbuff[2] = 0x00;
       	        	txbuff[3] = 0x00;
       	        	clean_num++;
       	        	clean_step = 0;
       			}
            	update_write_to_ZW();
       		}
        	else
        	{
       			clean_num = 0;
            	zw_update_state = ZW_UPDATE_READ;
       			printf("Finishing clean flash!\n");
       		}
    	}else if(zw_update_state == ZW_UPDATE_READ)//读数据
    	{
    		catch_state = 0;//清空抓捕器
	   		memset(buf,0xff,2048);
    	    hex_catch_head = catch_num*2048;
    	    hex_catch_tail = catch_num*2048 + 2047;

    	    //判断上次读取的那一行数据是否有剩余！
    		if(tempnum != 0)
    		{
           	    for( i = 0; i < tempnum; i++)
           	    {
           	    	buf[i] = temp[i];
           	    }
           	    catch_state = 1;
    	   		tempnum = 0;
    		}

    	    while(1)
    	    {
                if(zw_update_read_state == ZW_UPDATE_READ_NORMAL)
    	    	{
        	    	fscanf(fp,"%s",buff);
        	        //printf("the result is \n%s\n",buff);
        	    	datakind = hextoascii(buff[7],buff[8]);
    	    		length = (int)hextoascii(buff[1],buff[2]);
      	    	    hex_addr_curr[0] = hextoascii(buff[3],buff[4]);
      	    	    hex_addr_curr[1] = hextoascii(buff[5],buff[6]);
      	    	    hex_h = (long)hex_addr_curr[0];
      	    	    hex_l = (long)hex_addr_curr[1];
    	    	   	hex_curr = hex_h*256 + hex_l;
    	    	   	//printf("the hex_curr is %d\n",hex_curr);

    	    	   	zw_update_read_state = ZW_UPDATE_READ_ANALYSE;
    	    	}else if(zw_update_read_state == ZW_UPDATE_READ_ANALYSE)
    	    	{
    	    	   	if(datakind == 0)//正常数据
    	    	   	{
    		    	   	if(hex_curr > hex_catch_tail)
    		    	   	{
        	    	   		if(catch_state == 1)
        	    	   		{
        	    	    		zw_update_state = ZW_UPDATE_WRITE;
            	    	   		zw_update_read_state = ZW_UPDATE_READ_ANALYSE;

        	    	    		zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;//budao

        	    	    		num2 = addr_offset;
   	        	         	 while(1)
   	        	         	 {
   	        	         	 	 if(buf[num2-1] == 0xFF)
   	        	         		 {
   	        	         			 num2 = num2 -1;
   	        	         			 if(num2 == 0)
   	        	         			 {
   	        	    	    	    		zw_update_state = ZW_UPDATE_READ;
   	        	        	    	   		zw_update_read_state = ZW_UPDATE_READ_ANALYSE;
   	        	         			     break;
   	        	         			 }
   	        	         			 continue;
   	        	         		 }
   	        	         		 else
   	        	         		 {
   	        	         			 break;
   	        	         		 }
   	        	         	 }


        	    	    		num4 = num2;
        	            	    flash_addr = catch_num + flash_next_page;
        	            	    catch_num++;
        	    	   		}
        	    	   		else
        	    	   		{
        	    	    		zw_update_state = ZW_UPDATE_READ;
            	    	   		zw_update_read_state = ZW_UPDATE_READ_ANALYSE;
        	            	    catch_num++;
        	    	   		}
    		    	   		break;
    		    	   	}
    		    	   	else
    		    	   	{
    		    	   		catch_state = 1;//抓捕器中有内容
    		    	   		addr_offset = hex_curr - hex_catch_head;
    	    	    		for( i = 0; i < length; i++)
    	    	            {
    	    	                 buf[addr_offset + i] = hextoascii(buff[i*2+9],buff[i*2+10]);
    	    	            }
    	    	    		addr_offset = addr_offset + length;

    	    	    		zw_update_read_state = ZW_UPDATE_READ_NORMAL;

    	    	    		if( addr_offset >= 2048)
    	    	    		{
    	    	    			//temp_addr = hex_curr;
    		                	 tempnum = addr_offset - 2048;
    		               	     for( i = 0; i < tempnum; i++)
    		               	     {
    		               	    	  temp[i] = buf[2048 + i];
    		               	     }
    	    	    	    	 zw_update_state = ZW_UPDATE_WRITE;
    	        	    	   	 zw_update_read_state = ZW_UPDATE_READ_NORMAL;

    	        	    	   	 //异常一：抓捕器抓取的2KB数据的最后n位是0xFF
    	    	    	    	 num2 = 2048;

    	        	         	 while(1)
    	        	         	 {
    	        	         	 	 if(buf[num2-1] == 0xFF)
    	        	         		 {
    	        	         			 num2 = num2 -1;
    	        	         			 if(num2 == 0)
    	        	         			 {
    	        	    	    	    		zw_update_state = ZW_UPDATE_READ;
    	        	        	    	   		zw_update_read_state = ZW_UPDATE_READ_NORMAL;
    	        	         			     break;
    	        	         			 }
    	        	         			 continue;
    	        	         		 }
    	        	         		 else
    	        	         		 {
    	        	         			 zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;
    	        	         			 break;
    	        	         		 }
    	        	         	 }

         	    	    		 num4 = num2;

    	    	    	    	 addr_offset = 0;
    	    	            	 flash_addr = catch_num + flash_next_page;
    	    	            	 catch_num++;

    		               	     break;
    	    	    		}
    	    	    		continue;
    		    	   	}

    	    	   	}else if(datakind == 1)//hex文件结束标志，读取完成
    	    	   	{
    	    	   		if(catch_state == 1)
    	    	   		{
    	    	    		zw_update_state = ZW_UPDATE_WRITE;
        	    	   		zw_update_read_state = ZW_UPDATE_READ_END;
    	    	    		zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;//budao

    	    	    		num2 = addr_offset;
	        	         	 while(1)
	        	         	 {
	        	         	 	 if(buf[num2-1] == 0xFF)
	        	         		 {
	        	         			 num2 = num2 -1;
	        	         			 if(num2 == 0)
	        	         			 {
	        	    	    	    		zw_update_state = ZW_UPDATE_READ;
	        	        	    	   		zw_update_read_state = ZW_UPDATE_READ_END;
	        	         			     break;
	        	         			 }
	        	         			 continue;
	        	         		 }
	        	         		 else
	        	         		 {
	        	         			 break;
	        	         		 }
	        	         	 }

    	    	    		num4 = num2;
    	            	    flash_addr = catch_num+flash_next_page;
    	    	   		}
    	    	   		else
    	    	   		{
    	    	    		zw_update_state = ZW_UPDATE_READ;
        	    	   		zw_update_read_state = ZW_UPDATE_READ_END;
    	    	   		}
    	    	   		break;

    	    	   	}else if(datakind == 2)//读取下一个64KB
    	    	   	{
    	    	   		if(catch_state == 1)
    	    	   		{
    	    	    		zw_update_state = ZW_UPDATE_WRITE;
        	    	   		zw_update_read_state = ZW_UPDATE_READ_NORMAL;
    	    	    		zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;//budao
    	    	    		num2 = addr_offset;
	        	         	 while(1)
	        	         	 {
	        	         	 	 if(buf[num2-1] == 0xFF)
	        	         		 {
	        	         			 num2 = num2 -1;
	        	         			 if(num2 == 0)
	        	         			 {
	        	    	    	    		zw_update_state = ZW_UPDATE_READ;
	        	        	    	   		zw_update_read_state = ZW_UPDATE_READ_NORMAL;
	        	         			     break;
	        	         			 }
	        	         			 continue;
	        	         		 }
	        	         		 else
	        	         		 {
	        	         			 break;
	        	         		 }
	        	         	 }

    	    	    		num4 = num2;
    	            	    flash_addr = catch_num+flash_next_page;

        	    	   		flash_page = hextoascii(buff[11],buff[12]);
       	            	    flash_next_page = 0x20;
       	    	   			catch_num = 0;
    	    	   		}
    	    	   		else
    	    	   		{
    	    	    		zw_update_state = ZW_UPDATE_READ;
        	    	   		zw_update_read_state = ZW_UPDATE_READ_NORMAL;

        	    	   		flash_next_page = 0x20;
        	    	   		catch_num = 0;
    	    	   		}

    	    	   		break;
    	    	   	}
    	    	}else if(zw_update_read_state == ZW_UPDATE_READ_END)
    	    	{
					saveDataToLogStr("ZWAVEUPDATE","finishing read!",strlen("finishing read!"));
    	    		//printf("finishing read!!\n");
    	    		zw_update_state = ZW_UPDATE_WRITE;
    	    		zw_update_write_state = ZW_UPDATE_WRITE_CRC;//CRC
    	    		break;
    	    	}
    	    }
    	}else if(zw_update_state == ZW_UPDATE_WRITE)
    	{
    		if(zw_update_write_state == ZW_UPDATE_WRITE_NORMAL)
    		{
    			if(num2 > 511)//512yekeyi
    			{
        			if((buf[511] == 0xFF)&&(l == 0))
        			{
        				l = 0;
        				index = 0;

        				num3 = 511;//个数
        				while((num3 > 0)&&(buf[num3 - 1] == 0xFF))
        				{
        					num3--;
        				}
    					if(num3 == 0)
    					{
    						l = 2;
    						index = 512;
    					}
    					else
    					{
            				addr = num3;
            				zw_update_write_state = ZW_UPDATE_WRITE_NOT_512B;
    					}
    					num2 = num2 - 512;
        				continue;
        			}else if((buf[1023] == 0xFF)&&(l == 2))
        			{
        				l = 2;
        				index = 512;

        				num3 = 511;//个数
        				while((num3 > 0)&&(buf[num3 - 1] == 0xFF))
        				{
        					num3--;
        				}
    					if(num3 == 0)
    					{
    						l = 4;
    						index = 1024;
    					}
    					else
    					{
            				addr = num3;
            				zw_update_write_state = ZW_UPDATE_WRITE_NOT_512B;
    					}
    					num2 = num2 - 512;
        				continue;
        			}else if((buf[1535] == 0xFF)&&(l == 4))
        			{
        				l = 4;
        				index = 1024;

        				num3 = 511;//个数
        				while((num3 > 0)&&(buf[num3 - 1] == 0xFF))
        				{
        					num3--;
        				}
    					if(num3 == 0)
    					{
    						l = 6;
    						index = 1536;
    					}
    					else
    					{
            				addr = num3;
            				zw_update_write_state = ZW_UPDATE_WRITE_NOT_512B;
    					}
    					num2 = num2 - 512;
    					num4 = num2;
        				continue;
        			}

    				if(write_step == 0)
    				{
	    	        	txbuff[0] = 0x04;
	    	        	txbuff[1] = l;
	    	        	txbuff[2] = 0x00;
	    	        	txbuff[3] = buf[index++];
	    	        	write_step++;
	    			}else if((write_step > 0)&&(write_step < 86))//683/342
	    			{
	    	        	txbuff[0] = 0x80;
	    	        	txbuff[1] = buf[index++];
	    	        	txbuff[2] = buf[index++];
	    	        	txbuff[3] = buf[index++];
	    	        	txbuff[4] = 0x80;
	    	        	txbuff[5] = buf[index++];
	    	        	txbuff[6] = buf[index++];
	    	        	txbuff[7] = buf[index++];
	    	        	double80 = 1;
	    	        	write_step++;
	    	        	//usleep(2);
	    			}else if(write_step == 86)//683/342
	    			{
	    				txbuff[0] = 0x20;
	    			   	txbuff[1] = flash_addr;
	    	        	txbuff[2] = 0xFF;
	    	        	txbuff[3] = 0xFF;
	    	        	write_step++;
	    				//usleep(20);
	    			}else if(write_step == 87)//684/343
	    			{
	    	        	txbuff[0] = 0x7F;
	    	        	txbuff[1] = 0xFE;
	    	        	txbuff[2] = 0x00;
	    	        	txbuff[3] = 0x00;
	    	        	write_step++;
	    	        	dayin = 1;
	    			}else if(write_step == 88)//683/342
	    			{
	    	        	txbuff[0] = 0x04;
	    	        	txbuff[1] = l+1;
	    	        	txbuff[2] = 0xFF;
	    	        	txbuff[3] = buf[index++];
	    	        	write_step++;
	    			}else if(write_step == 89)//683/342
	    			{
	    	        	txbuff[0] = 0x20;
	    	        	txbuff[1] = flash_addr;
	    	        	txbuff[2] = 0xFF;
	    	        	txbuff[3] = 0xFF;
	    	        	write_step++;
	    				//usleep(20);
	    			}else if(write_step == 90)
	    			{
	    	        	txbuff[0] = 0x7F;
	    	        	txbuff[1] = 0xFE;
	    	        	txbuff[2] = 0x00;
	    	        	txbuff[3] = 0x00;
	    	        	if(l == 0)
	    	        	{
	    	        		l = 2;
	    	        	}else if(l == 2){
	    	        		l = 4;
	    	        	}else if(l == 4){
	    	        		l = 6;
	    	        	}else if(l == 6)
	    	        	{
            	        	printf("the 2KB_NUM is %d\n",flash_addr);
        	        		l = 0;
        	        		index = 0;
        	        		zw_update_state = ZW_UPDATE_READ;
	    	        	}
	    	        	write_step = 0;
	    	        	num2 = num2 - 512;
	    	        	num4 = num2;//num4防止写入的数据正好是512B的整数倍,同时，确定写入sram中的位置
	    	        	dayin = 1;
	    			}
    			}
    			else//极限 是 511
    			{
    				if(num4 == 0)
    				{
    					if(write_last_step == 0)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 1)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	        			zw_update_state = ZW_UPDATE_READ;
    	    	        	index = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = 0;
    					}
    				}
    				else
    				{
        				if(write_step == 0)
        				{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = buf[index++];
    	    	        	write_step++;
    	    				printf("the num2 is --- %d ----\n",num2);
    	    				addr = num2%256;
    	    	        	num2 = num2 -1;
    	    			}else if(write_step > 0)//683/342
    	    			{
    	    				if(num2 > 5)//=3yexing
    	    				{
    		    	        	txbuff[0] = 0x80;
    		    	        	txbuff[1] = buf[index++];
    		    	        	txbuff[2] = buf[index++];
    		    	        	txbuff[3] = buf[index++];
    		    	        	txbuff[4] = 0x80;
    		    	        	txbuff[5] = buf[index++];
    		    	        	txbuff[6] = buf[index++];
    		    	        	txbuff[7] = buf[index++];
    		    	        	double80 = 1;
    		    	        	//write_step++;
    		    	        	num2 = num2 -6;
        	    				printf("the num2 is --- %d ----\n",num2);
    		    	        	//usleep(2);
    	    				}else if(num2 == 5)
    	    				{
    	    					if(write_last_step == 0)
    	    					{
        		    	        	txbuff[0] = 0x80;
        		    	        	txbuff[1] = buf[index++];
        		    	        	txbuff[2] = buf[index++];
        		    	        	txbuff[3] = buf[index++];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 1)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 2)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    	     			}else if(write_last_step == 3)
    	    					{
    	    	    	        	txbuff[0] = 0x04;
    	    	    	        	txbuff[1] = l + num4/256;
    	    	    	        	txbuff[2] = addr-2;
    	    	    	        	txbuff[3] = buf[index++];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 4)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 5)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 6)
    	    					{
    	    	    	        	txbuff[0] = 0x04;
    	    	    	        	txbuff[1] = l + num4/256;
    	    	    	        	txbuff[2] = addr-1;
    	    	    	        	txbuff[3] = buf[index];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 7)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 8)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step = 0;
    	    	    	        	index = 0;
    	    	    	        	write_step = 0;
    	    	        			zw_update_state = ZW_UPDATE_READ;
    	    	    	        	dayin = 1;
    	    	    	        	l = 0;
    	    					}
    	    				}else if(num2 == 4)
    	    				{
    	    					if(write_last_step == 0)
    	    					{
        		    	        	txbuff[0] = 0x80;
        		    	        	txbuff[1] = buf[index++];
        		    	        	txbuff[2] = buf[index++];
        		    	        	txbuff[3] = buf[index++];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 1)
    	    				    {
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 2)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 3)
    	    					{
    	    	    	        	txbuff[0] = 0x04;
    	    	    	        	txbuff[1] = l + num4/256;
    	    	    	        	txbuff[2] = addr-1;
    	    	    	        	txbuff[3] = buf[index];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 4)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 5)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step = 0;
    	    	        			zw_update_state = ZW_UPDATE_READ;
    	    	    	        	index = 0;
    	    	    	        	write_step = 0;
    	    	    	        	//ceshi_step = 0;
    	    	    	        	//num2 = -1;
    	    	    	        	dayin = 1;
    	    	    	        	l = 0;
    	    					}
    	    				}else if(num2 == 3)
    	    				{
    	    					printf("the write_last_step is %d!\n",write_last_step);
    	    					if(write_last_step == 0)
    	    					{
        		    	        	txbuff[0] = 0x80;
        		    	        	txbuff[1] = buf[index++];
        		    	        	txbuff[2] = buf[index++];
        		    	        	txbuff[3] = buf[index++];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 1)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 2)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step = 0;
    	    	        			zw_update_state = ZW_UPDATE_READ;
    	    	    	        	index = 0;
    	    	    	        	write_step = 0;
    	    	    	        	//ceshi_step = 0;
    	    	    	        	//num2 = -1;
    	    	    	        	dayin = 1;
    	    	    	        	l = 0;
    	    					}
    	    				}else if(num2 == 2)
    	    				{
    	    					if(write_last_step == 0)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 1)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    	     			}else if(write_last_step == 2)
    	    					{
    	    	    	        	txbuff[0] = 0x04;
    	    	    	        	txbuff[1] = l;
    	    	    	        	txbuff[2] = addr-2;
    	    	    	        	txbuff[3] = buf[index++];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 3)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 4)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 5)
    	    					{
    	    	    	        	txbuff[0] = 0x04;
    	    	    	        	txbuff[1] = l;
    	    	    	        	txbuff[2] = addr-1;
    	    	    	        	txbuff[3] = buf[index];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 6)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 7)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step = 0;
    	    	    	        	index = 0;
    	    	    	        	write_step = 0;
    	    	        			zw_update_state = ZW_UPDATE_READ;
    	    	    	        	dayin = 1;
    	    	    	        	l = 0;
    	    					}
    	    				}else if(num2 == 1)
    	    				{
    	    					if(write_last_step == 0)
    	    				    {
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 1)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 2)
    	    					{
    	    	    	        	txbuff[0] = 0x04;
    	    	    	        	txbuff[1] = l + num4/256;
    	    	    	        	txbuff[2] = addr-1;
    	    	    	        	txbuff[3] = buf[index];
    	    	    	        	write_last_step++;
    	    	    	        	dayin = 1;
    	    					}else if(write_last_step == 3)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 4)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step = 0;
    	    	        			zw_update_state = ZW_UPDATE_READ;
    	    	    	        	index = 0;
    	    	    	        	write_step = 0;
    	    	    	        	//ceshi_step = 0;
    	    	    	        	//num2 = -1;
    	    	    	        	dayin = 1;
    	    	    	        	l = 0;
    	    					}
    	    				}else if(num2 == 0)
    	    				{
    	    					if(write_last_step == 0)
    	    					{
    	    	    	        	txbuff[0] = 0x20;
    	    	    	        	txbuff[1] = flash_addr;
    	    	    	        	txbuff[2] = 0xFF;
    	    	    	        	txbuff[3] = 0xFF;
    	    	    	        	write_last_step++;
    	    	    				//usleep(20);
    	    	    				dayin = 1;
    	    					}else if(write_last_step == 1)
    	    					{
    	    	    	        	txbuff[0] = 0x7F;
    	    	    	        	txbuff[1] = 0xFE;
    	    	    	        	txbuff[2] = 0x00;
    	    	    	        	txbuff[3] = 0x00;
    	    	    	        	write_last_step = 0;
    	    	        			zw_update_state = ZW_UPDATE_READ;
    	    	    	        	index = 0;
    	    	    	        	write_step = 0;
    	    	    	        	//ceshi_step = 0;
    	    	    	        	//num2 = -1;
    	    	    	        	dayin = 1;
    	    	    	        	l = 0;
    	    					}
    	    				}
    	    			}
        			}
    			}
    		}else if(zw_update_write_state == ZW_UPDATE_WRITE_CRC)
    		{
        		if(ceshi_step == 0)
        		{
    	        	txbuff[0] = 0x04;
    	        	txbuff[1] = 0x07;
    	        	txbuff[2] = 0xFC;
    	        	txbuff[3] = crc[0];
    	        	dayin = 1;
        			ceshi_step++;

    			}else if(ceshi_step == 1)
    			{
    	        	txbuff[0] = 0x80;
    	        	txbuff[1] = crc[1];
    	        	txbuff[2] = crc[2];
    	        	txbuff[3] = crc[3];
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 2)
    			{
    	        	txbuff[0] = 0x20;
    	        	txbuff[1] = 0x3F;
    	        	txbuff[2] = 0xFF;
    	        	txbuff[3] = 0xFF;
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 3)
    			{
    	        	txbuff[0] = 0x7F;
    	        	txbuff[1] = 0xFE;
    	        	txbuff[2] = 0x00;
    	        	txbuff[3] = 0x00;
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 4)
    			{
    	        	txbuff[0] = 0x7F;
    	        	txbuff[1] = 0xFE;
    	        	txbuff[2] = 0x00;
    	        	txbuff[3] = 0x00;
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 5)
    			{
    	        	txbuff[0] = 0x7F;
    	        	txbuff[1] = 0xFE;
    	        	txbuff[2] = 0x00;
    	        	txbuff[3] = 0x00;
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 6)
    			{
    	        	txbuff[0] = 0xC3;
    	        	txbuff[1] = 0x00;
    	        	txbuff[2] = 0x00;
    	        	txbuff[3] = 0x00;
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 7)
    			{
    	        	txbuff[0] = 0x7F;
    	        	txbuff[1] = 0xFE;
    	        	txbuff[2] = 0x00;
    	        	txbuff[3] = 0x00;
    	        	dayin = 1;
        			ceshi_step++;
    			}else if(ceshi_step == 8)
    			{
    	        	txbuff[0] = 0xFF;
    	        	txbuff[1] = 0xFF;
    	        	txbuff[2] = 0xFF;
    	        	txbuff[3] = 0xFF;
    	        	dayin = 1;
        			ceshi_step++;
    			}else
    			{
    				ceshi_step = 0;
    				zw_update_state = ZW_UPDATE_OVER;
    				//en_dongle_state = DONGLE_STATE_OK;
    			}
    		}else if(zw_update_write_state == ZW_UPDATE_WRITE_NOT_512B)
    		{
				if(write_step == 0)
				{
    	        	txbuff[0] = 0x04;
    	        	txbuff[1] = l;//
    	        	txbuff[2] = 0x00;
    	        	txbuff[3] = buf[index++];
    	        	write_step++;
    				printf("the num3 is --- %d ----\n",num3);
    	        	num3 = num3 -1;
    			}else if(write_step > 0)//683/342
    			{
    				if(num3 > 5)//=3yexing
    				{
	    	        	txbuff[0] = 0x80;
	    	        	txbuff[1] = buf[index++];
	    	        	txbuff[2] = buf[index++];
	    	        	txbuff[3] = buf[index++];
	    	        	txbuff[4] = 0x80;
	    	        	txbuff[5] = buf[index++];
	    	        	txbuff[6] = buf[index++];
	    	        	txbuff[7] = buf[index++];
	    	        	double80 = 1;
	    	        	//write_step++;
	    	        	num3 = num3 -6;
	    				printf("the num3 is --- %d ----\n",num3);
	    	        	//usleep(2);
    				}else if(num3 == 5)
    				{
    					if(write_last_step == 0)
    					{
		    	        	txbuff[0] = 0x80;
		    	        	txbuff[1] = buf[index++];
		    	        	txbuff[2] = buf[index++];
		    	        	txbuff[3] = buf[index++];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 1)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 2)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    	     			}else if(write_last_step == 3)
    					{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = addr-2;
    	    	        	txbuff[3] = buf[index++];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 4)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 5)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 6)
    					{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = addr-1;
    	    	        	txbuff[3] = buf[index];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 7)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 8)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = l + 2;
    	    	        	index = l/2*512;
    	    	        	zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;
    					}
    				}else if(num3 == 4)
    				{
    					if(write_last_step == 0)
    					{
		    	        	txbuff[0] = 0x80;
		    	        	txbuff[1] = buf[index++];
		    	        	txbuff[2] = buf[index++];
		    	        	txbuff[3] = buf[index++];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 1)
    				    {
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 2)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 3)
    					{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = addr-1;
    	    	        	txbuff[3] = buf[index];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 4)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 5)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = l + 2;
    	    	        	index = l/2*512;
    	    	        	zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;
    					}
    				}else if(num3 == 3)
    				{
    					if(write_last_step == 0)
    					{
		    	        	txbuff[0] = 0x80;
		    	        	txbuff[1] = buf[index++];
		    	        	txbuff[2] = buf[index++];
		    	        	txbuff[3] = buf[index++];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 1)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 2)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = l + 2;
    	    	        	index = l/2*512;
    	    	        	zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;
    					}
    				}else if(num3 == 2)
    				{
    					if(write_last_step == 0)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 1)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    	     			}else if(write_last_step == 2)
    					{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = addr-2;
    	    	        	txbuff[3] = buf[index++];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 3)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 4)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 5)
    					{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = addr-1;
    	    	        	txbuff[3] = buf[index];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 6)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 7)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = l + 2;
    	    	        	index = l/2*512;
    	    	        	zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;
    					}
    				}else if(num3 == 1)
    				{
    					if(write_last_step == 0)
    				    {
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 1)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 2)
    					{
    	    	        	txbuff[0] = 0x04;
    	    	        	txbuff[1] = l;
    	    	        	txbuff[2] = addr-1;
    	    	        	txbuff[3] = buf[index];
    	    	        	write_last_step++;
    	    	        	dayin = 1;
    					}else if(write_last_step == 3)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 4)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = l + 2;
    	    	        	index = l/2*512;
    	    	        	zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;

    					}
    				}else if(num3 == 0)
    				{
    					if(write_last_step == 0)
    					{
    	    	        	txbuff[0] = 0x20;
    	    	        	txbuff[1] = flash_addr;
    	    	        	txbuff[2] = 0xFF;
    	    	        	txbuff[3] = 0xFF;
    	    	        	write_last_step++;
    	    				//usleep(20);
    	    				dayin = 1;
    					}else if(write_last_step == 1)
    					{
    	    	        	txbuff[0] = 0x7F;
    	    	        	txbuff[1] = 0xFE;
    	    	        	txbuff[2] = 0x00;
    	    	        	txbuff[3] = 0x00;
    	    	        	write_last_step = 0;
    	    	        	write_step = 0;
    	    	        	dayin = 1;
    	    	        	l = l + 2;
    	    	        	index = l/2*512;
    	    	        	zw_update_write_state = ZW_UPDATE_WRITE_NORMAL;
    					}
    				}
    			}
    		}

        	if(zw_update_state == ZW_UPDATE_OVER)
        	{
    			printf("sx:the fp is %p,",&fp);
    			printf("update is over!!!!!!!!\n");
    			//zw_controller_state = DONGLE_STATE_OK;
    			//free(buf);
    			//i = fflush(fp);
    			/*
    			i = fclose(fp);
    			if(i == 0)
    			{
    				printf("sx:close is ok!\n");
    			}
    			else if(i == -1)
    			{
    				printf("sx:close is not ok!\n");
    			}
    			else
    			{
    				printf("sx:i do not know!\n");
    			}
    			*/
    			ZW_closeDongle();
    			break;
        	}
        	update_write_to_ZW();
    	}
    }

    return 0;
}

/**

     @brief 重新开启串口

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_closeDongle()
{
	tcflush(zw_fd, TCIOFLUSH);
	close(zw_fd);
	//popen("rm /dev/ttyUSB0","r");
	zw_controller_state = DONGLE_STATE_NO;
	zw_start_step = STEP_OPEN_CONTROLLER;
	ZWave_state = 0;
	serial_num++;
	/*
	 * 还要进行的额外的初始化
	 *  */
	/* 电量sensor存储结构体 */
	memset(&zw_battery, 0, sizeof(struct ZW_battery));
	/* 重发结构体 */
	memset(&zw_resend, 0, sizeof(struct ZW_resend));
}

/**

     @brief 发送ACK

     @author sunxun

     @remark 2015-7-1

     @note

*/
void sendResponseFlagToDongle(unsigned char serialflag)
{
	int ret;
	ret = write(zw_fd, &serialflag, 1);
	if(ret < 0)
	{
		ZW_closeDongle();
	}
	saveDataToLogBin("ZWAVESND",(char *)&serialflag,1);
}

/**

     @brief 收到错误数据，重新发送

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_resendDataToDongle()
{
	int ret;
	//printf("sx:write wrong-2!!!!!!!!\n");
	ret = write(zw_fd, txBuf,(txBuf[1] + 2));
	if(ret < 0)
	{
		ZW_closeDongle();
	}
	saveDataToLogBin("ZWAVERESND",(char *)txBuf,(txBuf[1] + 2));
}

/**

     @brief 是否重发的计时函数

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_resend_time_handle(int receive_step)
{
	if(receive_step == zw_resend.step)
	{
		/* 成功执行该次写入命令，清空标志位 */
		memset(&zw_resend, 0, sizeof(struct ZW_resend));
		//printf("sx:finish this step!\n");
	}
	else
	{
		clock_gettime(CLOCK_MONOTONIC, &current_time);
		zw_resend.time.tv_sec = current_time.tv_sec;
		/* 这里是BUG
		 * 不能够将num清零，否则会影响重发的，这里可以认为num是该条指令完成这几步后，一共重发了3此不行 */
		//zw_resend.num = 0;

		//printf("sx:step %d is %ld\n",receive_step,zw_resend.time.tv_sec);
	}
}

/**

     @brief 上报云端处理函数

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_send_to_cloud()
{
	/* 将节点信息＋信息种类＋信息，组合 */
}

/**

     @brief IPU判断sensor是否在线——12h

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_judge_sensor_online()
{
	int i;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	for(i = 0 ; i < SlaveNodeInf->num ; i++)
	{
		if((SlaveNodeInf->node_inf[i].sensor_state == ZWSENSOR_ON_LINE)
				&&(current_time.tv_sec - SlaveNodeInf->node_inf[i].sensor_time) > ZWSENSOR_ON_LINE_TIME_LIMIT)
		{
			SlaveNodeInf->node_inf[i].sensor_state = ZWSENSOR_OFF_LINE;
			printf("sx:there is a sensor off line named %d!\n",SlaveNodeInf->node_inf[i].sensor_ID[4]);
		}
	}

	/* 判断执行命令是否超时,超时重发 */
	if(zw_resend.step != RECEIVE_STEP_ZERO)
	{
		if((current_time.tv_sec - zw_resend.time.tv_sec) > 2)/* 大于2s就超时 */
		{
    		/* 开机流程中，获取HomeID出现的重发，认为不需要重发，认为这个port不是ZWave，还下一个口 */
    		if(zw_start_step == STEP_STORE_HOMEID)
    		{
    			if(serial_num >= 3)
    			{
    				serial_num = 0;
    			}
    			else
    			{
    				serial_num++;
    			}
    			printf("sx:only usb->serial!!\n");
    			ZW_closeDongle();
    			return 0;
    		}

    		/* 重发次数判断 */
			if(zw_resend.num >= 2)
			{
				/* 重发不成功，根据flag作进一步的判断 */
				printf("sx:resend failed!\n");

				if(zw_resend.flag == ZW_GET_VERSION_FAILED)
				{
					/* 保留－可以删除 */
					/* 获取controller的版本信息重发失败 */
					ZW_closeDongle();
					printf("@@@@:controller open failed!");
				}else if(zw_resend.flag == ZW_ADD_SENSOR_FAILED)
				{
					/* 组网开启或者关闭的失败，提示 */
					if(zw_controller_state == DONGLE_STATE_ADDING_NODE)
					{
						printf("@@@@:end add sensor failed!\n");
					}
					else
					{
						printf("@@@@:begin add sensor failed!\n");
					}
				}else if(zw_resend.flag == ZW_DELETE_SENSOR_FAILED)
				{
					/* 撤网开启或者关闭的失败，提示 */
					if(zw_controller_state == DONGLE_STATE_REMOVING_NODE)
					{
						printf("@@@@:end delete sensor failed!\n");
					}
					else
					{
						printf("@@@@:begin delete sensor failed!\n");
					}
				}else if(zw_resend.flag == ZW_FORCE_DELETE_FAILED)
				{
					/* 强删除某个sensor失败，提示 */
					printf("@@@@:force delete failed!\n");
				}else if(zw_resend.flag == ZW_CONFIGURE_SENSOR_FAILED)
				{
					/* 组入sensor时失败，删除！ */
					ZW_delete_node(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4]);
					/* 向controller发送命令，重新开启组网 */
					ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 1);
				}else if(zw_resend.flag == ZW_OPERATE_SENSOR_FAILED)
				{
					/* operate the sensor failed */
					printf("sx:resend failed!end resend!!\n");
					ZW_send_to_Child(ZW_YALE_DOOR_LOCK, 1, 32, 4);
					/* 结束重发，即可 */
				}

				/* 把数据处理完成后，再清零，记好了顺序，要不你会后悔的 */
				memset(&zw_resend, 0, sizeof(struct ZW_resend));
			}
			else
			{
				zw_resend.num++;
				printf("sx:resend num is %d!\n",zw_resend.num);
				ZW_resendDataToDongle();
			}
		}
	}
	return 0;
}

/**

     @brief IPU自我清除列表
            500型模组不支持

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_self_update()
{
	//struct timespec currect_time = {0, 0};
	//clock_gettime(CLOCK_MONOTONIC, &currect_time);
}

/**

     @brief 增加新的节点到IPU节点列表中

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_add_new_node(unsigned char nodeid, unsigned char kind, unsigned char flag)
{
	int i;

	for(i = 0; i < SlaveNodeInf->num; i++)
	{
		if(SlaveNodeInf->node_inf[i].sensor_ID[4] == nodeid)
		{
			/* this node is already in your list */
			return ZW_REPEAT_JOIN_NETWORK;
		}
	}

	if(SlaveNodeInf->num == 232)
	{
		/* your list is full,you can not add new one! */
		saveDataToLogStr("ZWERROR","the network is full!",strlen("the network is full!"));
		return ZW_NETWORK_LIST_FULL;
	}

	SlaveNodeInf->node_inf[SlaveNodeInf->num].sensor_ID[4] = nodeid;
	/* sensor的种类 */
	SlaveNodeInf->node_inf[SlaveNodeInf->num].sensor_kind  = kind;
	/* sensor需要配置的参数个数 */
	SlaveNodeInf->node_inf[SlaveNodeInf->num].sensor_flag  = flag;
	/* sensor在线或者离线的标志位 */
	SlaveNodeInf->node_inf[SlaveNodeInf->num].sensor_state = ZWSENSOR_ON_LINE;
	/* 设置时间 */
	clock_gettime(CLOCK_MONOTONIC, &current_time);
	SlaveNodeInf->node_inf[SlaveNodeInf->num].sensor_time  = current_time.tv_sec;

	/* 设置全局变量，方便下面对该信加入的sensor进行配置 */
	zw_set_sensor_number = SlaveNodeInf->num;
	SlaveNodeInf->num++;

	printf("sx:there is a new one coming,named %d!the list contain sensor is %d!\n", nodeid, SlaveNodeInf->num);
	//saveDataToLogStr("ZWAVEADD1","a new node add to the network success!",strlen("a new node add to the network success!"));
	return ZW_SUCCESS;
}

/**

     @brief 删除传感器在IPU中存储的信息

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_delete_node(unsigned char nodeid)
{
	int i;

	for(i = 0 ; i < SlaveNodeInf->num ; i++)
	{
		if(SlaveNodeInf->node_inf[i].sensor_ID[4] == nodeid)
		{
			if(i == (SlaveNodeInf->num - 1))//如果是最后一个结点直接删除
			{
				//SlaveNodeInf->node_inf[i].sensor_flag = 0x00;
				/* 提醒，只是将某个节点的flag置零是不行的，因为我们还会通过nodeID来轮询查找节点 */
				memset(&SlaveNodeInf->node_inf[i], '\0', sizeof(struct s_zw_defination));
				SlaveNodeInf->num--;
			}
			else
			{
				memcpy(&SlaveNodeInf->node_inf[i],&SlaveNodeInf->node_inf[SlaveNodeInf->num - 1],sizeof(struct s_zw_defination));
				memset(&SlaveNodeInf->node_inf[SlaveNodeInf->num - 1], '\0', sizeof(struct s_zw_defination));
				SlaveNodeInf->num--;
			}
			//saveDataToLogStr("ZWAVEDEL","this node delete success!",strlen("this node delete success!"));
			printf("the num of the node in the list is %d\n",SlaveNodeInf->num);
			return 0;
		}
	}
	return 1;
}

/**

     @brief 获取组如的sensor需要配置的参数个数

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_attribute(unsigned char productID)
{
	int i;
	for(i = 0 ; i < 10 ; i++)
	{
		if(ZwaveTable[i][0] == productID)
		{
			return ZwaveTable[i][1];
		}
	}

	return ZW_NOT_SUPPORT_SENSOR;
}

/**

     @brief 确定sensor的种类：watersensor-01,multisensor-02

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_sensor_kind(unsigned char productID)
{
	int i;
	for(i = 0 ; i < 10 ; i++)
	{
		if(ZwaveTable[i][0] == productID)
		{
			return (i + 1);
		}
	}

	/* 不会执行 */
	return 0;
}

/**

     @brief 根据nodeID来确定它在IPU列表中的位置

     @author sunxun

     @remark 2015-7-1

     @note

*/
unsigned char ZW_sensor_location(unsigned char nodeid)
{
	int i;

	for(i = 0; i < SlaveNodeInf->num; i++)
	{
		if(SlaveNodeInf->node_inf[i].sensor_ID[4] == nodeid)
		{
			/* this node is already in your list */
			return SlaveNodeInf->node_inf[i].sensor_kind;
		}
	}
	/* 此sensor确实在本网络中，但是，由于异常并没有记录 */
	return 0xFF;
}

/**

     @brief ZW controller串口配置

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_serialport_config()
{
	struct termios operation;
	if (tcgetattr(zw_fd, &operation) != 0)
	{
		perror("set tty");
	}
	cfmakeraw(&operation);/*raw mode*/
	operation.c_cflag |= CLOCAL | CREAD; /*local mode and can read*/
	operation.c_cflag &= ~CSIZE;/*NO mask*/
	operation.c_cflag |= CS8;/*8 bit data */
	operation.c_cflag &= ~PARENB;/*no parity check */
	operation.c_cflag &= ~CSTOPB; // 1 stop bit;
	operation.c_cc[VTIME] = 0;
	operation.c_cc[VMIN] = 1;
	cfsetispeed(&operation, B115200);
	cfsetospeed(&operation, B115200);
	tcflush(zw_fd, TCIFLUSH);

	if ((tcsetattr(zw_fd, TCSAFLUSH, &operation)) != 0)
	{
		perror("tty set error");
	}
}

/**

     @brief ZW controller串口打开

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_open_port()
{
	printf("sx:@@@@@@@@@@@@@@@@@@@@.......%d!\n",serial_num);
	memset(zw_port_name, 0, sizeof(zw_port_name));
	sprintf(zw_port_name, "/dev/ttyUSB%d", serial_num);
	zw_fd = open(zw_port_name, O_RDWR | O_NOCTTY | O_NDELAY);
	if(zw_fd > 0)
	{
		printf("sx:open is right!\n");
		/* 设成阻塞模式 */
		fcntl(zw_fd, F_SETFL, 0);
		ZW_serialport_config();
		/* 开机标志位 */
		zw_start_step = STEP_GET_HOMEID_FROM_CONTROLLER;
	}
	else
	{
		if(serial_num >= 3)
		{
			serial_num = 0;
		}
		else
		{
			serial_num++;
		}
		printf("sx:open is wrong!\n");
		sleep(2);
		/* 打开失败后，就当做什么也没有发生！ */
		//ZW_closeDongle();
	}
}

/**

     @brief 线程同步

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_threadSynchronization()
{
	rZwave = 1;
	while(rChildProcess == 0)
	{
		thread_usleep(0);
	}
	thread_usleep(0);
}

/**

     @brief 创建共享队列 ＋ 初始化参数

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_ModuleInit()
{
	/* ******************************************************
	 * 创建共享队列
	 * ******************************************************/
	zw_localMsgId = msg_queue_get((key_t)CHILD_THREAD_MSG_KEY);
	if (zw_localMsgId == -1)
	{
		exit(0);
	}
	zw_remoteMsgId = msg_queue_get((key_t)CHILD_PROCESS_MSG_KEY);
	if (zw_remoteMsgId == -1)
	{
		exit(0);
	}

	/* *******************************************************
	 * 初始化参数
	 * ******************************************************/
	/* IPU本地存储sensor信息静态列表 */
	SlaveNodeInf = (struct SlaveNode *)malloc(sizeof(struct SlaveNode));
	memset(SlaveNodeInf, 0, sizeof(struct SlaveNode));

	/* 电量sensor存储结构体 */
	memset(&zw_battery, 0, sizeof(struct ZW_battery));

	/* 重发结构体 */
	memset(&zw_resend, 0, sizeof(struct ZW_resend));

#if 0
	不使用的原因：1.插着dongle开机，IPU无法识别；
	             2.底层机制不清楚，然而使用的过于细致；
	/* ************************
	 *  插、拔判断
	 *  ***********************/
	/* 给套接子一个绑定的sockaddr结构，这里是sockaddr_nl结构 */
    memset(&sa,0,sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 15;//NETLINK_KOBJECT_UEVENT;//如果为零，表示要接收所有内核消息
    sa.nl_pid    = 0;

    /* 判断add,还是remove */
    data[0].iov_base = malloc(80);
    data[0].iov_len  = 80;
    /* 存储内核上发的多余的数据 */
    data[1].iov_base = malloc(1024);
    data[1].iov_len  = 1024;

    sockfd = socket(AF_NETLINK, SOCK_RAW, 15);//NETLINK_KOBJECT_UEVENT);
    if(sockfd == -1)
    {
		perror("socket creating failed");
    }

    if(bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
    	perror("bind error");
    }
#endif

	/* 透传指令需要，0x13 */
	txOptions = (TRANSMIT_OPTION_ACK | TRANSMIT_OPTION_AUTO_ROUTE | TRANSMIT_OPTION_EXPLORE);
#if 0
	/* 测试首先打开ttyUSB0 */
	test_2 = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_NDELAY);
	if(test_2 > 0)
	{
		printf("sx:ttyUSB0 已经给了别人！\n");
	}
#endif
}

/**

     @brief 计算校验值

     @author sunxun

     @remark 2015-7-1

     @note

*/
unsigned char ZW_CalculateChecksum(unsigned char *pData,int nLength)
{
	unsigned char byChecksum = 0xFF;
    int i;
    for (i = 0; i < nLength; nLength--){
        byChecksum ^= *pData++;
    }
    return byChecksum;
}

/**

     @brief 向子进程发送响应命令

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_send_to_Child(int cmd, unsigned char state, unsigned char nodeID, unsigned char sensorKind)
{
	unsigned char sendZWaveData[MAX_MSG_LEN];
	memset(sendZWaveData,'\0',MAX_MSG_LEN);
	struct MsgData *msg = (struct MsgData *)sendZWaveData;
	unsigned char * rebakStr = sendZWaveData + sizeof(struct MsgData);

	msg->type = ZWAVEDONGLE_MSG_TYPE;
	msg->cmd  = cmd;

	switch (cmd)
	{
	    /* 应答APPS的组网开启命令 */
	    case (ZW_BEGIN_ADD_SENSOR + ZW_ANSWER_APPS):
	    	*rebakStr = 0;
	        if(state == ZW_SUCCESS)
	        {
		    	*(rebakStr + 1) = '0';
	        }
	        else
	        {
	        	/* 组网开启失败，因为已经处于组网状态 */
		    	*(rebakStr + 1) = '1';
	        }

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 2) == -1){
	    	}
	    	break;

	    /* 应答APPS的组网结束指令 */
	    case (ZW_END_ADD_SENSOR + ZW_ANSWER_APPS):
	    	*rebakStr = 0;
	        if(state == ZW_SUCCESS)
	        {
		    	*(rebakStr + 1) = '0';
	        }
	        else
	        {
	        	/* 组网关闭失败，因为没有处于组网态 */
		    	*(rebakStr + 1) = '1';
	        }

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 2) == -1){
	    	}
	    	break;

	    /* 应答APPS的删除开启指令 */
	    case (ZW_BEGIN_DELETE_SENSOR + ZW_ANSWER_APPS):
	    	*rebakStr = 0;
	        if(state == ZW_SUCCESS)
	        {
		    	*(rebakStr + 1) = '0';
	        }
	        else
	        {
	        	/* 删除开启失败 */
		    	*(rebakStr + 1) = '1';
	        }

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 2) == -1){
	    	}
	    	break;

		/* 应答APPS的删除关闭指令 */
	    case (ZW_END_DELETE_SENSOR + ZW_ANSWER_APPS):
	    	*rebakStr = 0;
	        if(state == ZW_SUCCESS)
	        {
		    	*(rebakStr + 1) = '0';
	        }
	        else
	        {
	        	/* 删除关闭失败，因为controller没有处于删除状态 */
		    	*(rebakStr + 1) = '1';
	        }

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 2) == -1){
	    	}
	    	break;

		/* 应答APPS强制删除 */
	    case (ZW_FORCE_DELETE_SENSOR + ZW_ANSWER_APPS):
	    	if(state == ZW_SUCCESS)
	    	{
		    	*rebakStr = ZW_SUCCESS;
	    	}else if(state == ZW_FORCE_DELETE_SENSOR_FAILED)
	    	{
		    	*rebakStr = 0x01;
	    	}

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 1) == -1){
	    	}
	    	break;

	    /* 应答APPS清除指令 */
	    case (ZW_CLEAR_SENSOR + ZW_ANSWER_APPS):
	    	*rebakStr = 0;
	        if(state == ZW_SUCCESS)
	        {
		    	*(rebakStr + 1) = 0;
	        }
	        else
	        {
	        	/* 清除开启或者关闭失败 */
		    	*(rebakStr + 1) = 1;
	        }

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 2) == -1){
	    	}
	    	break;

	    /* 清除sensor信息上报 */
	    case ZW_CLEAR_SENSOR_UPLOARD:
	        if(state == ZW_SUCCESS)
	        {
		    	*rebakStr = ZW_SUCCESS;
		    	memset(rebakStr + 1, 0, 5);
	        }else if(state == ZW_NO_SENSOR_CLEAR)
	        {
	        	/* 没有sensor清除，时间到拉 */
		    	*rebakStr = 0x01;
		    	memset(rebakStr + 1, 1, 5);
	        }else if(state == ZW_CLEAR_OWN_SENSOR)
	        {
	        	/* 删除了自己网络中的sensor */
		    	*rebakStr = 0x02;
		    	memcpy(rebakStr + 1, SlaveNodeInf->home_ID, 4);
		    	*(rebakStr + 5)= nodeID;
	        }

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 6) == -1){
	    	}
	    	break;

	    /* sensor标识 */
	    case ZW_CONFIRM_SENSOR:
	    	/* 复制homeID */
	    	memcpy(rebakStr, SlaveNodeInf->home_ID, 4);
	    	/* 复制nodeID */
	    	memcpy(rebakStr + 4, &nodeID, 1);

	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 5) == -1){
	    	}
	    	break;

	    /* 上报APPS新加入的sensor */
	    case ZW_NEW_SENSOR_UPLOARD:
	    	if(state == ZW_SUCCESS)
	    	{
	    		/* 状态位 */
	    		*rebakStr = state;
		    	/* 复制homeID */
		    	memcpy(rebakStr + 1, SlaveNodeInf->home_ID, 4);
		    	/* 复制nodeID */
		    	memcpy(rebakStr + 5, &nodeID, 1);
		    	/* 新sensor的种类 */
		    	*(rebakStr + 6) = 0x10;
		    	*(rebakStr + 7) = sensorKind;

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 8) == -1){
		    	}
	    	}else if(state == ZW_NO_SENSOR_JOIN)
	    	{
	    		/* 状态位 */
	    		*rebakStr = state;

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 1) == -1){
		    	}
	    	}else if(state == ZW_REPEAT_JOIN_NETWORK)
	    	{
	    		/* 状态位 */
	    		*rebakStr = state;

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 1) == -1){
		    	}
	    	}else if(state == ZW_NETWORK_LIST_FULL)
	    	{
	    		/* 状态位 */
	    		*rebakStr = state;

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 1) == -1){
		    	}
	    	}else if(state == ZW_NOT_SUPPORT_SENSOR)
	    	{
	    		/* 状态位 */
	    		/* 这里0xFE是为了照顾前面确定sensor种类时方便，0x04是为了照顾后面，给APPS错误码连续 */
	    		*rebakStr = 0x04;

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 1) == -1){
		    	}
	    	}
	    	break;

	    /* 删除sensor信息上报 */
	    case ZW_DELETE_SENSOR_UPLOARD:
	    	if(state == ZW_SUCCESS)/* 成功删除希望删除的sensor */
	    	{
	    		/* 状态位 */
	    		*rebakStr = state;
		    	/* 希望删除的sensor */
		    	memcpy(rebakStr + 1, zw_delete_sensor.hope_sensor, 5);
		    	/* 实际删除的sensor */
		    	memcpy(rebakStr + 6, zw_delete_sensor.delete_sensor, 5);

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 11) == -1){
		    	}
	    	}else if(state == ZW_NO_SENSOR_DELETE)
	    	{
	    		/* 状态位 */
	    		*rebakStr = 0x01;
		    	/* 希望删除的sensor */
		    	memcpy(rebakStr + 1, zw_delete_sensor.hope_sensor, 5);
		    	/* 实际删除的sensor */
		    	memcpy(rebakStr + 6, zw_delete_sensor.delete_sensor, 5);

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 11) == -1){
		    	}
	    	}else if(state == ZW_DELETE_OTHER_SENSOR)
	    	{
	    		/* 状态位 */
	    		*rebakStr = 0x02;
		    	/* 希望删除的sensor */
		    	memcpy(rebakStr + 1, zw_delete_sensor.hope_sensor, 5);
		    	/* 实际删除的sensor */
		    	memcpy(rebakStr + 6, zw_delete_sensor.delete_sensor, 5);

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 11) == -1){
		    	}
	    	}else if(state == ZW_DELETE_UNKNOW_SENSOR)
	    	{
	    		/* 状态位 */
	    		*rebakStr = 0x03;
		    	/* 希望删除的sensor */
		    	memcpy(rebakStr + 1, zw_delete_sensor.hope_sensor, 5);
		    	/* 实际删除的sensor */
		    	memcpy(rebakStr + 6, zw_delete_sensor.delete_sensor, 5);

		        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
		    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 11) == -1){
		    	}
	    	}
	    	break;

	    /* 从云端获取sensor列表 */
	    case ZW_GET_SENSOR_LIST_CLOUD:
	    	break;

	    /* 上报云端sensor上报的信息 */
	    case ZW_UPLOARD_TO_CLOUD:
	    	break;

	    /* zwave 门锁测试
	     * 返回给APPS开关们成功与否 */
	    case ZW_YALE_DOOR_LOCK:
        	/* ***************************
        	 * back data construction
        	 * | sensorID | Mode | Cmd |
        	 * |    5     |  4   |  2  |
        	 * ************************* */
        	memcpy(rebakStr, SlaveNodeInf->home_ID, 4);

	    	*(rebakStr + 4) = SlaveNodeInf->node_inf[0].sensor_ID[4];/* NodeID */

	    	*(rebakStr + 8) = 1;/* Mode 0001 */

	    	*(rebakStr + 10) = state;

			saveDataToLogBin("ZW-OP-B", sendZWaveData + sizeof(struct MsgData), 11);
	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData)-sizeof(long int) + 11) == -1){
	    	}
	    	break;

	    /* 返回给APPS door lock 的状态 */
	    case ZW_YALE_DOOR_BACK_STATE:
        	/* ***************************
        	 * back data construction
        	 * | sensorID | State |
        	 * |    5     |   2   |
        	 * ************************* */
        	memcpy(rebakStr, SlaveNodeInf->home_ID, 4);

	    	*(rebakStr + 4) = SlaveNodeInf->node_inf[0].sensor_ID[4];/* NodeID */

	    	*(rebakStr + 6) = state;

			saveDataToLogBin("ZW-SE-B", sendZWaveData + sizeof(struct MsgData), 7);
	        /* 对于所要发送命令的长度问题，现在之能够根据协议定 */
	    	if(msg_queue_snd(zw_remoteMsgId, sendZWaveData, sizeof(struct MsgData) - sizeof(long int) + 7) == -1){
	    	}
	    	break;

	    default:

	    	break;
	}

}

/**

     @brief 接收来自子进程的命令
            APPS＋云端

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_analyse_Msg_from_Child()
{
	int i;
	char getZWaveData[MAX_MSG_LEN];
	memset(getZWaveData,'\0',MAX_MSG_LEN);
	struct MsgData *msg = (struct MsgData *)getZWaveData;

	if(msg_queue_rcv(zw_localMsgId, getZWaveData, MAX_MSG_LEN, ZWAVEDONGLE_MSG_TYPE) == -1)
	{
	}
	else {
        printf(".........OK3.........\n");
		switch(msg->cmd) {
		    /* 开始组网 */
			case ZW_BEGIN_ADD_SENSOR:
#if 0
				/* 测试新函数的可靠性 */
				clock_gettime(CLOCK_REALTIME, &time1);
				clock_gettime(CLOCK_MONOTONIC, &time2);
				time3 = time(NULL);
				printf("@@@@@@@@@@@sx:time is %ld,%ld,%ld!!\n",time1.tv_sec, time2.tv_sec, time3);
#endif
				if(zw_controller_state == DONGLE_STATE_OK)
				{
					/* 向controller发送命令，开启组网 */
					ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 1);
					/* 应答APPS组网开启成功 */
					ZW_send_to_Child(ZW_BEGIN_ADD_SENSOR + ZW_ANSWER_APPS, ZW_SUCCESS, 0, 0);
				}
				else
				{
					/* 应答APPS组网开启失败，因为正在组网态 */
					ZW_send_to_Child(ZW_BEGIN_ADD_SENSOR + ZW_ANSWER_APPS, ZW_BEGIN_ADD_SENSOR_FAILED, 0, 0);
				}
				break;

			/* 结束组网 */
			case ZW_END_ADD_SENSOR:
#if 0
				time3 = time(NULL);
				time4.tv_sec = time3 + 1000000;
				settimeofday(&time4, NULL);
				printf("@@@@@@@@@@@sx:set time!!\n");
#endif
				if(zw_controller_state == DONGLE_STATE_ADDING_NODE)
				{
					ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 2);
					/* 应答APPS组网关闭成功 */
					ZW_send_to_Child(ZW_END_ADD_SENSOR + ZW_ANSWER_APPS, ZW_SUCCESS, 0, 0);
				}
				else
				{
					/* 应答APPS组网关闭失败，因为controller没有处于组网态 */
					ZW_send_to_Child(ZW_END_ADD_SENSOR + ZW_ANSWER_APPS, ZW_END_ADD_SENSOR_FAILED, 0, 0);
				}
				break;

			/* YALE operation */
			case 0x03:
				printf("sx:opetate is ok!!!!!!!!!!!!\n the data is");
#if 0
				for(i = 0 ; i < 11 ; i++)
				{
					printf("%d,",*(getZWaveData + sizeof(struct MsgData) + i));
				}
				printf("\n");
#endif
				saveDataToLogBin("ZW-OP", getZWaveData + sizeof(struct MsgData), 11);
				SlaveNodeInf->node_inf[0].sensor_ID[4] = *(getZWaveData + sizeof(struct MsgData) + 4);
				//搜索door的时候已经赋值,但是，如果IPU重启，APPS不再搜索
				if(*(getZWaveData + sizeof(struct MsgData) + 10) == 1)
				{
					zw_ofb_flag = 3;/* APP open */
				}
				else
				{
					zw_ofb_flag = 4;/* APP close */
				}
				ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
						COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 11);
				break;
			/* 开始删除 */
			case ZW_BEGIN_DELETE_SENSOR:
#if 0
				clock_gettime(CLOCK_REALTIME, &time1);
				clock_gettime(CLOCK_MONOTONIC, &time2);
				time3 = time(NULL);
				printf("@@@@@@@@@@@sx:time is %ld,%ld,%ld!!\n",time1.tv_sec, time2.tv_sec, time3);
#endif
				if(zw_controller_state == DONGLE_STATE_OK)
				{
					/* 存储要删除的sensor信息 ，这里homeID不做判断，默认一致 */
					memcpy(zw_delete_sensor.hope_sensor, getZWaveData + sizeof(struct MsgData), 4);
					zw_delete_sensor.hope_sensor[4] = *(getZWaveData + sizeof(struct MsgData) + 4);
					/* 测试 */
					printf("sx:hope to delete sensor ID is %d,%d,%d,%d,%d\n",zw_delete_sensor.hope_sensor[0], zw_delete_sensor.hope_sensor[1],
							zw_delete_sensor.hope_sensor[2], zw_delete_sensor.hope_sensor[3], zw_delete_sensor.hope_sensor[4]);
					/* 发送命令启动删除 */
					ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK, REMOVE_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 3);
					/* 应答APPS删除开启成功 */
					ZW_send_to_Child(ZW_BEGIN_DELETE_SENSOR + ZW_ANSWER_APPS, ZW_SUCCESS, 0, 0);
				}
				else
				{
					/* 应答APPS删除开始失败 */
					ZW_send_to_Child(ZW_END_ADD_SENSOR + ZW_ANSWER_APPS, ZW_BEGIN_DELETE_SENSOR_FAILED, 0, 0);
				}
				break;

			/* YALE search */
			case 0x05:
				printf("sx:search is ok!!!!!!!!!!!!\n");
#if 0
				for(i = 0 ; i < 5 ; i++)
				{
					printf("%d,",*(getZWaveData + sizeof(struct MsgData) + i));
				}
				printf("\n");
#endif
				saveDataToLogBin("ZW-SE", getZWaveData + sizeof(struct MsgData), 5);
				if(memcmp(SlaveNodeInf->home_ID, getZWaveData + sizeof(struct MsgData), 4) == 0)
				{
					printf("ok:the same dongle!\n");
				}
				else
				{
					printf("warming:not the same dongle!\n");
				}

				/* 新模式，获取门锁的状态  */
				SlaveNodeInf->node_inf[0].sensor_ID[4] = *(getZWaveData + sizeof(struct MsgData) + 4);//
				zw_ofb_flag = 9;/* door state */
				ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
						COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 11);
				break;

			/* 强制删除sensor */
			case ZW_FORCE_DELETE_SENSOR:
				/* 必须在删除模式下才会开启强删模式 */
				if(zw_controller_state == DONGLE_STATE_REMOVING_NODE)
				{
					/* 存储要删除的sensor信息 ，这里homeID不做判断，默认一致 */
					memcpy(zw_delete_sensor.hope_sensor, getZWaveData + sizeof(struct MsgData), 4);
					zw_delete_sensor.hope_sensor[4] = *(getZWaveData + sizeof(struct MsgData) + 4);
					/* 测试 */
					printf("sx:hope to delete sensor ID is %d,%d,%d,%d,%d\n",zw_delete_sensor.hope_sensor[0], zw_delete_sensor.hope_sensor[1],
							zw_delete_sensor.hope_sensor[2], zw_delete_sensor.hope_sensor[3], zw_delete_sensor.hope_sensor[4]);

					zw_controller_state = DONGLE_FORCE_DELETE;
					/* 强制删除的第一步是结束撤网 */
					ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK, REMOVE_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 4);
				}
				break;

			/* 清除sensor，等同于使controller进入到撤网状态 */
			case ZW_CLEAR_SENSOR:
				if(*(getZWaveData + sizeof(struct MsgData) + 1) == ZW_OPEN_MODE)
				{
					/* 开启清除模式 */
					if(zw_controller_state == DONGLE_STATE_OK)
					{
						ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK, REMOVE_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 3);

						zw_clear_mode = ZW_OPEN_MODE;
						/* 应答APPS清除开启成功 */
						ZW_send_to_Child(ZW_CLEAR_SENSOR + ZW_ANSWER_APPS, ZW_SUCCESS, 0, 0);
					}
					else
					{
						/* 应答APPS清除开始失败 */
						ZW_send_to_Child(ZW_CLEAR_SENSOR + ZW_ANSWER_APPS, ZW_BEGINE_CLEAR_SENSOR_FAILED, 0, 0);
					}
				}else if(*(getZWaveData + sizeof(struct MsgData) + 1) == ZW_CLOSE_MODE)
				{
					/* 关闭清除模式 */
					if(zw_controller_state == DONGLE_STATE_REMOVING_NODE)
					{
						ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK, REMOVE_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 4);
						/* 应答APPS清除关闭成功 */
						zw_clear_mode = ZW_CLOSE_MODE;
						ZW_send_to_Child(ZW_CLEAR_SENSOR + ZW_ANSWER_APPS, ZW_SUCCESS, 0, 0);
					}
					else
					{
						/* 应答APPS清除关闭失败 */
						ZW_send_to_Child(ZW_CLEAR_SENSOR + ZW_ANSWER_APPS, ZW_END_CLEAR_SENSOR_FAILED, 0, 0);
					}
				}

				break;

			/* 更新ZW controller模组镜像,测试 */
			case ZW_CONTROLLER_UPGRADE:
				printf("sx:begin upgrade!\n");
				printf("sx:the cmd is %d!\n",*(getZWaveData + sizeof(struct MsgData)));
				switch(*(getZWaveData + sizeof(struct MsgData)))
				{
				case 1:/* 获取亮度？ */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_MULTILEVEL, SWITCH_MULTILEVEL_GET, 0x22);
					break;
				case 2:
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_MULTILEVEL, SWITCH_MULTILEVEL_SET, 0x23);
					break;
				case 3:/* 配置可以远处控制，funcID不能变 */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0xFF, NEED_RESPONSE, 128,
							COMMAND_CLASS_CONFIGURATION, CONFIGURATION_SET, 0x24);
					break;
				case 4:/* 设置颜色 */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 22, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_COLOR, SWITCH_COLOR_SET, 0x25);
					memcpy(zw_bulb_color, getZWaveData + sizeof(struct MsgData) + 1, 3);
					break;
				case 5:
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 22, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_ALL, SWITCH_ALL_ON, 0x26);
					break;
				case 6:
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 50, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_ALL, SWITCH_ALL_OFF, 0x27);
					break;
				case 7:
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0x20, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_COLOR, SWITCH_COLOR_START_LEVEL_CHANGE, 0x28);
					break;
				case 8:
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0x60, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_COLOR, SWITCH_COLOR_START_LEVEL_CHANGE, 0x28);
					break;
				case 9:
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 22, NEED_RESPONSE, 128,
							COMMAND_CLASS_SWITCH_COLOR, SWITCH_COLOR_STOP_LEVEL_CHANGE, 0x28);
					break;
				case 10:
					//aaaa =1;
					//memcpy(zw_Ka, zw_Ka_new, 16);
					//memcpy(zw_Ke, zw_Ke_new, 16);
					/* door lock ID */
					SlaveNodeInf->node_inf[0].sensor_ID[4] = 32;//
					zw_ofb_flag = 3;/* APP open */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 11);
					break;
				case 11:
					//aaaa =1;
					//memcpy(zw_Ka, zw_Ka_new, 16);
					//memcpy(zw_Ke, zw_Ke_new, 16);
					zw_ofb_flag = 4;/* APP close */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 12);
					break;
				case 12://c
					zw_ofb_flag = 5;/* set door--- re-lock open */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 13);
					break;
				case 13://d
					zw_ofb_flag = 6;/* set door --- operating mode 01-all user code disable(warming : can close the door) except for master */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 14);
					break;
				case 14://e
					zw_ofb_flag = 7;/* set door --- operating mode 02-all user code disable and APPS can not open the door(can close the door) */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 15);
					break;
				case 15://f
					zw_ofb_flag = 8;/* set door --- operating mode 02-all user code disable and APPS can not open the door(can close the door) */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 16);
					break;
				default:

					break;
				}
//				printf("sx:set ZWave_state success!\n");
//				ZWave_state = 1;
				/*
				serial_num = 0;
				ZW_open_port();
				printf("sx:open success!\n");
				ZW_controller_upgrade();
				*/
				//ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, 116,
					//	COMMAND_CLASS_MANUFACTURER_SPECIFIC, MANUFACTURER_SPECIFIC_GET, ZW_GET_SENSOR_SPECIFIC_KIND);
			//	ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, 116,
				//		COMMAND_CLASS_MANUFACTURER_SPECIFIC, MANUFACTURER_SPECIFIC_GET, ZW_GET_SENSOR_SPECIFIC_KIND);
				break;

			/* 从云端获取sensor列表 */
		    case ZW_GET_SENSOR_LIST_CLOUD:
		    	/* 存储云端下发的列表 */
		    	break;

			default:
				break;
		}
	}
}

/**

     @brief 设置组入的传感器的参数,关联、设置参数等

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_set_sensor(unsigned char funcID)
{
	/* 变化配置步骤，第一次传入的为0x00! */
	if(funcID < ZW_SET_CONFIGURATION)
	{
		funcID++;
	}

	/* AEON led bulb */
	if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 5)
	{
		switch(funcID)
		{
		case 1:
			ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					COMMAND_CLASS_ASSOCIATION, ASSOCIATION_SET, funcID);
			return 0;
		case 2:
			funcID = 3;
			break;
			/* 保证最后一步结束就行 */
			//ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				//	COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 2);
			//return 0;
		case 3:
			return 0;
			funcID = 3;
			break;

		default:
			break;
		}
	}

	/* Yale 门锁 */
	if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 4)
	{
		switch(funcID)
		{
		case 1:
			ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					COMMAND_CLASS_SECURITY, SECURITY_SCHEME_GET, 1);
			return 0;

		case 2:
			/* 专门防止组网异常的出现 */
			return 0;
		case 6:
			/* 保证最后一步结束就行 */
			printf("SX:JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ\n");
			zw_ofb_flag = 1;/* 设置Kn */
			ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 2);
			return 0;
		case 3:
			return 0;
			funcID = 3;
			break;

		default:
			break;
		}
	}

	switch(funcID)
	{
	case ZW_ASSOCIATION_SENSOR:
        /*测试1，测试重发机制
		for(i = 5 ; i > 0 ; i--)
		{
			sleep(1);
			printf("%d\n",i);
		}
		*/
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_ASSOCIATION, ASSOCIATION_SET, funcID);
		break;
	case ZW_SET_WAKE_UP_TIME:
		ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
				COMMAND_CLASS_WAKE_UP, WAKE_UP_INTERVAL_SET, funcID);
		break;
	case ZW_SET_CONFIGURATION:
		if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag == ZW_SENSOR_NOTHING)
		{
			/* 该sensor信息，传递给APPS */
			ZW_send_to_Child(ZW_NEW_SENSOR_UPLOARD, ZW_SUCCESS, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
					SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind);
			printf("@@@@@:a new sensor to APPS!!\n");
			/* 重新开启组网，给用户连续的感觉 */
			ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 1);
		}
		else
		{
			if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 2)/*  多合一  sensor类型该了，0x05-0x02,0x2d-0x01 */
			{
				if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag == ZW_MULTI_SENSOR_UPLOARD_KIND)
				{
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,
							SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_CONFIGURATION, CONFIGURATION_SET, funcID);
					SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag--;
				}else if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag == ZW_MULTI_SENSOR_PIR_UPLOARD_INTERVAL)
				{
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,
							SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_CONFIGURATION, CONFIGURATION_SET, funcID);
					SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag--;
				}
			}else if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 4)
			{
				if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag == ZW_DOOR_LOCK_AUTO_RELOCK)
				{
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,
							SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
							COMMAND_CLASS_CONFIGURATION, CONFIGURATION_SET, funcID);
					SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag--;
				}
			}else if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 6)
			{
				ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,
						SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
						COMMAND_CLASS_CONFIGURATION, CONFIGURATION_SET, funcID);
				SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag--;
			}/* 加入其他sensor */
/* 加入其他sensor */
		}

		break;
	case ZW_GET_SENSOR_BATTERY:
		//printf("sx:dianlianghuoquchenggong!!");
		break;
	default:

		break;
	}
	return 0;
}

/**

     @brief 接收来自ZW controller上报的信息

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_accept_data_from_controller()
{
	int ret;
	unsigned char header;

	memset(RecvBuffer, '\0', BUF_SIZE);

	/* 先读取数据头 */
	ret = read(zw_fd,&header,1);
	if(ret <= 0)
	{
		close(zw_fd);
		printf("sx:read!1111\n");
		ZW_closeDongle();
		//ZW_detect_port();
		return -1;
	}
	else
	{
		saveDataToLogBin("ZWAVEREC",(char *)&header,1);

		if(header == NAK)
		{
			/* Dongle接收数据checksum有误，需要重发，理论上不会出现 */
			saveDataToLogStr("ZWAVEEP","ZWaveDongle return NAK,need resend data",strlen("ZWaveDongle return NAK,need resend data"));
			sleep(1);
			ZW_resendDataToDongle();
		}else if(header == CAN)
		{
			/* Dongle期望先接收到ACK，再接收数据，因此先发送ACK给Dongle，然后再重发数据 */
			saveDataToLogStr("ZWAVEEP","ZWaveDongle return CAN,need send ACK first",strlen("ZWaveDongle return CAN,need send ACK first"));
			sendResponseFlagToDongle(ACK);
			ZW_resendDataToDongle();
		}else if(header == ACK)
		{
			/* 正常的应答 */
			//saveDataToLogStr("ZWAVE","ZWaveDongle return ACK data",strlen("ZWaveDongle return ACK data"));
			/* 执行流程的第一步完成 */
			ZW_resend_time_handle(RECEIVE_STEP_ONE);
		}else if(header == SOF)
		{
			/* 获取数据长度 */
			ret = read(zw_fd,RecvBuffer,1);
			if(ret <= 0)
			{
				close(zw_fd);
				printf("sx:read!2222\n");
				ZW_closeDongle();
				saveDataToLogStr("ZWAVEEP","read ZWaveDongle data length failed!",strlen("read ZWaveDongle data length failed!"));
				//ZW_detect_port();
				//close(zw_fd);
				return -1;
			}

			/* 获取数据内容 */
			ret = read(zw_fd,(RecvBuffer + 1),RecvBuffer[0]);
			if(ret <= 0)
			{
				close(zw_fd);
				printf("sx:read!3333\n");
				ZW_closeDongle();
				saveDataToLogStr("ZWAVEEP","read ZWaveDongle data content failed!",strlen("read ZWaveDongle data content failed!"));
				//ZW_detect_port();
				//close(zw_fd);
				return -1;
			}

			/* 处理收到的数据 */
			ZW_process_data_from_controller(RecvBuffer);
		}
		else
		{
			saveDataToLogStr("ZWAVE","ZWaveDongle return data can not be analyze!",strlen("ZWaveDongle return data can not be analyze!"));
			sendResponseFlagToDongle(ACK);
			//zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_OPEN;
			return -1;
		}
	}

	return 0;
}

/**

     @brief 分析处理来自控制器的信息

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_process_data_from_controller(unsigned char * data)
{
	/* 为了获取controller中的nodeID信息 */
	int ret = 0;
	int i = 0;
	int j = 0;/* j/k 用于存储从controller中获得的nodeID列表 */
	int k = 0;/* 当k＝1000时，表示存在！ */
	unsigned char tmp;

	unsigned char serialCMD;
	unsigned char checksum;//计算结果的checksum
	unsigned char checksumrecv;//接收到的checksum
	unsigned char frametype;
	unsigned char dataLen = 0;
	unsigned char txStatus = 0;
	unsigned char bStatus  = 0;

	unsigned char sourceNodeID = 0;
	unsigned char zwaveDataLen = 0;
	unsigned char zwaveCmdClass = 0;
	unsigned char zwaveCmd = 0;
	unsigned char value = 0;
	unsigned char rxStatus = 0;

	unsigned char ProductID;
	unsigned char kind;
	unsigned char funcID;
	unsigned char attribute_num;
	unsigned char zwaveCmdContent;

	dataLen      = data[IDX_DL];
	frametype    = data[IDX_FT];
	serialCMD    = data[IDX_CMD];
	checksumrecv = data[dataLen];
	checksum     = ZW_CalculateChecksum(data,dataLen);

	saveDataToLogBin("ZWAVEREC",(char *)data,(data[0] + 1));

	//接收到消息的checksum错误
	if(checksumrecv != checksum)
	{
		saveDataToLogStr("ZWAVEEP","return checksum has error, send NAK",strlen("return checksum has error, send NAK"));
		/* 要求controller重新发送数据 */
		sendResponseFlagToDongle(NAK);
		return;
	}

	switch(serialCMD)
	{
	    /* 向controller中获取homeID */
	    case FUNC_ID_MEMORY_GET_ID:
	    	/* 忘了应答会造成连续发送四次数据 */
			sendResponseFlagToDongle(ACK);
			if(memcmp(SlaveNodeInf->home_ID, data + 3, 4) == 0)
			{
				printf("SX:dongle reback!!!!\n");
			}
			else
			{
				/* IPU本地存储sensor信息静态列表，清空！ */
				memset(SlaveNodeInf, 0, sizeof(struct SlaveNode));
		    	SlaveNodeInf->home_ID[0] = data[3];
		    	SlaveNodeInf->home_ID[1] = data[4];
		    	SlaveNodeInf->home_ID[2] = data[5];
		    	SlaveNodeInf->home_ID[3] = data[6];
			}
	    	zw_start_step = STEP_OPEN_SUCCESS;

	    	/* 需要从云端获取列表！ */

	    	/* 执行步骤 */
			ZW_resend_time_handle(RECEIVE_STEP_TWO);
	    	printf("sx:homeID is %d,%d,%d,%d\n",data[3],data[4],data[5],data[6]);
	    break;

	    /* 获得版本号 */
	    case FUNC_ID_ZW_GET_VERSION:
			sendResponseFlagToDongle(ACK);
	    	printf("sx:version is %d,%d,%d,%d,%d,%d,%d,%d\n",data[3],data[4],data[5],data[6],data[7],data[8],data[9],data[10]);
	    	/* data[9]-data[12] 表示版本号，如果版本号不一样，就需要升级
	    	 *  zw_start_step = STEP_UPGRADE;
	    	 *  如果一样
	    	 *  zw_start_step = STEP_GET_INFORMATION_FROM_CLOUD；*/
	    	//zw_start_step = STEP_UPGRADE;

	    	/* 执行步骤 */
			ZW_resend_time_handle(RECEIVE_STEP_TWO);
			break;

	    /* @@500型controller不支持@@controller中包含的nodeID信息 */
		case FUNC_ID_SERIAL_API_GET_INIT_DATA:
			sendResponseFlagToDongle(ACK);
			//data[6]开始，29个字节数！
            for(i = 0; i < NODES_BUF_LEN; i++)
            {
            	if(data[6 + i] != 0)
            	{
					for(j = 0; j < 8;j++)
					{
						if(data[6 + i] & (1 << j))
						{
							/* NodeID的取值不能够取1,1是controller的nodeID */
							tmp = i * 8 + j + 1;
							if(tmp != 1)
							{
								for(k = 0 ; k < SlaveNodeInf->num ; k++)
								{
									if(SlaveNodeInf->node_inf[k].sensor_ID[4] == tmp)
									{
										k = 1000;
									}
								}

								if(k != 1000)
								{
									printf("sx:there is a node only in controller named %d\n",tmp);
									/* 存在失效节点，进入自我清除的第二步 */
									//zw_controller_state = DONGLE_STATE_SELF_CLEAR;
									//ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, tmp,
										//	COMMAND_CLASS_VERSION, VERSION_COMMAND_CLASS_GET, ZW_SET_SENSOR_FAILED_QUEUE);
									//usleep(100000);
								}
							}
						}
					}
            	}
            }
            break;

        /* 组网 */
		case FUNC_ID_ZW_ADD_NODE_TO_NETWORK:
			/* 表示此时controller所处于的工作状态 */
			bStatus = data[4];
			/* 在3和5模式下是这样的,5模式（组如一个新的sensor成功）下使用*/
			sourceNodeID = data[5];
			if(bStatus == ADD_NODE_STATUS_LEARN_READY)
			{
				/* IPU中的controller进入到可接收模式 */
				printf("sx:the controller is ready for new node coming!\n");
				/* 开启组网模式计时，如果没有sensor响应，最多等待1min */
				clock_gettime(CLOCK_MONOTONIC, &zw_busying_time);

		    	/* 执行步骤 */
				ZW_resend_time_handle(RECEIVE_STEP_TWO);

				zw_controller_state = DONGLE_STATE_ADDING_NODE;
				/* ACK响应尽量往后推 */
				sendResponseFlagToDongle(ACK);
				//saveDataToLogStr("ZWAVEADDNEWONE","the ZWaveDongle ready to include a node into the network!",strlen("the ZWaveDongle ready to include a node into the network!"));
			}else if(bStatus == ADD_NODE_STATUS_NODE_FOUND)
			{
				zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_OPEN;
				sendResponseFlagToDongle(ACK);
				saveDataToLogStr("ZWAVEADDNEWONE","the ZWaveDongle has found a node that wants to be included into the network!",strlen("the ZWaveDongle has found a node that wants to be included into the network!"));
			}else if(bStatus == ADD_NODE_STATUS_ADDING_SLAVE)
			{
				sendResponseFlagToDongle(ACK);
				/* 保存 */
				zw_temp_node.nodeID = sourceNodeID;
				zw_temp_node.flag = 1;
				/* 为了进行锁测试 */
				ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 11);
			}else if(bStatus == ADD_NODE_STATUS_ADDING_CONTROLLER)
			{
				sendResponseFlagToDongle(ACK);
				/* 保存 */
				zw_temp_node.nodeID = sourceNodeID;
				zw_temp_node.flag = 1;
				/* 为了进行锁测试 */
				ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 11);
			}else if(bStatus == ADD_NODE_STATUS_PROTOCOL_DONE)
			{
				sendResponseFlagToDongle(ACK);
#if 0
				//测试1，测试重发机制
				for(i = 5 ; i > 0 ; i--)
				{
					sleep(1);
					printf("%d\n",i);
				}
#endif
			}else if(bStatus == ADD_NODE_STATUS_DONE)
			{
				sendResponseFlagToDongle(ACK);
				zw_controller_state = DONGLE_STATE_OK;
		    	/* 执行步骤 */
				ZW_resend_time_handle(RECEIVE_STEP_TWO);
				if(data[3] == 11)
				{
					/* 组如一个新的sensor后，开始获取它的专属属性
					 * 目前这里不会执行！！ */
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, zw_temp_node.nodeID,
							COMMAND_CLASS_MANUFACTURER_SPECIFIC, MANUFACTURER_SPECIFIC_GET, ZW_GET_SENSOR_SPECIFIC_KIND);
				}
				else
				{
					printf("sx:the controller end adding node!\n");
				}
			}
			break;

		/* 正常删除流程 */
		case FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK:
			bStatus = data[4];
			sourceNodeID  = data[5];
			if(bStatus == REMOVE_NODE_STATUS_LEARN_READY)
			{
				/* 开启撤网模式计时，如果没有sensor响应，最多等待1min */
				clock_gettime(CLOCK_MONOTONIC, &zw_busying_time);

				printf("sx:the controller ready to delete some sensor!\n");

		    	/* 执行步骤 */
				ZW_resend_time_handle(RECEIVE_STEP_TWO);

				sendResponseFlagToDongle(ACK);

				zw_controller_state = DONGLE_STATE_REMOVING_NODE;
				//saveDataToLogStr("ZWAVEREMOVENODE","the ZWaveDongle ready to remove a node from the network!",strlen("the ZWaveDongle ready to remove a node from the network!"));
			}else if(bStatus == REMOVE_NODE_STATUS_NODE_FOUND)
			{
				sendResponseFlagToDongle(ACK);
				//saveDataToLogStr("ZWAVEREMOVENODE","the ZWaveDongle has found a node that wants to be deleted from the network!",strlen("the ZWaveDongle has found a node that wants to be deleted from the network!"));
			}else if(bStatus == REMOVE_NODE_STATUS_REMOVING_S)
			{
				sendResponseFlagToDongle(ACK);
				//saveDataToLogStr("ZWAVEREMOVENODE","the ZWaveDongle :a new slave node has been deleted from the network!",strlen("the ZWaveDongle :a new slave node has been deleted from the network!"));
				//fnDeleteNode(data[5]);
			}else if(bStatus == REMOVE_NODE_STATUS_DONE)
			{
				/* 0x06有很多含义，1。正常删除；2。结束撤网成功；3。删除异常传感器； */
				if(dataLen == REMOVE_NODE_END)
				{
					/* 结束撤网 */
					sendResponseFlagToDongle(ACK);
			    	/* 执行步骤 */
					ZW_resend_time_handle(RECEIVE_STEP_TWO);

					if(zw_controller_state == DONGLE_FORCE_DELETE)
					{
						ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, zw_delete_sensor.hope_sensor[4],
								COMMAND_CLASS_VERSION, VERSION_COMMAND_CLASS_GET, ZW_SET_SENSOR_FAILED_QUEUE);
					}
					else
					{
						printf("sx:end delete sensor!\n");
					}
					/* 要放到后面，不会影响判断条件 */
					zw_controller_state = DONGLE_STATE_OK;
				}else if(dataLen == REMOVE_NODE_COME)/* 我自作多情写成0x0c */
				{
					/* 正常删除流程 */
					if(sourceNodeID == 0)
					{
						/* 删除的sensor为其他网络的sensor或者是新的，反馈给APPS删除不成功 */
						if(zw_clear_mode == ZW_OPEN_MODE)
						{
							/* clear mode */
							printf("@@@@@:success clear!!\n");
							ZW_send_to_Child(ZW_CLEAR_SENSOR_UPLOARD, ZW_SUCCESS, 0, 0);
						}
						else
						{
							printf("@@@@@:delete others!!\n");
							memset(zw_delete_sensor.delete_sensor, 0, 5);
							ZW_send_to_Child(ZW_DELETE_SENSOR_UPLOARD, ZW_DELETE_UNKNOW_SENSOR, 0, 0);
						}
					}
					else
					{
						/* 删除sensor的正常流程，还没有应答controller！可以放心的运行！ */
						ZW_delete_node(sourceNodeID);
						if(zw_clear_mode == ZW_OPEN_MODE)
						{
							/* clear mode */
							printf("@@@@@:delete own sensor,shit!!!\n");
							ZW_send_to_Child(ZW_CLEAR_SENSOR_UPLOARD, ZW_CLEAR_OWN_SENSOR, sourceNodeID, 0);
						}
						else
						{
							/* 填充删除结构体 */
							memcpy(zw_delete_sensor.delete_sensor,SlaveNodeInf->home_ID,4);
							zw_delete_sensor.delete_sensor[4] = sourceNodeID;

							/* 判断所删除的sensor是不是希望删除的sensor */
							if(strncmp(&sourceNodeID, &zw_delete_sensor.hope_sensor[4], 1) == 0)
							{
								/* same－－－删除成功 */
								ZW_send_to_Child(ZW_DELETE_SENSOR_UPLOARD, ZW_SUCCESS, 0, 0);
							}
							else
							{
								/* 错误的删除了网络中的其他sensor */
								ZW_send_to_Child(ZW_DELETE_SENSOR_UPLOARD, ZW_DELETE_OTHER_SENSOR, 0, 0);
							}
						}
						printf("@@@@@:success delete the sensor named %d\n",sourceNodeID);
					}

					/* 处理完成后再去应答在这里可能会更好 */
					sendResponseFlagToDongle(ACK);

					/* 每次只之删除一个sensor */
					ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK, REMOVE_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 4);
				}
				else
				{
					/* 理论能上不会出现 */
					sendResponseFlagToDongle(ACK);
				}
			}else if(bStatus == REMOVE_NODE_STATUS_FAILED)
			{
			/* 07属于错误，不再是异常拉！！ */
				sendResponseFlagToDongle(ACK);
			}else if(bStatus == REMOVE_NODE_STATUS_STOP)
			{
		    /* 删除sensor中的一种异常，当两次触发sensor时会产生，这里我们直接无视 */
				sendResponseFlagToDongle(ACK);
			}else
			{
				sendResponseFlagToDongle(ACK);
			}

			break;

		/* 删除失败的传感器 */
		case FUNC_ID_ZW_REMOVE_FAILED_NODE_ID:
			if(dataLen == SEND_DATA_BACK_STEP1_LEN)
			{
		    	/* 执行步骤 */
				ZW_resend_time_handle(RECEIVE_STEP_TWO);

				//RetVal = data[IDX_DATA];要保证为01
				sendResponseFlagToDongle(ACK);
			}else if(dataLen == SEND_DATA_BACK_STEP2_LEN)
			{
		    	/* 执行步骤 */
				ZW_resend_time_handle(RECEIVE_STEP_THREE);

				sendResponseFlagToDongle(ACK);
				txStatus = data[4];
				if(txStatus == ZW_FAILED_NODE_REMOVED)
				{
					printf("sx:success delete!\n");
					/* 强制删除sensor成功*/
					ZW_send_to_Child(ZW_FORCE_DELETE_SENSOR + ZW_ANSWER_APPS, ZW_SUCCESS, 0, 0);
					/* 根据APPS穿过来的NodeID来删除 */
					ZW_delete_node(zw_delete_sensor.hope_sensor[4]);
				}
				else
				{
					/* sensor删除不成功，sensor信息仍然存在 */
					printf("@@@@@:failed delete!\n");
					/* 强制删除sensor失败是
					 * 目前，测试阶段，加入了判断sensor是不是存在于失效列表中，所以不会执行到这里 */
					//ZW_send_to_Child(ZW_FORCE_DELETE_SENSOR + ZW_ANSWER_APPS, ZW_FORCE_DELETE_SENSOR_FAILED, 0, 0);
				}

		        /* 先现在进行处理，然后，再应答 */
				//sendResponseFlagToDongle(ACK);
			}

			break;

		/* 确定是否为失败传感器 */
		case FUNC_ID_ZW_IS_FAILED_NODE_ID:
			sendResponseFlagToDongle(ACK);
			value = data[3];
			if(value == 0)
			{
				printf("sx:can not compulsion deletion!\n");
				/* 强制删除sensor失败是*/
				ZW_send_to_Child(ZW_FORCE_DELETE_SENSOR + ZW_ANSWER_APPS, ZW_FORCE_DELETE_SENSOR_FAILED, 0, 0);
			}
			else
			{
				printf("sx:you can delete this sensor!\n");
				ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_FAILED_NODE_ID, 0, NEED_RESPONSE, zw_delete_sensor.hope_sensor[4],
						0, 0, 1);
			}

			break;

		/* 透传指令  */
		case FUNC_ID_ZW_SEND_DATA:
			if(dataLen == SEND_DATA_BACK_STEP1_LEN)
			{
				//RetVal = data[IDX_DATA];要保证为01
				sendResponseFlagToDongle(ACK);
				/* 执行步骤的第二步 */
				ZW_resend_time_handle(RECEIVE_STEP_TWO);
			}else if(dataLen == SEND_DATA_BACK_STEP2_LEN)
			{
				funcID   = data[IDX_CMD + 1];/* 规律，接收的数据funcID紧紧跟着串口命令,前提是你发送了funcID */
				txStatus = data[IDX_DATA + 1];//保证为00
				sendResponseFlagToDongle(ACK);

				/* 就只有一种情况是希望失败，将传感器转移到失败列表中 */
				if(funcID == ZW_SET_SENSOR_FAILED_QUEUE)
				{
					/* 执行的第三步 */
					ZW_resend_time_handle(RECEIVE_STEP_THREE);

					/* 当senddata命令执行失败后，就可以强制删除该sensor */
					/* 强制删除sensor，IPU向controller确定一下是不是该sensor已经进入到失败列表中 */
					ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_FAILED_NODE_ID, 0, NEED_RESPONSE, zw_delete_sensor.hope_sensor[4],
							0, 0, 1);
				}else if(funcID == ZW_GET_SENSOR_BATTERY)
				{
					/* 这里成功不成功无所谓 */
					/* 执行的第三步 */
					ZW_resend_time_handle(RECEIVE_STEP_THREE);
					zw_battery.num--;
					zw_battery.flag = ZW_BATTERY_FREE;
				}
				else
				{
					if(txStatus == ZW_SUCCESS)
					{
						/* 执行的第三步 */
						ZW_resend_time_handle(RECEIVE_STEP_THREE);
						/* Send Data执行成功 */
						ZW_set_sensor(funcID);
					}
					else
					{
						printf("sx:send data failed!\n");
					}//透传失败
				}//不是强之删除操作
			}//头传的第2种

			break;

		/* controller主动上发信息
		 *  COMMAND_CLASS_MANUFACTURER_SPECIFIC没有，因为此时该节点没有存在IPU列表中
		 *  只要是有信息上报，就将其时间重新设置成当前时间*/
		case FUNC_ID_APPLICATION_COMMAND_HANDLER:
			rxStatus        = data[IDX_DATA];/* 0-单播；8－多播 */
			sourceNodeID    = data[IDX_DATA + 1];//4
			zwaveDataLen    = data[IDX_DATA + 2];//5
			zwaveCmdClass   = data[IDX_DATA + 3];//6
			zwaveCmd        = data[IDX_DATA + 4];//7
			/* ***************************
			 * 只要有sensor主动上报数据
			 * 就重置该sensor的时间
			 * **************************/
			for(i = 0 ; i < SlaveNodeInf->num ; i++)
			{
				if(SlaveNodeInf->node_inf[i].sensor_ID[4] == sourceNodeID)
				{
					clock_gettime(CLOCK_MONOTONIC, &current_time);
					SlaveNodeInf->node_inf[i].sensor_time = current_time.tv_sec;
					//printf("sx:reset a sensor time,named %d\n",sourceNodeID);
				}
			}

			/* 传感器的专属信息的获得 */
			if(zwaveCmdClass == COMMAND_CLASS_MANUFACTURER_SPECIFIC)
			{
				/* Yale门锁 */
				if(sourceNodeID == 116)
				{
					sendResponseFlagToDongle(ACK);
					printf("sx:Yale door lock specific ok!\n");
					//ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, 116,
						//	COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 22);
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, 116,
							COMMAND_CLASS_SECURITY, SECURITY_COMMANDS_SUPPORTED_GET, 23);
					break;
				}

				if(zwaveCmd == MANUFACTURER_SPECIFIC_REPORT)
				{
					/* ***********************************************
					 * 目前，只能通过sensor的产品号来区分sensor种类
					 * AEON厂家的产品号是两个字节，而我们只使用一个字节
					 * ((data[IDX_DATA + 9] * 0x100) + data[IDX_DATA + 10])
					 * ***********************************************/
					ProductID = data[IDX_DATA + 10];
					//printf("sx:poduct ID is %x\n",ProductID);
					attribute_num = ZW_attribute(ProductID);
					if(attribute_num != ZW_NOT_SUPPORT_SENSOR)
					{
						printf("sx:we can support this node!\n");
						/* 确定sensor的种类：水浸－01；多合一－02； */
						kind = ZW_sensor_kind(ProductID);
						/* 加入IPU的sensor列表 */
						ret = ZW_add_new_node(sourceNodeID, kind, attribute_num);
					}
					else
					{
						ret = ZW_NOT_SUPPORT_SENSOR;
					}

					/* 应答controller往后推，感觉会好点，这样防止冲突 */
					sendResponseFlagToDongle(ACK);

					/* ************************************
					 * 0-成功接入一个新结点，开始配置
					 * 1-已经接入
					 * 2-满了，无法在接入新的sensor
					 * 3-不支持此类设备
					 * *************************************/
					if(ret == ZW_SUCCESS)
					{
						/* 开始配置新加入的sensor */
						ZW_set_sensor(ZW_START_SET);
					}else if(ret == ZW_REPEAT_JOIN_NETWORK)
					{
						printf("@@@@@@:the sensor is already in your list!\n");
						/* 重新开启组网 */
						ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 1);

						/* 返回给APPS,该sensor已经存在网络中 */
						ZW_send_to_Child(ZW_NEW_SENSOR_UPLOARD, ZW_REPEAT_JOIN_NETWORK, sourceNodeID, 0);
					}else if(ret == ZW_NETWORK_LIST_FULL)
					{
						printf("@@@@@@:the list is full,you can not add new one!\n");
						/* 关闭组网 */
						ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 2);

						/* 返回给APPS，该ZWave网络已满 */
						ZW_send_to_Child(ZW_NEW_SENSOR_UPLOARD, ZW_NETWORK_LIST_FULL, sourceNodeID, 0);
					}else if(ret == ZW_NOT_SUPPORT_SENSOR)
					{
						printf("@@@@@@:we can not support this node!\n");
						/* 重新开启组网 */
						ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_ANY, NEED_RESPONSE, 0, 0, 0, 1);

						/* 返回给APPS，不支持此类sensor */
						ZW_send_to_Child(ZW_NEW_SENSOR_UPLOARD, ZW_NOT_SUPPORT_SENSOR, sourceNodeID, 0);
					}

					/* 开始获取电量 */
					//ZW_send_command_to_controller(FUNC_ID_ZW_SENDA, 0, NEED_RESPONSE, sourceNodeID,
						//	COMMAND_CLASS_BATTERY, BATTERY_GET, 52);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_BATTERY)
			{
				if(zwaveCmd == BATTERY_REPORT)
				{
					/* The field can take values from 0 to 100% (0x00 – 0x64). The value 0xFF indicates a battery low warning */
					value = data[8];
					sendResponseFlagToDongle(ACK);
					printf("sx:a sensor named %d report its battery - %d!\n",sourceNodeID,value);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_WAKE_UP)
			{
				/* 传感器定时醒来，保存nodeID，后续发送命令来获取电量 */
		    	if(zwaveCmd == WAKE_UP_NOTIFICATION)
		    	{
		    		/* 开启加速模式 */
		    		zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_OPEN;
					sendResponseFlagToDongle(ACK);
		    		printf("sx:the sensor named %d wake up!!\n",sourceNodeID);

		    		/* 存储该节点的nodeID为了后续获得电量 */
		    		zw_battery.nodeID[zw_battery.num] = sourceNodeID;
		    		zw_battery.num++;
		    	}
			}else if(zwaveCmdClass == COMMAND_CLASS_SENSOR_BINARY)/* 该方式将会被淘汰，黄工！ */
			{
				if(zwaveCmd == SENSOR_BINARY_REPORT)
				{
					sendResponseFlagToDongle(ACK);
					//触发警笛响起
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_BASIC)
			{
				sendResponseFlagToDongle(ACK);
				value = data[IDX_DATA + 5];
				if(zwaveCmd == BASIC_SET)/* 应该为BASIC_REPORT但log中的确是0x01，也只能这样 */
				{
					if((value == 0xff)&&(rxStatus == RECEIVE_STATUS_TYPE_SINGLE))
					{
						kind = ZW_sensor_location(sourceNodeID);
						printf("sx:a %d sensor named %d triggering!\n",kind,sourceNodeID);
					}
					else
					{
						//printf("sx:multi-sensor PIR no used!\n");
					}
				}

			}else if(zwaveCmdClass == COMMAND_CLASS_SENSOR_MULTILEVEL)
			{
				/* light->humidity->temperature */
				if(zwaveCmd == SENSOR_MULTILEVEL_REPORT)
				{
					sendResponseFlagToDongle(ACK);
					if(rxStatus == RECEIVE_STATUS_TYPE_SINGLE)/* 只要单播数据 */
					{
						zwaveCmdContent = data[IDX_DATA + 5];
						if(zwaveCmdContent == ZW_SEND_DATA_UNIT_TEM)
						{//温度
							printf("sx:multisensor named %d up temperature.\n",sourceNodeID);
						}else if(zwaveCmdContent == ZW_SEND_DATA_UNIT_LUM)
						{//光亮度
							printf("sx:multisensor named %d up light.\n",sourceNodeID);
							zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_OPEN;
						}else if(zwaveCmdContent == ZW_SEND_DATA_UNIT_HUM)
						{//湿度
							printf("sx:multisensor named %d up humidity.\n",sourceNodeID);
						}
					}
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_ALARM)// = 0x71 = COMMAND_CLASS_NOTIFICATION_V3
			{
				if(zwaveCmd == ALARM_REPORT)
				{
					/* 传感器报警上发
					 * 这种方式不是sensor默认的报警方式，需要设置
					 * 并且，传感器以这种方式上报的报警信息，当dongle处于组网或者撤网状态时是收不到的 */
					printf("sx:water sensor up!!!\n");
					sendResponseFlagToDongle(ACK);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_BASIC)
			{

			}else if(zwaveCmdClass == COMMAND_CLASS_SECURITY)
			{
				if(zwaveCmd == SECURITY_NONCE_REPORT)
				{
					sendResponseFlagToDongle(ACK);
					printf("sx:Yale report nonce!\n");
					printf("sx:the data is %d,%d,%d,%d,%d,%d,%d,%d!\n",data[8],data[9],data[10],
							data[11],data[12],data[13],data[14],data[15]);
					memset(zw_IV, 1, 16);
					memcpy(zw_IV + 8, data + 8, 8);
					/* 分析什么数据要加密 */
					ZW_fob_encryption_processing(sourceNodeID);
				}else if(zwaveCmd == SECURITY_NONCE_GET)
				{
					sendResponseFlagToDongle(ACK);
					printf("sx:lock wants nonce!!\n");
					ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  sourceNodeID,
							COMMAND_CLASS_SECURITY, SECURITY_NONCE_REPORT, 99);
				}else if(zwaveCmd == SECURITY_COMMANDS_SUPPORTED_REPORT)
				{
					printf("sx:Yale report support!\n");
					printf("sx:the data is %d,%d,%d,%d,%d,%d,%d,%d!\n",data[8],data[9],data[10],
							data[11],data[12],data[13],data[14],data[15]);
				}else if(zwaveCmd == SECURITY_MESSAGE_ENCAPSULATION)
				{
					printf("sx:success!!!!\n");
					sendResponseFlagToDongle(ACK);
					/* analysis message */
					memset(zw_IV, 1, 16);
					memcpy(zw_IV, data + 8, 8);
					printf("sx:@@warming open the door!\n the data is %d,%d,%d,%d,%d,%d,%d,%d!\n ",
							data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15]);
					/* the data length is data[0],do not include the 0x01!
					 *  zwaveDataLen    = data[IDX_DATA + 2];//5  is better
					 *  | sequence counter | CC | cmd | data |
					 *  当APPS开关门时，会受到0x71命令，CC_ALARM  0x05 ALARM_REPORT
					 *  新门锁组网成功后，0 98 7(0x98 --- COMMAND_CLASS_SECURITY)
					 *  */
					zwaveDataLen = zwaveDataLen - 19;
					for(i = 0 ; i < zwaveDataLen ; i++)
					{
						printf("%d\n",i);
						zw_text_in[i] = data[i + 16];
					}
					ZW_fob_encryption(zwaveDataLen, zw_Ke_new);
					printf("sx:the out data is ");
					for(i = 0 ; i < zwaveDataLen ; i++)
					{
						printf("%x ",zw_text_out[i]);
					}
					printf("!!!\n");

					if(zw_text_out[1] == COMMAND_CLASS_SECURITY)
					{
						/* 表示设置Kn成功！！进行关联！！ */
						zw_ofb_flag = 2;
						ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
								COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 5);
					}
					else
					{
						/* else */
						ZW_security_data_analysis(zwaveDataLen);
					}
#if 0
					/* BUG 目前收到信息就表示设置成功，就进行一次关联 */
					if(aaaa == 0)
					{
						aaaa =1;
						/* analysis message */
						memset(zw_IV, 1, 16);
						memcpy(zw_IV, data + 8, 8);
						printf("sx:@@warming open the door!\n the data is %d,%d,%d,%d,%d,%d,%d,%d!\n ",
								data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15]);
						/* the data length is data[0],do not include the 0x01!
						 *  zwaveDataLen    = data[IDX_DATA + 2];//5  is better
						 *  | sequence counter | CC | cmd | data |
						 *  当APPS开关门时，会受到0x71命令，CC_ALARM  0x05 ALARM_REPORT
						 *  新门锁组网成功后，0 98 7(0x98 --- COMMAND_CLASS_SECURITY)
						 *  */
						zwaveDataLen = zwaveDataLen - 19;
						for(i = 0 ; i < zwaveDataLen ; i++)
						{
							printf("%d\n",i);
							zw_text_in[i] = data[i + 16];
						}
						ZW_fob_encryption(zwaveDataLen, zw_Ke_new);
						printf("sx:the out data is ");
						for(i = 0 ; i < zwaveDataLen ; i++)
						{
							printf("%x ",zw_text_out[i]);
						}
						printf("!!!\n");
						/* 表示设置Kn成功！！进行关联！！ */
						zw_ofb_flag = 2;
						ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE,  SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
								COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 5);
					}
					else
					{
						/* analysis message */
						memset(zw_IV, 1, 16);
						memcpy(zw_IV, data + 8, 8);
						printf("sx:@@warming open the door!\n the data is %d,%d,%d,%d,%d,%d,%d,%d!\n ",
								data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15]);
						/* the data length is data[0],do not include the 0x01!
						 *  zwaveDataLen    = data[IDX_DATA + 2];//5  is better
						 *  | sequence counter | CC | cmd | data |
						 *  当APPS开关门时，会受到0x71命令，CC_ALARM  0x05 ALARM_REPORT
						 *  */
						zwaveDataLen = zwaveDataLen - 19;
						for(i = 0 ; i < zwaveDataLen ; i++)
						{
							printf("%d\n",i);
							zw_text_in[i] = data[i + 16];
						}
						ZW_fob_encryption(zwaveDataLen, zw_Ke_new);
						printf("sx:the out data is ");
						for(i = 0 ; i < zwaveDataLen ; i++)
						{
							printf("%x ",zw_text_out[i]);
						}
						printf("!!!\n");
						ZW_security_data_analysis(zwaveDataLen);
					}
#endif
				}else if(zwaveCmd == SECURITY_SCHEME_REPORT)
				{
					sendResponseFlagToDongle(ACK);
					printf("sx:Yale report scheme!\n");
					printf("sx:the data is %d!\n",data[8]);
					ZW_set_sensor(6);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_HAIL)
			{
	    		printf("sx:the sensor named %d hail!!\n",sourceNodeID);
				sendResponseFlagToDongle(ACK);
			}else if(zwaveCmdClass == COMMAND_CLASS_MARK)
			{

			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_BINARY)
			{
				if(zwaveCmd == SWITCH_BINARY_REPORT)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_ALL)
			{

			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_MULTILEVEL)
			{
	    		printf("sx:the sensor named %d report,the value is %d!!\n",sourceNodeID, data[8]);
				sendResponseFlagToDongle(ACK);
			}else if(zwaveCmdClass == COMMAND_CLASS_DOOR_LOCK)
			{
				if(zwaveCmd == DOOR_LOCK_OPERATION_REPORT)
				{
				}else if(zwaveCmd == DOOR_LOCK_CONFIGURATION_REPORT)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_DOOR_LOCK_LOGGING)
			{
				if(zwaveCmd == DOOR_LOCK_LOGGING_RECORDS_SUPPORTED_REPORT)
				{
				}else if(zwaveCmd == RECORD_REPORT)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_USER_CODE)
			{
				if(zwaveCmd == USER_CODE_REPORT)
				{
				}else if(zwaveCmd == USERS_NUMBER_REPORT)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_TIME_PARAMETERS)
			{
				if(zwaveCmd == TIME_PARAMETERS_REPORT)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_SCENE_ACTIVATION)
			{
				if(zwaveCmd == SCENE_ACTIVATION_SET)
				{
					sendResponseFlagToDongle(ACK);
					/* panic button come data! */
					printf("sx:the scene ID is %d!\n",data[8]);
					if(data[8] == 1)
					{
						/* short press */
						zw_ofb_flag = 3;/* APP open */
						/* door lock nodeID is 32! */
						SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4] = 32;

						ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
								COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 11);
					}
					else if(data[8] == 2)
					{
						/* panic button long press! */
						zw_ofb_flag = 4;/* APP close */
						/* door lock nodeID is 32! */
						SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4] = 32;

						ZW_send_command_to_controller(FUNC_ID_ZW_SEND_DATA, 0, NEED_RESPONSE, SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_ID[4],
								COMMAND_CLASS_SECURITY, SECURITY_NONCE_GET, 12);
					}
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_SCENE_ACTUATOR_CONF)
			{
				printf("sx:the the scene ID is %d,%d,%d!\n",data[8],data[9],data[10]);
			}
			else
			{
				sendResponseFlagToDongle(ACK);
			}
			break;

		/* sensor确认、sensor标识 */
		case FUNC_ID_ZW_APPLICATION_CONTROLLER_UPDATE:
			sourceNodeID = data[4];
			/* 告知APPS此传感器响应，请提示用户 */
			ZW_send_to_Child(ZW_CONFIRM_SENSOR, 0, sourceNodeID, 0);
			/* 重置sensor的时间 */
			for(i = 0 ; i < SlaveNodeInf->num ; i++)
			{
				if(SlaveNodeInf->node_inf[i].sensor_ID[4] == sourceNodeID)
				{
					clock_gettime(CLOCK_MONOTONIC, &current_time);
					SlaveNodeInf->node_inf[i].sensor_time = current_time.tv_sec;
					printf("sx:reset a sensor time,named %d\n",sourceNodeID);
				}
			}

			sendResponseFlagToDongle(ACK);
			break;

		default://不处理的命令直接应答即可
			sendResponseFlagToDongle(ACK);
			break;
	}//switch(serialCMD)
}

/**

     @brief IPU——>ZW controller
              完成信息向controller的写入

     @author sunxun

     @remark 2015-7-1

     @note

*/
int ZW_write(unsigned char *tx_buf,int length, int step, int flag)
{
	int ret;
	ret = write(zw_fd, tx_buf, length);
	if(ret <= 0)
	{
		printf("sx:write wrong-1!!!!!!!!\n");
		saveDataToLogStr("ZW_ERROR","send something failed!",strlen("send something failed!"));
		ZW_closeDongle();
		/* 回到主循环后，进行异常处理－重新打开dongle */
		//ZW_detect_port();
		//zw_controller_state = DONGLE_STATE_NO;
		return 0;
	}
	saveDataToLogBin("ZWAVESND",tx_buf,length);

	/* 开始记录执行情况，防止出现异常，出现了好重发 */
	zw_resend.step = step;
	zw_resend.flag = flag;
	clock_gettime(CLOCK_MONOTONIC, &zw_resend.time);
	printf("sx:step 0 is %ld\n",zw_resend.time.tv_sec);

	/* 每次向controller中写入数据后都要等待应答 */
	//zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_OPEN;
	return 0;
}

/**

     @brief 组织向controller中写入的信息

     @author sunxun

     @remark 2015-7-1

     @note

*/
void ZW_send_command_to_controller(unsigned char serial_cmd, unsigned char serial_cmd_mode, unsigned char flag, unsigned char node_ID,
		unsigned char zwaveCmdClass, unsigned char zwaveCmd, unsigned char func_ID)
{
	int index = 0;
	memset(txBuf, '\0', sizeof(txBuf));

	//初始化头部信息
	txBuf[index++] = SOF;
	txBuf[index++] = 0;
	txBuf[index++] = REQUEST;
	txBuf[index++] = serial_cmd;

	switch(serial_cmd)
	{
	    /* 获取controller的homeID */
	    case FUNC_ID_MEMORY_GET_ID:/* 不需要funcID */
			txBuf[1] = index -1;//数据长度
			//计算checksum时需要在长度部分，加上长度字段本身
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_TWO, ZW_SUCCESS);
	    	break;

	    case FUNC_ID_ZW_GET_VERSION:
			txBuf[1] = index -1;//数据长度
			//计算checksum时需要在长度部分，加上长度字段本身
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_TWO, ZW_GET_VERSION_FAILED);
	    	break;

	    /* @@500型模组没有此命令@@获取controller中的node列表，用于清理无效节点 */
		case FUNC_ID_SERIAL_API_GET_INIT_DATA:
			txBuf[1] = index -1;//数据长度
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_TWO, ZW_SUCCESS);
			break;

		/* 组网 */
		case FUNC_ID_ZW_ADD_NODE_TO_NETWORK:
			txBuf[index++] = serial_cmd_mode;
			txBuf[index++] = func_ID;
			txBuf[1] = index - 1;
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_TWO, ZW_ADD_SENSOR_FAILED);

			break;

		/* 正常删除sensor */
		case FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK:
			txBuf[index++] = serial_cmd_mode;
			txBuf[index++] = 1;
			txBuf[1] = index - 1;
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_TWO, ZW_DELETE_SENSOR_FAILED);
			break;

		/* 删除失败的传感器 */
		case FUNC_ID_ZW_REMOVE_FAILED_NODE_ID:
			txBuf[index++] = node_ID;
			txBuf[index++] = 1;/* func_ID */
			txBuf[1] = index -1;//数据长度
			//计算checksum时需要在长度部分，加上长度字段本身
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_FORCE_DELETE_FAILED);
			break;

		/* 判断sensor是否为失效sensor */
		case FUNC_ID_ZW_IS_FAILED_NODE_ID:
			txBuf[index++] = node_ID;
			txBuf[1] = index -1;//数据长度
			//计算checksum时需要在长度部分，加上长度字段本身
			txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
			ZW_write(txBuf, index, RECEIVE_STEP_TWO, ZW_SUCCESS);
			break;

		/* 透传指令，命令类的使用 */
		case FUNC_ID_ZW_SEND_DATA:
			txBuf[index++] = node_ID;/* !!!!!! */

			if(zwaveCmdClass == COMMAND_CLASS_MANUFACTURER_SPECIFIC)
			{
				if(zwaveCmd == MANUFACTURER_SPECIFIC_GET)/* 传感器专属特性 */
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_FOUR, ZW_CONFIGURE_SENSOR_FAILED);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_ASSOCIATION)
			{
				if(zwaveCmd == ASSOCIATION_SET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE + ZW_SEND_DATA_SIZE_TWO;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 1;/* group 1 */
					txBuf[index++] = 1;/* controllerID */
					//txBuf[index++] = node_ID;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x01
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_BATTERY)
			{
				if(zwaveCmd == BATTERY_GET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x04
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_SUCCESS);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_CONFIGURATION)
			{
				if(zwaveCmd == CONFIGURATION_SET)
				{
					/* 测试配置灯泡可以远处控制 */
					if(func_ID == 0x24)
					{
						txBuf[index++] = (ZW_SEND_COMMAND_HEADER_LEN + ZW_SEND_DATA_SIZE_ONE);
						txBuf[index++] = zwaveCmdClass;
						txBuf[index++] = zwaveCmd;
						txBuf[index++] = 34;
						txBuf[index++] = ZW_SEND_DATA_SIZE_ONE;
						txBuf[index++] = 1;
						txBuf[index++] = txOptions;
						txBuf[index++] = func_ID;//func_ID
						txBuf[1] = index -1;//数据长度
						//计算checksum时需要在长度部分，加上长度字段本身
						txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
						ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
					}

					if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 0x02)/* kind 修改 */
					{
						if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag == ZW_MULTI_SENSOR_UPLOARD_KIND)
						{
							txBuf[index++] = ZW_SEND_COMMAND_HEADER_LEN + ZW_SEND_DATA_SIZE_FOUR;
							txBuf[index++] = zwaveCmdClass;
							txBuf[index++] = zwaveCmd;
							txBuf[index++] = ZW_MULTISENSOR_UPLOAD_INFO_PN101;
							txBuf[index++] = ZW_SEND_DATA_SIZE_FOUR;
							txBuf[index++] = 0;
							txBuf[index++] = 0;
							txBuf[index++] = 0;
							txBuf[index++] = ZW_MULTISENSOR_LUMINANCE_UPLOAD | ZW_MULTISENSOR_HUMIDITY_UPLOAD | ZW_MULTISENSOR_TEMPERATURE_UPLOAD;
							txBuf[index++] = txOptions;
							txBuf[index++] = func_ID;//func_ID
							txBuf[1] = index -1;//数据长度
							//计算checksum时需要在长度部分，加上长度字段本身
							txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
							ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
						}else if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_flag == ZW_MULTI_SENSOR_PIR_UPLOARD_INTERVAL)
						{
							txBuf[index++] = (ZW_SEND_COMMAND_HEADER_LEN + ZW_SEND_DATA_SIZE_TWO);
							txBuf[index++] = zwaveCmdClass;
							txBuf[index++] = zwaveCmd;
							txBuf[index++] = ZW_MULTISENSOR_PIR_OFF_GOSLEEPTIME_PN;
							txBuf[index++] = ZW_SEND_DATA_SIZE_TWO;
							txBuf[index++] = ZW_MULTISENSOR_PIR_OFF_GOSLEEPTIME_MSB;//pirSleepTime[0];
							txBuf[index++] = ZW_MULTISENSOR_PIR_OFF_GOSLEEPTIME_LSB;//pirSleepTime[1];
							txBuf[index++] = txOptions;
							txBuf[index++] = func_ID;//func_ID
							txBuf[1] = index -1;//数据长度
							//计算checksum时需要在长度部分，加上长度字段本身
							txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
							ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
						}
					}else if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 0x04)
					{
						txBuf[index++] = (ZW_SEND_COMMAND_HEADER_LEN + ZW_SEND_DATA_SIZE_TWO);
						txBuf[index++] = zwaveCmdClass;
						txBuf[index++] = zwaveCmd;
						txBuf[index++] = 2;
						txBuf[index++] = 1;
						txBuf[index++] = 0xFF;//pirSleepTime[1];
						txBuf[index++] = txOptions;
						txBuf[index++] = func_ID;//func_ID
						txBuf[1] = index -1;//数据长度
						//计算checksum时需要在长度部分，加上长度字段本身
						txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
						ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
					}else if(SlaveNodeInf->node_inf[zw_set_sensor_number].sensor_kind == 0x06)
					{
						txBuf[index++] = (ZW_SEND_COMMAND_HEADER_LEN + 1);
						txBuf[index++] = zwaveCmdClass;
						txBuf[index++] = zwaveCmd;
						txBuf[index++] = 250;
						txBuf[index++] = 1;
						txBuf[index++] = 1;
						txBuf[index++] = txOptions;
						txBuf[index++] = func_ID;//func_ID
						txBuf[1] = index -1;//数据长度
						//计算checksum时需要在长度部分，加上长度字段本身
						txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
						ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
					}/* 其他种类的sensor */
/* 其他种类的sensor */
#if 0
					if(func_ID == 54)//设置多合一传感器红外触发后多久sleep,15s触发
					{
						txBuf[index++] = (ZW_SET_SENSOR_COMMAND_HEADER_LEN + PN_DATA_SIZE_TWO);
						txBuf[index++] = zwaveCmdClass;
						txBuf[index++] = zwaveCmd;
						txBuf[index++] = ZW_MULTISENSOR_PIR_OFF_GOSLEEPTIME_PN;
						txBuf[index++] = PN_DATA_SIZE_TWO;
						txBuf[index++] = ZW_MULTISENSOR_PIR_OFF_GOSLEEPTIME_MSB;//pirSleepTime[0];
						txBuf[index++] = ZW_MULTISENSOR_PIR_OFF_GOSLEEPTIME_LSB;//pirSleepTime[1];
						txBuf[index++] = txOptions;
						txBuf[index++] = 54;//func_ID
						txBuf[1] = index -1;//数据长度
						//计算checksum时需要在长度部分，加上长度字段本身
						txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
						ZW_write(txBuf, index, node_ID, func_ID);
					}else if(func_ID == 55)//设置多合一上报信息种类，不包括电量
					{
						txBuf[index++] = (ZW_SET_SENSOR_COMMAND_HEADER_LEN + PN_DATA_SIZE_FOUR);
						txBuf[index++] = zwaveCmdClass;
						txBuf[index++] = zwaveCmd;
						txBuf[index++] = ZW_MULTISENSOR_UPLOAD_INFO_PN101;
						txBuf[index++] = PN_DATA_SIZE_FOUR;
						txBuf[index++] = 0;
						txBuf[index++] = 0;
						txBuf[index++] = 0;
						txBuf[index++] = ZW_MULTISENSOR_LUMINANCE_UPLOAD | ZW_MULTISENSOR_HUMIDITY_UPLOAD | ZW_MULTISENSOR_TEMPERATURE_UPLOAD;
						txBuf[index++] = txOptions;
						txBuf[index++] = 55;//func_ID
						txBuf[1] = index -1;//数据长度
						//计算checksum时需要在长度部分，加上长度字段本身
						txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
						ZW_write(txBuf, index, node_ID, func_ID);
					}else if(func_ID == 56)//设置多合一上报信息时间间隔，这里默认值是12min
					{

					}else if(func_ID == 58)
					{
						txBuf[index++] = (ZW_SET_SENSOR_COMMAND_HEADER_LEN + PN_DATA_SIZE_ONE);
						txBuf[index++] = zwaveCmdClass;
						txBuf[index++] = zwaveCmd;
						txBuf[index++] = ZW_MULTISENSOR_PIR_STATUS_PN;
						txBuf[index++] = PN_DATA_SIZE_ONE;
						txBuf[index++] = ZW_MULTISENSOR_PIR_SEND_BY_BR;
						txBuf[index++] = txOptions;
						txBuf[index++] = 58;
						txBuf[1] = index -1;//数据长度
						//计算checksum时需要在长度部分，加上长度字段本身
						txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
						ZW_write(txBuf, index, node_ID, func_ID);
					}
#endif
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_WAKE_UP)
			{
				if(zwaveCmd == WAKE_UP_INTERVAL_SET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE + ZW_SEND_DATA_SIZE_FOUR;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 0;
					txBuf[index++] = 0;
					txBuf[index++] = 0xfe;//time
					txBuf[index++] = 0x01;//controller来接收数据！！
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x02
					txBuf[1] = index -1;//数据长度
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
				}else if(zwaveCmd == WAKE_UP_NO_MORE_INFORMATION)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x05
					txBuf[1] = index -1;//数据长度
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));//..
					ZW_write(txBuf, index, node_ID, func_ID);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_VERSION)
			{
				/* 用来确定是不是失效节点 */
				if(zwaveCmd == VERSION_COMMAND_CLASS_GET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE + ZW_SEND_DATA_SIZE_ONE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = COMMAND_CLASS_MANUFACTURER_SPECIFIC;//class cmd
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_FORCE_DELETE_FAILED);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_BASIC)
			{

			}else if(zwaveCmdClass == COMMAND_CLASS_ALARM)// = 0x71 = COMMAND_CLASS_NOTIFICATION_V3
			{

			}else if(zwaveCmdClass == COMMAND_CLASS_SECURITY)
			{
				if(zwaveCmd == SECURITY_COMMANDS_SUPPORTED_GET)
				{
					printf("sx:Yale door lock send support ok!\n");
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x01
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_OPERATE_SENSOR_FAILED);
				}else if(zwaveCmd == SECURITY_NONCE_GET)
				{
					printf("sx:IPU send nonce_get to Yale!\n");
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_OPERATE_SENSOR_FAILED);
				}else if(zwaveCmd == SECURITY_NONCE_REPORT)
				{
					printf("sx:IPU send nonce to Yale!\n");
					txBuf[index++] = ZW_SEND_COMMAND_BASE + 8;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 1;
					txBuf[index++] = 1;
					txBuf[index++] = 1;
					txBuf[index++] = 1;
					txBuf[index++] = 1;
					txBuf[index++] = 1;
					txBuf[index++] = 1;
					txBuf[index++] = 1;

					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x01
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_OPERATE_SENSOR_FAILED);
				}else if(zwaveCmd == SECURITY_SCHEME_GET)
				{
					printf("sx:IPU send scheme ok!\n");
					txBuf[index++] = ZW_SEND_COMMAND_BASE + ZW_SEND_DATA_SIZE_ONE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 0;/* 规定模式 */
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_OPERATE_SENSOR_FAILED);
				}else if(zwaveCmd == SECURITY_MESSAGE_ENCAPSULATION)
				{
					printf("sx:IPU send encapsulation ok!\n");
					txBuf[index++] = ZW_SEND_COMMAND_BASE + 17 + serial_cmd_mode;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 0x01;/* send_nonce */
					txBuf[index++] = 0x01;
					txBuf[index++] = 0x01;
					txBuf[index++] = 0x01;
					txBuf[index++] = 0x01;
					txBuf[index++] = 0x01;
					txBuf[index++] = 0x01;
					txBuf[index++] = 0x01;
					/* 一下为加密数据，原始数据为0，0x98, 0x06
					 * serial_cmd_mode 为加密数据*/
					memcpy(txBuf + index, zw_text_out, serial_cmd_mode);
					index = index + serial_cmd_mode;
					txBuf[index++] = zw_IV[8];/* Receiver’s nonce Identifier */
					memcpy(txBuf + index, zw_AE, 8);
					index = index + 8;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x01
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_OPERATE_SENSOR_FAILED);
				}else if(zwaveCmd == SECURITY_MESSAGE_ENCAPSULATION_NONCE_GET)
				{

				}else if(zwaveCmd == NETWORK_KEY_SET)
				{
					/* 发送加密数据！！ */

				}
			}else if(zwaveCmdClass == COMMAND_CLASS_HAIL)
			{
				txBuf[index++] = ZW_SEND_COMMAND_BASE;
				txBuf[index++] = zwaveCmdClass;//HAIL
				txBuf[index++] = zwaveCmd;
				txBuf[index++] = txOptions;
				txBuf[index++] = func_ID;
				txBuf[1] = index -1;
				txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
				ZW_write(txBuf, index, 0, ZW_SUCCESS);
			}else if(zwaveCmdClass == COMMAND_CLASS_MARK)
			{

			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_BINARY)
			{
				if(zwaveCmd == SWITCH_BINARY_SET)
				{

				}else if(zwaveCmd == SWITCH_BINARY_GET)
				{

				}
			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_ALL)
			{
				if(zwaveCmd == SWITCH_ALL_ON)
				{
					txBuf[index++] = ZW_SEND_DATA_SIZE_TWO;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//func_ID
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
				}else if(zwaveCmd == SWITCH_ALL_OFF)
				{/* 多余 */
					txBuf[index++] = ZW_SEND_DATA_SIZE_TWO;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//func_ID
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_CONFIGURE_SENSOR_FAILED);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_MULTILEVEL)
			{
				if(zwaveCmd == SWITCH_MULTILEVEL_GET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_SUCCESS);
				}else if(zwaveCmd == SWITCH_MULTILEVEL_SET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = serial_cmd_mode;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;//0x04
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_SUCCESS);
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_DOOR_LOCK)
			{
				if(zwaveCmd == DOOR_LOCK_OPERATION_SET)
				{

				}else if(zwaveCmd == DOOR_LOCK_OPERATION_GET)
				{

				}else if(zwaveCmd == DOOR_LOCK_CONFIGURATION_SET)
				{

				}else if(zwaveCmd == DOOR_LOCK_CONFIGURATION_GET)
				{

				}
			}else if(zwaveCmdClass == COMMAND_CLASS_DOOR_LOCK_LOGGING)
			{
				if(zwaveCmd == DOOR_LOCK_LOGGING_RECORDS_SUPPORTED_GET)
				{

				}else if(zwaveCmd == RECORD_GET)
				{

				}
			}else if(zwaveCmdClass == COMMAND_CLASS_USER_CODE)
			{
				if(zwaveCmd == USER_CODE_SET)
				{
				}else if(zwaveCmd == USER_CODE_GET)
				{
				}else if(zwaveCmd == USERS_NUMBER_GET)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_TIME_PARAMETERS)
			{
				if(zwaveCmd == TIME_PARAMETERS_SET)
				{
				}else if(zwaveCmd == TIME_PARAMETERS_GET)
				{
				}
			}else if(zwaveCmdClass == COMMAND_CLASS_SWITCH_COLOR)
			{
				if(zwaveCmd == SWITCH_COLOR_SET)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE + 3;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 6;
					txBuf[index++] = 2;//r
					txBuf[index++] = zw_bulb_color[0];
					txBuf[index++] = 3;//g
					txBuf[index++] = zw_bulb_color[1];
					txBuf[index++] = 4;//b
					txBuf[index++] = zw_bulb_color[2];
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_SUCCESS);
				}else if(zwaveCmd == SWITCH_COLOR_START_LEVEL_CHANGE)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE + 3;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = serial_cmd_mode;//0   0x40
					txBuf[index++] = 2;//r
					txBuf[index++] = 0;
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_SUCCESS);
				}else if(zwaveCmd == SWITCH_COLOR_STOP_LEVEL_CHANGE)
				{
					txBuf[index++] = ZW_SEND_COMMAND_BASE + 1;
					txBuf[index++] = zwaveCmdClass;
					txBuf[index++] = zwaveCmd;
					txBuf[index++] = 2;//r
					txBuf[index++] = txOptions;
					txBuf[index++] = func_ID;
					txBuf[1] = index -1;//数据长度
					//计算checksum时需要在长度部分，加上长度字段本身
					txBuf[index++] = ZW_CalculateChecksum((txBuf + 1),(txBuf[1] + 1));
					ZW_write(txBuf, index, RECEIVE_STEP_THREE, ZW_SUCCESS);
				}
			}

			break;
	}
}

/**

     @brief 主函数

     @author sunxun

     @remark 2015-7-1

     @note

*/
int * ZW_Main()
{
	fd_set rset;
	struct timeval tv;

	/* 创建共享队列和完成参数的初始化 */
	ZW_ModuleInit();

	/* 线程同步 */
	ZW_threadSynchronization();

	while(1)
	{
		/* 判断donglede的插入或者拔出 */
		//ZW_detect_port();

		/* 开机打开流程 */
		if(zw_start_step == STEP_OPEN_CONTROLLER)
		{
			/* 如果打开port失败将会循环继续打开 --no!*/
			ZW_open_port();
		}else if(zw_start_step == STEP_GET_HOMEID_FROM_CONTROLLER)
		{
			zw_start_step = STEP_STORE_HOMEID;
			ZW_send_command_to_controller(FUNC_ID_MEMORY_GET_ID, 0, NEED_RESPONSE, 0, 0, 0, 1);
		}else if(zw_start_step == STEP_OPEN_SUCCESS)
		{
			zw_start_step = STEP_FINISH;
			zw_controller_state = DONGLE_STATE_OK;
			ZWave_state = 1;
		}

		/* 从子进程获取命令 */
		ZW_analyse_Msg_from_Child();

		/* 异常处理,ZW controller所处的状态
		if((zw_start_step == STEP_FINISH) && (zw_controller_state == DONGLE_STATE_NO))
		{
			printf("sx:main-close!\n");
			ZW_closeDongle();
			continue;
		}*/

		if(zw_start_step == STEP_OPEN_CONTROLLER)
		{
			/* *******************************
			 * dongle没有插入不会继续执行
			 * 不能执行select
			 * ******************************/
		}
		else
		{

			/* IPU检测sensor的在线/离线，同时，判断命令执行是否超时，超时要重发 */
			ZW_judge_sensor_online();

			/* 获取sensor电量操作 */
			ZW_get_sensor_battery();

			FD_ZERO(&rset);
			FD_SET(zw_fd, &rset);
			tv.tv_sec = 1; /* 文当中规定的，不能改？ */
			tv.tv_usec = 500000;
			while(1)
			{
				/* controller处于组网模式或者撤网模式时，1min没有响应，退出！ */
				if(zw_controller_state == DONGLE_STATE_ADDING_NODE)
				{
					clock_gettime(CLOCK_MONOTONIC, &current_time);
					if((current_time.tv_sec - zw_busying_time.tv_sec) > ZW_CONTROLLER_BUSYING_STATE)
					{
						ZW_send_command_to_controller(FUNC_ID_ZW_ADD_NODE_TO_NETWORK, ADD_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 2);
						zw_busying_time.tv_sec = current_time.tv_sec;

						/* 告诉APPS，1min之内没有新sensor接入,需要吗？？？ */
						ZW_send_to_Child(ZW_NEW_SENSOR_UPLOARD, ZW_NO_SENSOR_JOIN, 0, 0);
					}
				}else if(zw_controller_state == DONGLE_STATE_REMOVING_NODE)
				{
					clock_gettime(CLOCK_MONOTONIC, &current_time);
					if((current_time.tv_sec - zw_busying_time.tv_sec) > ZW_CONTROLLER_BUSYING_STATE)
					{
						ZW_send_command_to_controller(FUNC_ID_ZW_REMOVE_NODE_FROM_NETWORK, REMOVE_NODE_STOP, NEED_RESPONSE, 0, 0, 0, 4);
						zw_busying_time.tv_sec = current_time.tv_sec;

						/* 反馈给APPS无sensor删除或者清除 */
						if(zw_clear_mode == ZW_OPEN_MODE)
						{
							ZW_send_to_Child(ZW_CLEAR_SENSOR_UPLOARD, ZW_NO_SENSOR_CLEAR, 0, 0);
						}
						else
						{
							memset(zw_delete_sensor.delete_sensor, 1, 5);
							ZW_send_to_Child(ZW_DELETE_SENSOR_UPLOARD, ZW_NO_SENSOR_DELETE, 0, 0);
						}
						printf("@@@@@:there is no seneor delete!\n");
					}
				}

				/* 等待controller的响应 */
				switch(select(zw_fd + 1, &rset, NULL, NULL, &tv))
				{
				    case 0:
				    	/* 退出加速模式 */
			    		zw_accelerate_to_capture = ZW_ACCELERATE_TO_CAPTURE_CLOSE;
			    		break;
				    case -1:
				    	ZW_closeDongle();
				    	printf("sx:select error!\n");
					    saveDataToLogStr("ZWAVESELECTERROR",strerror(errno),strlen(strerror(errno)));
				    	break;
				    default:
				 	   if(FD_ISSET(zw_fd, &rset))
				 	   {
				 		   /* 接收数据 */
				 		  ZW_accept_data_from_controller();
				 	   }
				 	   break;
				}//select+swicth

				if(zw_accelerate_to_capture == ZW_ACCELERATE_TO_CAPTURE_OPEN)
				{
					printf("sx:++++++++++++++++++++++++++++++++!\n");
					FD_ZERO(&rset);
					FD_SET(zw_fd, &rset);
					tv.tv_sec = 0;
					tv.tv_usec = 100000;
				}
				else
				{
					/* 正常模式 */
					break;
				}
			}//while(1)
		}//if
	}//while(1)
	return 0;
}

/**

     @brief 线程启动函数

     @author sunxun

     @remark 2015-7-1

     @note

*/
int Create_ZW_Thread()
{
	int ret;
	ret = thread_start(ZW_Main);
	return ret;
}
