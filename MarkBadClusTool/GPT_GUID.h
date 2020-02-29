#pragma once

#ifndef ____GPT__GUID_H____
#define ____GPT__GUID_H____

#include <windows.h>
#include "layout_mbr.h"

typedef  BYTE uint8_t;
typedef unsigned long long  uint64_t;
typedef DWORD uint32_t;

struct gpt_header //GPT表头512字节 4Kn硬盘请另请高明
{
	uint8_t signature[8];//无符号8字节签名
	uint8_t version[4];//4字节版本号
	uint8_t headersize[4];//GPT表头大小
	uint8_t headercrc32[4];//GPT表头的CRC-32校验
	uint8_t reserve[4];//保留，为0
	uint8_t header_lba[8];//表头的扇区号
	uint8_t backup_lba[8];//备份表头的扇区号
	uint8_t pation_first_lba[8];//GPT分区起始扇区号
	uint8_t pation_last_lba[8];//GPT分区结束扇区号
	uint8_t guid[16];//磁盘的GUID
	uint8_t pation_table_first[8];//分区表起始扇区号
	uint8_t pation_table_entries[4];//分区表总项数
	uint8_t pation_table_size[4];//单个分区表占用字节数
	uint8_t pation_table_crc[4];//分区表的CRC校验
	uint8_t notuse[420];//保留的420字节
};//GPT表头结构

struct partition_table//分区表是128字节
{
	uint8_t pationtype[16];//分区类型，全0是未使用
	uint8_t pationid[16];//分区唯一标识符
	uint8_t pation_start[8];//分区起始扇区号
	uint8_t pation_end[8];//分区结束扇区号
	uint8_t pation_attr[8];//分区属性标志,区分分区是什么类型的
	uint8_t pation_name[72];//分区名
};

struct MBR_disk_entry
{
	uint8_t bootflag;//引导标志
	uint8_t citouhao;//磁头号
	uint8_t shanquhao;//扇区号
	uint8_t zhumianhao;//柱面号
	uint8_t disk_flag;//分区类型标志，如果是05H/0FH是扩展分区；GPT是0xEE
	uint8_t someinfo[3];
	uint8_t relative[4];//相对起始扇区
	uint8_t sectors[4];//总扇区数
};

struct PMBR    //不是真正的MBR
{
	uint8_t boot_code[446];//引导代码
	MBR_disk_entry pation_table_entry[4];//4个分区表，每个16字节,只有一个分区表有内容，对应的标志是0xEE，
	uint8_t endflag[2];//55AA
};

//PartitionType
uint8_t PARTITION_BASIC_DATA_GUID[16] = { 0xeb,0xd0,0xa0,0xa2,0xb9,0xe5,0x44,0x33,
0x87,0xc0,0x68,0xb6,0xb7,0x26,0x99,0xc7 };
uint8_t PARTITION_SYSTEM_GUID[16] = { 0xc1,0x2a,0x73,28,0xf8,0x1f,0x11,0xd2,0xba,
0x4b,0x00,0xa0,0xc9,0x3e,0xc9,0x3b };
uint8_t PARTITION_MSFT_RESERVED_GUID[16] = { 0xe3,0xc9,0xe3,0x16,0x0b,0x5c,0x4d,0xb8,
0x81,0x7d,0xf9,0x2d,0xf0,0x02,0x15,0xae };
uint8_t PARTITION_MSFT_RECOVERY_GUID[16] = { 0xde,0x94,0xbb,0xa4,0x06,0xd1,0x4d,0x40,0xa1,
0x6a,0xbf,0xd5,0x01,0x79,0xd6,0xac };
uint8_t PARTITION_ENTRY_UNUSED_GUID[16] = { 0 };
uint8_t * partitiontype[5] = { PARTITION_BASIC_DATA_GUID,PARTITION_SYSTEM_GUID ,
PARTITION_MSFT_RESERVED_GUID ,PARTITION_MSFT_RECOVERY_GUID,PARTITION_ENTRY_UNUSED_GUID };

const char * partition_type_info[] = { "这是一个基本数据分区","这是一个EFI系统分区","这是一个微软保留分区",
"这是一个微软恢复分区","这是一个空分区" };


//GPT表项的attributes bits的最高位，也就是最左边的1位，索引是[0]
//相与不为0说明置位了
uint64_t read_only = 0x1000000000000000;
uint64_t shadow_copy = 0x2000000000000000;//其它分区的影像0x200000....
uint64_t hide_partition = 0x4000000000000000; //Hides a partition's volume.
uint64_t no_letter = 0x8000000000000000;//不自动挂载，没有盘符的
uint64_t EFI_hide = 0x0000000000000010;//EFI不可见分区
uint64_t system_partition = 0x0000000000000001;//系统分区
uint64_t attribute_bits[6] = { read_only,shadow_copy,hide_partition,no_letter,EFI_hide,system_partition };
const char * attribute_bits_info[] = { "这是一个只读分区","这是一个其它分区的shadow copy\n","这是一个隐藏分区",
"这是一个不自动挂载、不自动分配盘符的分区","这是一个EFI不可见分区",
"这是一个系统分区" };




uint32_t uint8to32(uint8_t fouruint8[4]) {
	return *(uint32_t*)fouruint8;
	//return((uint32_t)fouruint8[3] << 24) | ((uint32_t)fouruint8[2] << 16) | ((uint32_t)fouruint8[1] << 8) | ((uint32_t)fouruint8[0]);
}

uint64_t uint8to64(uint8_t fouruint8[8]) {
	return *(uint64_t*)fouruint8;
	//return((uint64_t)fouruint8[7] << 56) | ((uint64_t)fouruint8[6] << 48) | ((uint64_t)fouruint8[5] << 40) | ((uint64_t)fouruint8[4] << 32) |
	//((uint64_t)fouruint8[3] << 24) | ((uint64_t)fouruint8[2] << 16) | ((uint64_t)fouruint8[1] << 8) | ((uint64_t)fouruint8[0]);;
}

int compareuint8(uint8_t * a, uint8_t *b)
{
	if (sizeof(*a) != sizeof(*b))
		return 0;
	for (int i = 0; i < sizeof(*a); i++)
	{
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

void changeseqGUID(uint8_t *GUID, uint8_t *seqGUID)
{
	//最左边4位，是大端，转过来
	seqGUID[0] = GUID[3]; seqGUID[1] = GUID[2]; seqGUID[2] = GUID[1]; seqGUID[3] = GUID[0];
	//交叉顺序
	seqGUID[4] = GUID[5]; seqGUID[5] = GUID[4]; seqGUID[6] = GUID[7]; seqGUID[7] = GUID[6];
	//顺序
	for (int i = 8; i < 16; i++)
		seqGUID[i] = GUID[i];
}

void show_partion_name(uint8_t*beginchar, int length) {
	int j = 0;
	for (int i = 0; i < length; i++) {
		if (beginchar[i] == 0)
			j++;
		else
			j = 0;

		if (j > 2)
			return;//后面都是0
		else if (j == 0)
			printf("%c", beginchar[i]);
	}
}

void show_gpt_header(struct gpt_header* the_gpt_header) {
	printf("GPT头签名为:");
	for (int i = 0; i < 8; i++)
		printf("%c", the_gpt_header->signature[i]);
	printf("\n");

	printf("版本号为:");
	for (int i = 0; i < 4; i++)
		printf("%0X", the_gpt_header->version[i]);
	printf("\n");

	printf("GPT头大小为 %u 字节\n", uint8to32(the_gpt_header->headersize));

	printf("GPT头CRC校验值为:");
	for (int i = 0; i < 4; i++)
		printf("%0X", the_gpt_header->headercrc32[i]);
	printf("\n");

	printf("GPT表头起始扇区号为 %I64X\n", uint8to64(the_gpt_header->header_lba));
	//备份表头在最后一个EFI扇区，可以得知整个磁盘的大小，扇区数*512/1024/1024/1024
	printf("GPT备份表头扇区号为 %I64X\n", uint8to64(the_gpt_header->backup_lba));

	printf("GPT分区区域的起始扇区号为 %I64X\n", uint8to64(the_gpt_header->pation_first_lba));

	printf("GPT分区区域结束扇区号为 %I64X\n", uint8to64(the_gpt_header->pation_last_lba));

	printf("磁盘GUID为:");
	uint8_t GUID[16];
	changeseqGUID(the_gpt_header->guid, GUID);
	for (int i = 0; i < 16; i++)
	{
		printf("%0X", GUID[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			printf("-");
	}
	printf("\n");

	printf("GPT分区表起始扇区号为 %I64X\n", uint8to64(the_gpt_header->pation_table_first));

	printf("GPT分区表总项数为 %I32X\n", uint8to32(the_gpt_header->pation_table_entries));

	printf("每个分区表占用字节数为 %I32X\n", uint8to32(the_gpt_header->pation_table_size));

	printf("分区表CRC校验值为 %I32X\n", uint8to32(the_gpt_header->pation_table_crc));
}

void showPMBR(struct PMBR*the_pmbr)
{
	printf("引导标志为%X\n", the_pmbr->pation_table_entry[0].bootflag);
	printf("磁头号为%X\n", the_pmbr->pation_table_entry[0].citouhao);
	printf("扇区号为%X\n", the_pmbr->pation_table_entry[0].shanquhao);
	printf("柱面号为%X\n", the_pmbr->pation_table_entry[0].zhumianhao);
	printf("分区类型标志为 %X\n", the_pmbr->pation_table_entry[0].disk_flag);
	printf("第一个扇区为 %u\n", uint8to32(the_pmbr->pation_table_entry[0].relative));
	printf("扇区数为 %u\n", uint8to32(the_pmbr->pation_table_entry[0].sectors));
}

uint8_t show_partition_table(struct partition_table * the_partition_table)
{
	uint8_t GUID[16];
	printf("分区类型值为:");
	uint8_t flag = 0;
	changeseqGUID(the_partition_table->pationtype, GUID);
	for (int i = 0; i < 16; i++)
	{
		flag = flag | GUID[i];
		printf("%0X", GUID[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			printf("-");
	}
	printf("\n");
	for (int i = 0; i < 5; i++) {
		if (compareuint8(GUID, partitiontype[i]))
			printf("***%s***\n", partition_type_info[i]);
	}

	printf("分区GUID为:");
	changeseqGUID(the_partition_table->pationid, GUID);
	for (int i = 0; i < 16; i++)
	{
		printf("%0X", GUID[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			printf("-");
	}

	printf("\n该分区起始扇区号为%I64X\n", uint8to64(the_partition_table->pation_start));
	printf("该分区结束扇区号为%I64X\n", uint8to64(the_partition_table->pation_end));
	printf("该分区属性标志为%I64X\n", uint8to64(the_partition_table->pation_attr));
	uint64_t attr = uint8to64(the_partition_table->pation_attr);
	for (int i = 0; i < 6; i++)
	{
		if ((attr&attribute_bits[i]) != 0)
			printf("从attributes-bits中可知:%s\n", attribute_bits_info[i]);
	}
	printf("该分区名为:");
	show_partion_name(the_partition_table->pation_name, 72);
	uint64_t bytes = (uint8to64(the_partition_table->pation_end) - uint8to64(the_partition_table->pation_start)) * (uint64_t)512;
	double MB = bytes / 1024.0 / 1024.0;
	double GB = MB / 1024.0;
	printf("\n该分区大小为%I64X字节，%lf GB", bytes, GB);
	printf("\n\n\n");
	return flag;
}

int read_partition_table(struct gpt_header * the_gpt_header, HANDLE hDevice, ULONGLONG baseaddr)
{

	int entrynum = 0;
	DWORD dwCB;
	LARGE_INTEGER offset;
	partition_table the_partition_tables[4];
	ULONGLONG nextaddr = ((ULONGLONG)0 + (ULONGLONG)baseaddr) *(ULONGLONG)512;
	offset.QuadPart = nextaddr;//找到下一个要读取的地址
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//设置偏移准备读取
	//ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL);
	if (!ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL))
	{
		return 0;
	}
	int endflag = 1;
	int j = 0;//如果j=4，才重新读，因为某种限制，一次必须读512字节整数倍
	while (endflag > 0) {
		printf("\n第%d个分区表:\n", ++entrynum);
		if (j == 4)
		{
			nextaddr = nextaddr + (ULONGLONG)512;
			offset.QuadPart = nextaddr;//找到下一个要读取的地址
			SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//设置偏移准备读取
			//if (GetLastError())
			//{
			//	return 0;
			//}
			memset(&the_partition_tables, 0, 512);
			ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL);
			j = 0;
		}
		endflag = show_partition_table(&the_partition_tables[j]);
		j++;
	}
	return 1;
}

int trymain()
{
	DISK_GEOMETRY pdg;            // 保存磁盘参数的结构体
	HANDLE hDevice;               // 设备句柄
	BOOL bResult;                 // results flag
	DWORD junk;                   // discard resultscc

	int disk = 0;
	const char *diskname[] = { "\\\\.\\PhysicalDrive0" ,"\\\\.\\PhysicalDrive1" };
	printf("请输入要打开的硬盘号(一般为0，有2个硬盘可以输入0或1)\n");
	scanf("%d", &disk);
	if (disk != 0 && disk != 1)
	{
		disk = 0;
		printf("输入无效，打开磁盘0\n");
	}
	//通过CreateFile来获得设备的句柄
	hDevice = CreateFile(diskname[disk], // 设备名称，PhysicalDriveX表示打开第X个设备
		GENERIC_READ,                // no access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL);            // do not copy file attributes
	if (hDevice == INVALID_HANDLE_VALUE) //没能打开，可能是没有用管理员权限运行
	{
		printf("Creatfile error!May be no permission!ERROR_ACCESS_DENIED！\n");
		system("pause");
		return (FALSE);
	}

	//通过DeviceIoControl函数与设备进行IO
	bResult = DeviceIoControl(hDevice, // 设备的句柄
		IOCTL_DISK_GET_DRIVE_GEOMETRY, // 控制码，指明设备的类型
		NULL,
		0, // no input buffer
		&pdg,
		sizeof(pdg),
		&junk,                 // # bytes returned
		(LPOVERLAPPED)NULL); // synchronous I/O

	LARGE_INTEGER offset;//long long signed
	offset.QuadPart = (ULONGLONG)0 * (ULONGLONG)512;//0
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读PMBR
	if (GetLastError())
		printf("错误类型代号：%ld\n\n", GetLastError());//如果出错了

	DWORD dwCB;
	struct PMBR the_pmbr;
	//从这个位置开始读512字节PMBR
	//读取PMBR的512字节，里面的分区表第一项才有用，从1数，第5字节是0xEE
	//相对起始扇区值是GPT Header的位置
	BOOL bRet = ReadFile(hDevice, &the_pmbr, 512, &dwCB, NULL);
	printf("----------------读取PMBR部分:---------------\n");
	showPMBR(&the_pmbr);
	if (the_pmbr.pation_table_entry[0].disk_flag == 0xEE)//如果的确是GPT格式分区
	{
		printf("PMBR中分区表第一项的标志位为 0xEE，是GPT格式，跳转到%u扇区\n",
			uint8to32(the_pmbr.pation_table_entry[0].relative));
		printf("GPT表头在第%u扇区", uint8to32(the_pmbr.pation_table_entry[0].relative));
	}
	else {
		printf("PMBR中分区表第一项标志位为 %X，不是GPT格式，结束分析\n",
			the_pmbr.pation_table_entry[0].disk_flag);
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}


	//读取分析GPT Header
	//下一个要读取的线性地址=要读取的扇区号*512字节
	printf("\n\n----------------读取GPT Header部分:---------------\n\n");
	ULONGLONG nextaddr = (ULONGLONG)1 * (ULONGLONG)512;
	offset.QuadPart = nextaddr;//找到下一个要读取的地址
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//设置偏移准备读取
	if (GetLastError())
	{
		printf("读取GPT Header出错。错误类型代号：%ld\n\n", GetLastError());//如果出错了
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}
	//读取GPT Header
	gpt_header the_gpt_header;
	ReadFile(hDevice, &the_gpt_header, 512, &dwCB, NULL);
	show_gpt_header(&the_gpt_header);

	//读取主GPT分区表项，分区表项前16个字节如果全0，表示未用，后面都没有了，可以去读备份
	printf("\n\n-------------读取分区表项:-------------\n\n");
	ULONGLONG baseaddr = (ULONGLONG)uint8to64(the_gpt_header.pation_table_first);//GPT分区表起始位置
	if (!read_partition_table(&the_gpt_header, hDevice, baseaddr))//如果出错
	{
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}

	printf("\n\n---------------读取备份的GPT Header:---------------\n\n");
	nextaddr = (ULONGLONG)uint8to32(the_gpt_header.backup_lba)*(ULONGLONG)512;
	offset.QuadPart = nextaddr;//找到下一个要读取的地址
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//设置偏移准备读取
	if (GetLastError())
	{
		printf("读取备份GPT Header出错。错误类型代号：%ld\n\n", GetLastError());//如果出错了
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}
	//读取备份GPT Header
	gpt_header backup_gpt_header;
	ReadFile(hDevice, &backup_gpt_header, 512, &dwCB, NULL);
	show_gpt_header(&backup_gpt_header);

	//读取备份GPT分区表项，分区表项前16个字节如果全0，表示未用，后面都没有了，可以去读备份
	printf("\n\n-------------读取备份分区表项:-------------\n\n");
	baseaddr = (ULONGLONG)uint8to64(backup_gpt_header.pation_table_first);//GPT分区表起始位置
	if (!read_partition_table(&backup_gpt_header, hDevice, baseaddr))//如果出错
	{
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}

	printf("\n\n这块硬盘大小为 %lf GB\n", (double)uint8to64(the_gpt_header.backup_lba) * 512 / 1024 / 1024 / 1024);

	CloseHandle(hDevice);
	system("pause");
	return 0;
}

#endif
