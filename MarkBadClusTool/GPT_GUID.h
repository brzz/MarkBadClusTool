#pragma once

#ifndef ____GPT__GUID_H____
#define ____GPT__GUID_H____

#include <windows.h>
#include "layout_mbr.h"

typedef  BYTE uint8_t;
typedef unsigned long long  uint64_t;
typedef DWORD uint32_t;

struct gpt_header //GPT��ͷ512�ֽ� 4KnӲ�����������
{
	uint8_t signature[8];//�޷���8�ֽ�ǩ��
	uint8_t version[4];//4�ֽڰ汾��
	uint8_t headersize[4];//GPT��ͷ��С
	uint8_t headercrc32[4];//GPT��ͷ��CRC-32У��
	uint8_t reserve[4];//������Ϊ0
	uint8_t header_lba[8];//��ͷ��������
	uint8_t backup_lba[8];//���ݱ�ͷ��������
	uint8_t pation_first_lba[8];//GPT������ʼ������
	uint8_t pation_last_lba[8];//GPT��������������
	uint8_t guid[16];//���̵�GUID
	uint8_t pation_table_first[8];//��������ʼ������
	uint8_t pation_table_entries[4];//������������
	uint8_t pation_table_size[4];//����������ռ���ֽ���
	uint8_t pation_table_crc[4];//�������CRCУ��
	uint8_t notuse[420];//������420�ֽ�
};//GPT��ͷ�ṹ

struct partition_table//��������128�ֽ�
{
	uint8_t pationtype[16];//�������ͣ�ȫ0��δʹ��
	uint8_t pationid[16];//����Ψһ��ʶ��
	uint8_t pation_start[8];//������ʼ������
	uint8_t pation_end[8];//��������������
	uint8_t pation_attr[8];//�������Ա�־,���ַ�����ʲô���͵�
	uint8_t pation_name[72];//������
};

struct MBR_disk_entry
{
	uint8_t bootflag;//������־
	uint8_t citouhao;//��ͷ��
	uint8_t shanquhao;//������
	uint8_t zhumianhao;//�����
	uint8_t disk_flag;//�������ͱ�־�������05H/0FH����չ������GPT��0xEE
	uint8_t someinfo[3];
	uint8_t relative[4];//�����ʼ����
	uint8_t sectors[4];//��������
};

struct PMBR    //����������MBR
{
	uint8_t boot_code[446];//��������
	MBR_disk_entry pation_table_entry[4];//4��������ÿ��16�ֽ�,ֻ��һ�������������ݣ���Ӧ�ı�־��0xEE��
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

const char * partition_type_info[] = { "����һ���������ݷ���","����һ��EFIϵͳ����","����һ��΢��������",
"����һ��΢��ָ�����","����һ���շ���" };


//GPT�����attributes bits�����λ��Ҳ��������ߵ�1λ��������[0]
//���벻Ϊ0˵����λ��
uint64_t read_only = 0x1000000000000000;
uint64_t shadow_copy = 0x2000000000000000;//����������Ӱ��0x200000....
uint64_t hide_partition = 0x4000000000000000; //Hides a partition's volume.
uint64_t no_letter = 0x8000000000000000;//���Զ����أ�û���̷���
uint64_t EFI_hide = 0x0000000000000010;//EFI���ɼ�����
uint64_t system_partition = 0x0000000000000001;//ϵͳ����
uint64_t attribute_bits[6] = { read_only,shadow_copy,hide_partition,no_letter,EFI_hide,system_partition };
const char * attribute_bits_info[] = { "����һ��ֻ������","����һ������������shadow copy\n","����һ�����ط���",
"����һ�����Զ����ء����Զ������̷��ķ���","����һ��EFI���ɼ�����",
"����һ��ϵͳ����" };




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
	//�����4λ���Ǵ�ˣ�ת����
	seqGUID[0] = GUID[3]; seqGUID[1] = GUID[2]; seqGUID[2] = GUID[1]; seqGUID[3] = GUID[0];
	//����˳��
	seqGUID[4] = GUID[5]; seqGUID[5] = GUID[4]; seqGUID[6] = GUID[7]; seqGUID[7] = GUID[6];
	//˳��
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
			return;//���涼��0
		else if (j == 0)
			printf("%c", beginchar[i]);
	}
}

void show_gpt_header(struct gpt_header* the_gpt_header) {
	printf("GPTͷǩ��Ϊ:");
	for (int i = 0; i < 8; i++)
		printf("%c", the_gpt_header->signature[i]);
	printf("\n");

	printf("�汾��Ϊ:");
	for (int i = 0; i < 4; i++)
		printf("%0X", the_gpt_header->version[i]);
	printf("\n");

	printf("GPTͷ��СΪ %u �ֽ�\n", uint8to32(the_gpt_header->headersize));

	printf("GPTͷCRCУ��ֵΪ:");
	for (int i = 0; i < 4; i++)
		printf("%0X", the_gpt_header->headercrc32[i]);
	printf("\n");

	printf("GPT��ͷ��ʼ������Ϊ %I64X\n", uint8to64(the_gpt_header->header_lba));
	//���ݱ�ͷ�����һ��EFI���������Ե�֪�������̵Ĵ�С��������*512/1024/1024/1024
	printf("GPT���ݱ�ͷ������Ϊ %I64X\n", uint8to64(the_gpt_header->backup_lba));

	printf("GPT�����������ʼ������Ϊ %I64X\n", uint8to64(the_gpt_header->pation_first_lba));

	printf("GPT�����������������Ϊ %I64X\n", uint8to64(the_gpt_header->pation_last_lba));

	printf("����GUIDΪ:");
	uint8_t GUID[16];
	changeseqGUID(the_gpt_header->guid, GUID);
	for (int i = 0; i < 16; i++)
	{
		printf("%0X", GUID[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			printf("-");
	}
	printf("\n");

	printf("GPT��������ʼ������Ϊ %I64X\n", uint8to64(the_gpt_header->pation_table_first));

	printf("GPT������������Ϊ %I32X\n", uint8to32(the_gpt_header->pation_table_entries));

	printf("ÿ��������ռ���ֽ���Ϊ %I32X\n", uint8to32(the_gpt_header->pation_table_size));

	printf("������CRCУ��ֵΪ %I32X\n", uint8to32(the_gpt_header->pation_table_crc));
}

void showPMBR(struct PMBR*the_pmbr)
{
	printf("������־Ϊ%X\n", the_pmbr->pation_table_entry[0].bootflag);
	printf("��ͷ��Ϊ%X\n", the_pmbr->pation_table_entry[0].citouhao);
	printf("������Ϊ%X\n", the_pmbr->pation_table_entry[0].shanquhao);
	printf("�����Ϊ%X\n", the_pmbr->pation_table_entry[0].zhumianhao);
	printf("�������ͱ�־Ϊ %X\n", the_pmbr->pation_table_entry[0].disk_flag);
	printf("��һ������Ϊ %u\n", uint8to32(the_pmbr->pation_table_entry[0].relative));
	printf("������Ϊ %u\n", uint8to32(the_pmbr->pation_table_entry[0].sectors));
}

uint8_t show_partition_table(struct partition_table * the_partition_table)
{
	uint8_t GUID[16];
	printf("��������ֵΪ:");
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

	printf("����GUIDΪ:");
	changeseqGUID(the_partition_table->pationid, GUID);
	for (int i = 0; i < 16; i++)
	{
		printf("%0X", GUID[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			printf("-");
	}

	printf("\n�÷�����ʼ������Ϊ%I64X\n", uint8to64(the_partition_table->pation_start));
	printf("�÷�������������Ϊ%I64X\n", uint8to64(the_partition_table->pation_end));
	printf("�÷������Ա�־Ϊ%I64X\n", uint8to64(the_partition_table->pation_attr));
	uint64_t attr = uint8to64(the_partition_table->pation_attr);
	for (int i = 0; i < 6; i++)
	{
		if ((attr&attribute_bits[i]) != 0)
			printf("��attributes-bits�п�֪:%s\n", attribute_bits_info[i]);
	}
	printf("�÷�����Ϊ:");
	show_partion_name(the_partition_table->pation_name, 72);
	uint64_t bytes = (uint8to64(the_partition_table->pation_end) - uint8to64(the_partition_table->pation_start)) * (uint64_t)512;
	double MB = bytes / 1024.0 / 1024.0;
	double GB = MB / 1024.0;
	printf("\n�÷�����СΪ%I64X�ֽڣ�%lf GB", bytes, GB);
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
	offset.QuadPart = nextaddr;//�ҵ���һ��Ҫ��ȡ�ĵ�ַ
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//����ƫ��׼����ȡ
	//ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL);
	if (!ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL))
	{
		return 0;
	}
	int endflag = 1;
	int j = 0;//���j=4�������¶�����Ϊĳ�����ƣ�һ�α����512�ֽ�������
	while (endflag > 0) {
		printf("\n��%d��������:\n", ++entrynum);
		if (j == 4)
		{
			nextaddr = nextaddr + (ULONGLONG)512;
			offset.QuadPart = nextaddr;//�ҵ���һ��Ҫ��ȡ�ĵ�ַ
			SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//����ƫ��׼����ȡ
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
	DISK_GEOMETRY pdg;            // ������̲����Ľṹ��
	HANDLE hDevice;               // �豸���
	BOOL bResult;                 // results flag
	DWORD junk;                   // discard resultscc

	int disk = 0;
	const char *diskname[] = { "\\\\.\\PhysicalDrive0" ,"\\\\.\\PhysicalDrive1" };
	printf("������Ҫ�򿪵�Ӳ�̺�(һ��Ϊ0����2��Ӳ�̿�������0��1)\n");
	scanf("%d", &disk);
	if (disk != 0 && disk != 1)
	{
		disk = 0;
		printf("������Ч���򿪴���0\n");
	}
	//ͨ��CreateFile������豸�ľ��
	hDevice = CreateFile(diskname[disk], // �豸���ƣ�PhysicalDriveX��ʾ�򿪵�X���豸
		GENERIC_READ,                // no access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL);            // do not copy file attributes
	if (hDevice == INVALID_HANDLE_VALUE) //û�ܴ򿪣�������û���ù���ԱȨ������
	{
		printf("Creatfile error!May be no permission!ERROR_ACCESS_DENIED��\n");
		system("pause");
		return (FALSE);
	}

	//ͨ��DeviceIoControl�������豸����IO
	bResult = DeviceIoControl(hDevice, // �豸�ľ��
		IOCTL_DISK_GET_DRIVE_GEOMETRY, // �����룬ָ���豸������
		NULL,
		0, // no input buffer
		&pdg,
		sizeof(pdg),
		&junk,                 // # bytes returned
		(LPOVERLAPPED)NULL); // synchronous I/O

	LARGE_INTEGER offset;//long long signed
	offset.QuadPart = (ULONGLONG)0 * (ULONGLONG)512;//0
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//��0��ʼ��PMBR
	if (GetLastError())
		printf("�������ʹ��ţ�%ld\n\n", GetLastError());//���������

	DWORD dwCB;
	struct PMBR the_pmbr;
	//�����λ�ÿ�ʼ��512�ֽ�PMBR
	//��ȡPMBR��512�ֽڣ�����ķ������һ������ã���1������5�ֽ���0xEE
	//�����ʼ����ֵ��GPT Header��λ��
	BOOL bRet = ReadFile(hDevice, &the_pmbr, 512, &dwCB, NULL);
	printf("----------------��ȡPMBR����:---------------\n");
	showPMBR(&the_pmbr);
	if (the_pmbr.pation_table_entry[0].disk_flag == 0xEE)//�����ȷ��GPT��ʽ����
	{
		printf("PMBR�з������һ��ı�־λΪ 0xEE����GPT��ʽ����ת��%u����\n",
			uint8to32(the_pmbr.pation_table_entry[0].relative));
		printf("GPT��ͷ�ڵ�%u����", uint8to32(the_pmbr.pation_table_entry[0].relative));
	}
	else {
		printf("PMBR�з������һ���־λΪ %X������GPT��ʽ����������\n",
			the_pmbr.pation_table_entry[0].disk_flag);
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}


	//��ȡ����GPT Header
	//��һ��Ҫ��ȡ�����Ե�ַ=Ҫ��ȡ��������*512�ֽ�
	printf("\n\n----------------��ȡGPT Header����:---------------\n\n");
	ULONGLONG nextaddr = (ULONGLONG)1 * (ULONGLONG)512;
	offset.QuadPart = nextaddr;//�ҵ���һ��Ҫ��ȡ�ĵ�ַ
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//����ƫ��׼����ȡ
	if (GetLastError())
	{
		printf("��ȡGPT Header�����������ʹ��ţ�%ld\n\n", GetLastError());//���������
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}
	//��ȡGPT Header
	gpt_header the_gpt_header;
	ReadFile(hDevice, &the_gpt_header, 512, &dwCB, NULL);
	show_gpt_header(&the_gpt_header);

	//��ȡ��GPT���������������ǰ16���ֽ����ȫ0����ʾδ�ã����涼û���ˣ�����ȥ������
	printf("\n\n-------------��ȡ��������:-------------\n\n");
	ULONGLONG baseaddr = (ULONGLONG)uint8to64(the_gpt_header.pation_table_first);//GPT��������ʼλ��
	if (!read_partition_table(&the_gpt_header, hDevice, baseaddr))//�������
	{
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}

	printf("\n\n---------------��ȡ���ݵ�GPT Header:---------------\n\n");
	nextaddr = (ULONGLONG)uint8to32(the_gpt_header.backup_lba)*(ULONGLONG)512;
	offset.QuadPart = nextaddr;//�ҵ���һ��Ҫ��ȡ�ĵ�ַ
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//����ƫ��׼����ȡ
	if (GetLastError())
	{
		printf("��ȡ����GPT Header�����������ʹ��ţ�%ld\n\n", GetLastError());//���������
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}
	//��ȡ����GPT Header
	gpt_header backup_gpt_header;
	ReadFile(hDevice, &backup_gpt_header, 512, &dwCB, NULL);
	show_gpt_header(&backup_gpt_header);

	//��ȡ����GPT���������������ǰ16���ֽ����ȫ0����ʾδ�ã����涼û���ˣ�����ȥ������
	printf("\n\n-------------��ȡ���ݷ�������:-------------\n\n");
	baseaddr = (ULONGLONG)uint8to64(backup_gpt_header.pation_table_first);//GPT��������ʼλ��
	if (!read_partition_table(&backup_gpt_header, hDevice, baseaddr))//�������
	{
		CloseHandle(hDevice);
		system("pause");
		return 0;
	}

	printf("\n\n���Ӳ�̴�СΪ %lf GB\n", (double)uint8to64(the_gpt_header.backup_lba) * 512 / 1024 / 1024 / 1024);

	CloseHandle(hDevice);
	system("pause");
	return 0;
}

#endif
