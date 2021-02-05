//layout_mbr.h
//author:lzc
//date:2012/11/07
//e-mail:hackerlzc@126.com

#pragma once
#ifndef _LAYOUT_MBR_H
#define _LAYOUT_MBR_H

#include<windows.h>

#pragma pack(push)
#pragma pack(1)

#define PARTITION_ACTIVE_FLAG   (0x80)

#define PARTITION_TYPE_ILLEGAL      0x00
#define PARTITION_TYPE_FAT12        0X01
#define PARTITION_TYPE_XENIX_ROOT   0x02
#define PARTITION_TYPE_XENIX_USR    0x03
#define PARTITION_TYPE_FAT16_SMALL  0x04
#define PARTITION_TYPE_EXTENDED_SMALL 0x05
#define PARTITION_TYPE_FAT16        0x06
#define PARTITION_TYPE_NTFS         0x07
#define PARTITION_TYPE_HIPS         0x07
#define PARTITION_TYPE_AIX          0x08
#define PARTITION_TYPE_AIX_BOOTABLE 0x09
#define PARTITION_TYPE_OS2_BOOT_IMAGE 0x0a
#define PARTITION_TYPE_FAT32        0x0b
#define PARTITION_TYPE_FAT32_LBA    0x0c       //????
#define PARTITION_TYPE_FAT16_WIN95  0x0e
#define PARTITION_TYPE_EXTENDED     0x0f
#define PARTITION_TYPE_OPUS         0x10
#define PARTITION_TYPE_FAT12_HIDDEN 0x11
#define PARTITION_TYPE_COMPAQ_DIAGNOST 0x12
#define PARTITION_TYPE_FAT16_HIDDEN_SMALL 0x14
#define PARTITION_TYPE_FAT16_HIDDEN 0x16
#define PARTITION_TYPE_HIPS_HIDDEN  0x17
#define PARTITION_TYPE_NTFS_HIDDEN  0x17
#define PARTITION_TYPE_AST_WINDOWS_SWAP 0x18
#define PARTITION_TYPE_FAT32_HIDDEN 0x1b
#define PARTITION_TYPE_FAT32_HIDDEN_LBA 0x1c
#define PARTITION_TYPE_VFAT_LBA     0x1e
#define PARTITION_TYPE_NEC_DOS      0x24
#define PARTITION_TYPE_PARTITION_MAGIC 0x3c
#define PARTITION_TYPE_VENIX_80286  0x40
#define PARTITION_TYPE_PPC_PREP_BOOT 0x41
#define PARTITION_TYPE_SFS          0x42
#define PARTITION_TYPE_QNX4X        0x4d
#define PARTITION_TYPE_QNX4X_1      0x4e
#define PARTITION_TYPE_QNX4X_2      0x4f
#define PARTITION_TYPE_ONTRACK_DM   0x50
#define PARTITION_TYPE_ONTRACK_DM_AUX 0x51
#define PARTITION_TYPE_CP_M         0x52
#define PARTITION_TYPE_ONTRACK_DM6_AUX 0x53
#define PARTITION_TYPE_ONTRACK_DM6  0x54
#define PARTITION_TYPE_EZ_DRIVE     0x55
#define PARTITION_TYPE_GOLDEN_BOW   0x56
#define PARTITION_TYPE_PRIAM_EDISK  0x5c
#define PARTITION_TYPE_SPEED_STOR   0x61
#define PARTITION_TYPE_GNU_HURD_SYS 0x63
#define PARTITION_TYPE_NOVELL_NETWARE 0x64
#define PARTITION_TYPE_NOVELL_NETWARE2 0x65
#define PARTITION_TYPE_DISK_SECURE_MULT 0x70
#define PARTITION_TYPE_PC_IX        0x75
#define PARTITION_TYPE_MINIX_OLD    0x80
#define PARTITION_TYPE_MINIX        0x81
#define PARTITION_TYPE_LINUX_OLD    0x81
#define PARTITION_TYPE_LINUX_SWAP   0x82
#define PARTITION_TYPE_LINUX        0x83
#define PARTITION_TYPE_OS2_HIDDEN_C 0x84
#define PARTITION_TYPE_LINUX_EXTENDED 0x85
#define PARTITION_TYPE_NTFS_VOLUME_SET 0x86
#define PARTITION_TYPE_NTFS_VOLUME_SET2 0x87
#define PARTITION_TYPE_AMOEBA       0x93
#define PARTITION_TYPE_AMOEBA_BBT   0x94
#define PARTITION_TYPE_IBM_THINKPAD_HIDDEN 0xa0
#define PARTITION_TYPE_BSD_386      0xa5
#define PARTITION_TYPE_OPEN_BSD     0xa6
#define PARTITION_TYPE_NEXT_STEP    0xa7
#define PARTITION_TYPE_BSDI_FS      0xb7
#define PARTITION_TYPE_BSDI_SWAP    0xb8
#define PARTITION_TYPE_SOLARIX_BOOT 0xbe
#define PARTITION_TYPE_DR_DOS       0xc0
#define PARTITION_TYPE_NOVELL_DOS_SECURE 0xc0
#define PARTITION_TYPE_DRDOS_SEC    0xc1
#define PARTITION_TYPE_DRDOS_SEC2   0xc4
#define PARTITION_TYPE_DRDOS_SEC3   0xc6
#define PARTITION_TYPE_SYRINX       0xc7
#define PARTITION_TYPE_CP_M2         0xdb
#define PARTITION_TYPE_CTOS         0xdb
#define PARTITION_TYPE_DOS_ACCESS   0xe1
#define PARTITION_TYPE_DOS_R_O      0xe3
#define PARTITION_TYPE_SPEED_STOR2  0xe4
#define PARTITION_TYPE_BEOS_FS      0xe8
#define Not_MBR_isGUID              0xee
#define PARTITION_TYPE_SPEED_STOR3  0xf1
#define PARTITION_TYPE_DOS3P3_SECONDARY 0xf2
#define PARTITION_TYPE_SPEED_STOR4  0xf4
#define PARTITION_TYPE_LAN_STEP     0xfe
#define PARTITION_TYPE_BBT          0xff

typedef struct _PARTITION_TABLE_ENTRY
{
    BYTE boot_indicator;            /*������־��0x80ָ���Ƿ�Ϊ�����*/
    BYTE start_head;                /*��ʼ��ͷ*/
    WORD start_sector:6;            /*��ʼ����*/
    WORD start_cylinder:10;         /*��ʼ����*/
    BYTE partition_type_indicator;  /*�������ͱ�־*/
    BYTE end_head;                  /*������ͷ*/
    WORD end_sector:6;              /*��������*/
    WORD end_cylinder:10;           /*��������*/
    DWORD sectors_precding;         /*������֮ǰʹ�õ�������������ƫ�ƣ�*/
    DWORD total_sectors;            /*��������������*/
}PARTITION_TABLE_ENTRY,
*PPARTITION_TABLE_ENTRY;

typedef struct _MBR_SECTOR
{
    BYTE boot_code[440];            /*MBR��������*/
    DWORD disk_signature;           /*����ǩ��*/
    BYTE reserved[2];               /*��������Ϊ0*/
    PARTITION_TABLE_ENTRY dpt[4];   /*����������4����������*/
    WORD end_flag;                  /*��������������־����Ϊ0xAA55*/
	BYTE UNUSEFOR4K[3584];
}MBR_SECTOR,*PMBR_SECTOR;


typedef struct _EBR_SECTOR
{
    BYTE reserved[446];             /*δ���壬��Ϊ0*/
    PARTITION_TABLE_ENTRY dpt[4];   /*����������4����������*/
    WORD end_flag;                  /*��������������־����Ϊ0xAA55(С�˸�ʽ*/
}EBR_SECTOR,*PEBR_SECTOR;

//#define MBR_SECTOR_SIZE 512         /*��ָMBR����������������СΪ512�ֽ�*/


#pragma pack(pop)
#endif