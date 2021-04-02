//volume_list.h for class-CVolumeList
//author:lzc
//date:2012/11/10
//e-mail:hackerlzc@126.com

#pragma once
#ifndef _VOLUME_LIST_H
#define _VOLUME_LIST_H

#pragma warning(push)
#pragma warning(disable:4200)

#include<windows.h>
#include"utils.h"

#include "disk_list.h"

typedef struct _VOLUME_NODE
{
    LIST_ENTRY  List;               //�����������ɾ����
    DWORD       Index;              //����������0��ţ�
    BYTE        Type;               //�����ʹ���
    CHAR        VolumeLetter;       //�̷�
    BYTE        Reserved1[2];       //����
    LARGE_INTEGER StartSector;      //���������������ʼλ�õľ���������
    DWORD       Reserved2;          //����
    LARGE_INTEGER TotalSectors;     //������������������
    DWORD       Reserved3;          //����
    LPSTR       VolumeName;         //ָ������Ƶ��ַ���
	LPSTR       VolumeGUID;         //ָ���GUID //δ��� LCQ
    LPSTR       TypeName;
}VOLUME_NODE,*PVOLUME_NODE;

class CVolumeList:public CUtils
{
private:
    WORD         m_VolumeCount;      //�����о�����
    LIST_ENTRY   m_VolumeListHead;   //��������ͷ
    HANDLE       m_hDisk;
    DWORD        m_DiskId;
    DWORD        m_tbl_VolumeOwnerDiskId[26]; //�����������̺� ӳ���
    DWORDLONG    m_tbl_VolumeOffset[26]; //���������Դ�����ʼ����ƫ��(�ֽڣ�ӳ���
	
	
public:
    //CVolumeList( LPSTR DiskPath,DWORD DiskId);
	CVolumeList(PDISK_DEVICE pdisk);
	//���캯��
    ~CVolumeList();                 //�ع��������ͷ���Դ
    WORD GetVolumeCount();
    BOOL GetVolumeByIndex( IN WORD index,OUT PVOLUME_NODE *result );
    PVOLUME_NODE GetFirstVolume();
    PVOLUME_NODE GetNextVolume( IN PVOLUME_NODE curVolume );
    VOID UpdateVolumeList();

	PDISK_DEVICE m_pdisk;   //��Ӳ����Ϣ

private:
    VOID ReleaseAllResources();
    VOID InitVolumeList();
    DWORD SearchMbrVolume(PDISK_DEVICE pdisk, DWORD BaseSector,DWORD BaseEbrSector = 0 );
	DWORD SearchGPTVolume(PDISK_DEVICE pdisk, DWORD BaseSector, MBR_SECTOR  mbrSector);
	
    BOOL IsVolumeTypeSupported( BYTE type );
};

#pragma warning(pop)
#endif