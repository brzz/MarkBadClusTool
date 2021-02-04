//disk_list.h for class CDiskList
//author:lzc
//date:2012/11/07
//e-mail:hackerlzc@126.com

#pragma once
#ifndef _DISK_LIST_H
#define _DISK_LIST_H
#pragma warning(push)
#pragma warning(disable:4200)

#include<windows.h>
#include"utils.h"

#ifdef _UNICODE
#error this class not support UNICODE!
#endif

#define REG_ROOT    ("SYSTEM\\CurrentControlSet\\services\\Disk\\Enum")

typedef struct _DISK_DEVICE
{
    LIST_ENTRY  list;               //�������ڴ����豸��
    WORD        index;              //����������������豸����ţ���0��ʼ��
    WORD        reserved;           //����
    LARGE_INTEGER sizeInSectors;    //��������ʾ������
    LARGE_INTEGER sectorsPerCylinder;//ÿ����������
	WORD        BytesPerSector;         //ÿ�������Ĵ�Сbytes
    BYTE        *name;              //ϵͳ�Դ��̵�������Ϣ
    BYTE        *path;              //�����豸·�������ڴ򿪴����豸
}DISK_DEVICE,*PDISK_DEVICE;

//ע�⣺��֧�ֶ��̷߳���

class CDiskList:public CUtils
{
private:
    WORD        m_DiskCount;         //������������
    LIST_ENTRY  m_DiskListHead;     //������Ϣ����ͷ

public:
    CDiskList();                    //���캯��
    ~CDiskList();                   //�ع��������ͷ���Դ
    WORD GetDiskCount();
    BOOL GetDiskByIndex( IN WORD index,OUT PDISK_DEVICE *result );
    PDISK_DEVICE GetFirstDisk();
    PDISK_DEVICE GetNextDisk( IN PDISK_DEVICE curDisk );
    VOID UpdateDiskList();

private:
    VOID ReleaseAllResources();
    VOID InitDiskList();
};

#pragma warning(pop)
#endif