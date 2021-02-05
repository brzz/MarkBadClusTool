//repair_controller.h for class ----  CRepairController
//author:lzc
//date:2012/11/14
//e-mail:hackerlzc@126.com

#pragma once
#ifndef _REPAIR_CONTROLLER_H
#define _REPAIR_CONTROLLER_H
#pragma warning(push)
#pragma warning(disable:4200)

#include<windows.h>
#include"utils.h"

#ifdef _UNICODE
#error this class not support UNICODE!
#endif

//ע�⣺��֧�ֶ��߳�

#define BLOCK_TYPE_UNKNOWN      0x00
#define BLOCK_TYPE_USED         0x01
#define BLOCK_TYPE_FREE         0x02
#define BLOCK_TYPE_BAD          0x03
#define BLOCK_TYPE_MAXIMUM      0xff

typedef struct _BLOCK_DESCRIPTOR
{
    LIST_ENTRY  List;
    BYTE        type;               //BLOCK_TYPE_XXX
    BYTE        reserved1[3];       //����
    LARGE_INTEGER StartSector;      //��ʼ������
    LARGE_INTEGER TotalSectors;     //��������
}BLOCK_DESCRIPTOR,*PBLOCK_DESCRIPTOR;

typedef struct _BLOCK_INFOR_HEAD
{
    LARGE_INTEGER UsedBlockSize;    //��λ���ֽ�
    LIST_ENTRY  UsedBlockList;      //���ض����ļ�ϵͳģ�齨�����ͷ�

    LARGE_INTEGER FreeBlockSize;    //��λ���ֽ�
    LIST_ENTRY  FreeBlockList;      //���ض����ļ�ϵͳģ�齨�����ͷ�

    LARGE_INTEGER BadBlockSize;     //��λ���ֽ�
    LIST_ENTRY  BadBlockList;       //���ض����ļ�ϵͳģ�齨�����ͷ�
    LIST_ENTRY  DeadBlockList;      //��UIͨ���ض��Ļ���ӿڽ���
}BLOCK_INFOR_HEAD,*PBLOCK_INFOR_HEAD;

#define MESSAGE_CODE_UNKNOWN    0x00 //δ֪֪ͨ��
#define MESSAGE_CODE_NOTIFY     0x01 //֪ͨ��Ϣ�����ڽ��������ƣ�Param1,2�޶���
#define MESSAGE_CODE_REPORTSTATE 0x02 //״̬����֪ͨ�룬Param1Ϊһ�ַ���ָ��
                                     //Param2δ����
#define MESSAGE_CODE_PROGRESS   0x03 //������Ϣ��Param1Ϊ��ǰ������ɵ���������
                                     //Param2Ϊ��������
#define MESSAGE_CODE_REPORTERROR 0x04 //���󱨸�֪ͨ�룬Param1Ϊ�ַ���ָ��
                                      //Param2δ����
#define MESSAGE_CODE_FILENAME 0x05    //�����ļ�����Param1Ϊ���ַ���ָ�루LPWSTR),
#define MESSAGE_CODE_MAXIMUM    0xff


typedef VOID (*MESSAGE_CALLBACK_FUNC)(
                IN BYTE Code,
                IN OUT DWORD_PTR Param1,
                IN OUT DWORD_PTR Param2);

class CRepairController:public CUtils
{
protected:
    //��˽�б���
    BLOCK_INFOR_HEAD m_BlockInforHead;
    LARGE_INTEGER    m_VolumeStartSector;
    LARGE_INTEGER    m_VolumeTotalSectors;
    HANDLE  m_hDisk;
    MESSAGE_CALLBACK_FUNC   m_lpMessageFunc;
public:
    //��д�����Ա����

public:
    //�����ӿں���
    CRepairController( LPSTR lpszDiskPath,LONGLONG StartSector,LONGLONG NumberOfSectors);
    virtual ~CRepairController();
    PBLOCK_DESCRIPTOR GetFirstUsedBlock();
    PBLOCK_DESCRIPTOR GetNextUsedBlock( PBLOCK_DESCRIPTOR CurrBlock );
    PBLOCK_DESCRIPTOR GetFirstFreeBlock();
    PBLOCK_DESCRIPTOR GetNextFreeBlock( PBLOCK_DESCRIPTOR CurrBlock );
    PBLOCK_DESCRIPTOR GetFirstBadBlock();
    PBLOCK_DESCRIPTOR GetNextBadBlock( PBLOCK_DESCRIPTOR CurrBlock );
    LONGLONG GetUsedBlockSize();
    LONGLONG GetFreeBlockSize();
    LONGLONG GetBadBlockSize();
    MESSAGE_CALLBACK_FUNC RegisterMessageCallBack( MESSAGE_CALLBACK_FUNC lpFn );
    MESSAGE_CALLBACK_FUNC UnregisterMessageCallBack();
    VOID ReportStateMessage( LPSTR message );
    VOID ReportFileNameMessage(LPWSTR FileName );
    VOID ReportErrorMessage( LPSTR message );
    VOID ReportProgressState( DWORD Curr,DWORD Total );
    VOID ReportNotifyMessage();
    virtual VOID PrepareUpdateBadBlockList()=0;
    virtual VOID AddBadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors )=0;
    virtual VOID AddDeadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors )=0;
    virtual BOOL ProbeForRepair()=0;
    virtual BOOL VerifyFileSystem()=0;
    virtual BOOL StartRepairProgress() = 0;
    virtual BOOL StopRepairProgress() = 0;

protected:
    //�ɱ��̳е���˽�к���
    BOOL ReadLogicalSector( OUT LPVOID buffer,
                     IN DWORD bufferSize,
                     LONGLONG Lsn,
	                 WORD SectorSzie
                     );
    BOOL WriteLogicalSector( IN LPVOID buffer,
                     IN DWORD bufferSize,
                     LONGLONG Lsn,
	                 WORD SectorSzie
                     );
    virtual BOOL InitController() = 0;//��ʼ��Controller,��ͬ���ļ�ϵͳ�в�ͬ�ĳ�ʼ��������������������
                                      //ʵ�ִ˽ӿڣ�����ʵ�ֶԲ�ͬ�ļ�ϵͳ��֧�֡�
    virtual VOID ReleaseResources();

private:
    //���ɱ��̳е�˽�к���
};

#endif    //_REPAIR_CONTROLLER_H