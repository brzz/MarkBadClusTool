//repair_controller.cpp for class-- CRepairController
//author:lzc
//date:2012/11/14
//e-mail:hackerlzc@126.com

#include "stdafx.h"
#include<windows.h>
#include"repair_controller.h"

//��ʵ��

CRepairController::CRepairController(LPSTR lpszDiskPath,LONGLONG StartSector,LONGLONG NumberOfSectors)
/*++
�������������캯������ʼ�����Ա����
--*/
:
m_hDisk( INVALID_HANDLE_VALUE ),
m_lpMessageFunc( NULL)
{
    m_VolumeStartSector.QuadPart = StartSector;
    m_VolumeTotalSectors.QuadPart = NumberOfSectors;
    RtlZeroMemory( &m_BlockInforHead,sizeof( m_BlockInforHead ));
    InitializeListHead( &m_BlockInforHead.BadBlockList );
    InitializeListHead( &m_BlockInforHead.FreeBlockList );
    InitializeListHead( &m_BlockInforHead.UsedBlockList );
    InitializeListHead( &m_BlockInforHead.DeadBlockList );

    assert( lpszDiskPath != NULL );

    m_hDisk = CreateFile( lpszDiskPath,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if( m_hDisk == INVALID_HANDLE_VALUE )
        DbgPrint("open disk device failed!");

}

CRepairController::~CRepairController()
/*++
���������������������ͷ���Դ
--*/
{
    ReleaseResources();
}

VOID CRepairController::ReleaseResources()
/*++
�����������ͷű����������Դ

��������

����ֵ����

ע�⣺Ϊ�麯��������������������Դ���ͷ�
--*/
{
    assert( IsListEmpty( &m_BlockInforHead.BadBlockList));
    assert( IsListEmpty( &m_BlockInforHead.UsedBlockList));
    assert( IsListEmpty( &m_BlockInforHead.FreeBlockList));
    assert( m_BlockInforHead.BadBlockSize.QuadPart == 0 );
    assert( m_BlockInforHead.FreeBlockSize.QuadPart == 0 );
    assert( m_BlockInforHead.UsedBlockSize.QuadPart == 0 );

    if( m_hDisk != INVALID_HANDLE_VALUE )
        CloseHandle( m_hDisk );

    m_VolumeStartSector.QuadPart = 0;
    m_VolumeTotalSectors.QuadPart = 0;
    m_lpMessageFunc = NULL;

    if( !IsListEmpty( &m_BlockInforHead.DeadBlockList))
    {
        //�ͷ�������Ķ�̬�ڴ�ռ�

        PLIST_ENTRY entry = NULL;
        for( entry = RemoveHeadList( &m_BlockInforHead.DeadBlockList );
            entry != NULL;
            entry = RemoveHeadList( &m_BlockInforHead.DeadBlockList))
        {
            PBLOCK_DESCRIPTOR pBlockDesc = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
                entry,
                BLOCK_DESCRIPTOR,
                List);
            free( pBlockDesc );
        }
        assert( IsListEmpty( &m_BlockInforHead.DeadBlockList ));
    }
}

PBLOCK_DESCRIPTOR CRepairController::GetFirstUsedBlock()
/*++
������������ȡ�׸���������������Ϣ

��������

����ֵ������������Ϣָ�룬�������򷵻�NULL

--*/
{
    if( IsListEmpty( &m_BlockInforHead.UsedBlockList))
        return NULL;
    return (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(GetFirstListEntry(&m_BlockInforHead.UsedBlockList),
                                                BLOCK_DESCRIPTOR,
                                                List);
}

PBLOCK_DESCRIPTOR CRepairController::GetNextUsedBlock( PBLOCK_DESCRIPTOR CurrBlock )
/*++
������������ȡ��һ����������������Ϣ

������
    CurrBlock:��ǰ��������������Ϣָ��

����ֵ������������Ϣָ�룬�Ѿ����������β�򷵻�NULL
--*/
{
    if( CurrBlock->List.Flink == &m_BlockInforHead.UsedBlockList )
        return NULL;
    return (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( CurrBlock->List.Flink,
                                                BLOCK_DESCRIPTOR,
                                                List );
}

PBLOCK_DESCRIPTOR CRepairController::GetFirstFreeBlock()
/*++
������������ȡ�׸���������������Ϣ

��������

����ֵ������������Ϣָ�룬�������򷵻�NULL

--*/
{
    if( IsListEmpty( &m_BlockInforHead.FreeBlockList))
        return NULL;
    return (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(GetFirstListEntry(&m_BlockInforHead.FreeBlockList),
                                                BLOCK_DESCRIPTOR,
                                                List);
}

PBLOCK_DESCRIPTOR CRepairController::GetNextFreeBlock( PBLOCK_DESCRIPTOR CurrBlock )
/*++
������������ȡ��һ��δ�ã����У�����������Ϣ

������
    CurrBlock:��ǰδ������������Ϣָ��

����ֵ������������Ϣָ�룬�Ѿ����������β�򷵻�NULL

--*/
{
    if( CurrBlock->List.Flink == &m_BlockInforHead.FreeBlockList )
        return NULL;
    return (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(CurrBlock->List.Flink,
                                            BLOCK_DESCRIPTOR,
                                            List );

}

PBLOCK_DESCRIPTOR CRepairController::GetFirstBadBlock()
/*++
������������ȡ�׸�������������Ϣ

��������

����ֵ������������Ϣָ�룬�������򷵻�NULL

--*/
{
    if( IsListEmpty( &m_BlockInforHead.BadBlockList ))
        return NULL;
    return (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(GetFirstListEntry(&m_BlockInforHead.BadBlockList),
                                                BLOCK_DESCRIPTOR,
                                                List);
}


PBLOCK_DESCRIPTOR CRepairController::GetNextBadBlock( PBLOCK_DESCRIPTOR CurrBlock )
/*++
������������ȡ��һ��������������Ϣ

������
    CurrBlock:��ǰ������������Ϣָ��

����ֵ������������Ϣָ�룬�Ѿ����������β�򷵻�NULL

--*/
{
    if( CurrBlock->List.Flink == &m_BlockInforHead.BadBlockList )
        return NULL;
    return (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(CurrBlock->List.Flink,
                                                BLOCK_DESCRIPTOR,
                                                List );
}

LONGLONG CRepairController::GetUsedBlockSize()
/*++
������������������ʹ���еĿ���������������Ϊ��λ��

��������

����ֵ��ʹ���е���������ͨ������뵽�ص���������
--*/
{
    return m_BlockInforHead.UsedBlockSize.QuadPart;
}

LONGLONG CRepairController::GetFreeBlockSize()
/*++
�������������ؿ��п���������������Ϊ��λ��

��������

����ֵ��������������ͨ������뵽�ص���������
--*/
{
    return m_BlockInforHead.FreeBlockSize.QuadPart;
}

LONGLONG CRepairController::GetBadBlockSize()
/*++
�������������ػ�����������������Ϊ��λ��

��������

����ֵ������������ͨ������뵽�ص���������
--*/
{
    return m_BlockInforHead.BadBlockSize.QuadPart;
}

MESSAGE_CALLBACK_FUNC CRepairController::RegisterMessageCallBack( MESSAGE_CALLBACK_FUNC lpFn )
/*++
����������ע����Ϣ֪ͨ�����ص�

������
    lpFn:��ע��ĺ���ָ�룬ԭ��ΪMESSAGE_CALLBACK_FUNC

����ֵ����ǰ��ע�����Ϣ֪ͨ����ָ��
--*/
{
    MESSAGE_CALLBACK_FUNC prevFunc = m_lpMessageFunc;
    m_lpMessageFunc = lpFn;
    return prevFunc;
}

MESSAGE_CALLBACK_FUNC CRepairController::UnregisterMessageCallBack()
/*++
��������������ע����Ϣ֪ͨ����

��������

����ֵ����ǰ�Ѿ�ע��Ļص�����ָ�룬�������ڷ���NULL
--*/
{
    MESSAGE_CALLBACK_FUNC prevFunc = m_lpMessageFunc;
    m_lpMessageFunc = NULL;
    return prevFunc;
}

VOID CRepairController::ReportStateMessage( LPSTR message )
/*++
��������������ע��Ļص�������ʾ��ǰ״̬

������ָ��Ҫ��ʾ��״̬�ַ���

����ֵ����
--*/
{
    if( m_lpMessageFunc == NULL )return;

    m_lpMessageFunc( MESSAGE_CODE_REPORTSTATE,(DWORD_PTR)message,0);
}

VOID CRepairController::ReportFileNameMessage(LPWSTR FileName)
/*++
��������������ע��Ļص�������ʾ�ļ���

������
    FileName:ָ��Ҫ��ʾ��״̬�ַ���(���ַ�����

����ֵ����
--*/
{
    if( m_lpMessageFunc == NULL )return;

    m_lpMessageFunc( MESSAGE_CODE_FILENAME,(DWORD_PTR)FileName,0);
}

VOID CRepairController::ReportErrorMessage( LPSTR message )
/*++
��������������ע��Ļص�������ʾ��ǰ������Ϣ

������ָ��Ҫ��ʾ�Ĵ�����Ϣ�ַ���

����ֵ����
--*/
{
    if( m_lpMessageFunc == NULL )return;

    m_lpMessageFunc( MESSAGE_CODE_REPORTERROR,(DWORD_PTR)message,0);
}

VOID CRepairController::ReportProgressState(DWORD Curr,DWORD Total )
/*++
��������������ע��Ļص�������ʾ��ǰ����

������
    Cur:��ǰ�Ľ���ֵ
    Total:�ܽ���ֵ

����ֵ����
--*/
{
    if( m_lpMessageFunc == NULL )return;

    m_lpMessageFunc( MESSAGE_CODE_PROGRESS,(DWORD_PTR)Curr,(DWORD_PTR)Total);
}

VOID CRepairController::ReportNotifyMessage()
/*++
��������������֪ͨ��Ϣ��֤�������������У�

��������

����ֵ����
--*/
{
    if( m_lpMessageFunc == NULL )return;

    m_lpMessageFunc( MESSAGE_CODE_NOTIFY,0,0);

}

BOOL CRepairController::ProbeForRepair()
/*++
����������̽���Ƿ�����޸�����

��������

����ֵ�����Ϸ���TRUE�����򷵻�FALSE

ע�⣺Ϊ���麯��������ʵ��
--*/
{
    return FALSE;
}



VOID CRepairController::AddBadBlock( LONGLONG Lcn,LONGLONG NumberOfSectors )
/*++
�������������һ���������򣬸����ڲ�������ṹ

������
    StartLcn:��ʼ�߼������ţ�Lcn)
    NumberOfSectors:������������������

����ֵ����

ע�⣺���麯��������ʵ��
--*/
{

}

VOID AddDeadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors )
/*++
�������������һ����������Ӳ�������������ɶ����������ڲ�������ṹ

������
    StartLsn:��ʼ�߼������ţ�Lsn)
    NumberOfSectors:������������������

����ֵ����

ע�⣺���麯��������ʵ��

--*/
{

}

BOOL CRepairController::ReadLogicalSector(OUT LPVOID buffer, 
	IN DWORD bufferSize, 
	LONGLONG Lsn, 
	WORD SectorSzie
)
/*++
�������������߼�����������������ڷ�����ʼ��ַ��

������
    hDisk: �����豸�����������ж�Ȩ�ޣ�
    buffer:�������������С����Ϊһ������
    bufferSize:���������buffer�Ĵ�С
    Lsn:�߼�������
	SectorSzie: ����Ӳ��������С
����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE

--*/
{
    LONGLONG tmp = m_VolumeStartSector.QuadPart + Lsn;
    assert( tmp > 0 );
    assert( Lsn < m_VolumeTotalSectors.QuadPart );

    return ReadSector( m_hDisk, buffer, bufferSize, (DWORD)(tmp & 0xffffffff), (DWORD)(tmp >> 32) , SectorSzie);
}

BOOL CRepairController::WriteLogicalSector(IN LPVOID buffer,
	IN DWORD bufferSize,
	LONGLONG Lsn,
	WORD SectorSzie
)
/*++
����������д�߼�����������������ڷ�����ʼ��ַ��

������
    hDisk: �����豸������������дȨ�ޣ�
    buffer:���뻺��������С����Ϊһ������
    bufferSize:���뻺����buffer�Ĵ�С
    Lsn:�߼�������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    LONGLONG tmp = m_VolumeStartSector.QuadPart + Lsn;
    assert( tmp > 0 );
    assert( Lsn < m_VolumeTotalSectors.QuadPart );

    return WriteSector( m_hDisk, buffer, bufferSize, (DWORD)(tmp & 0xffffffff), (DWORD)(tmp >> 32) , SectorSzie);
}

