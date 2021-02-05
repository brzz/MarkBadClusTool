//ntfs_controller.cpp for class-- CNtfsController
//author:lzc
//date:2012/11/14
//e-mail:hackerlzc@126.com

#include "stdafx.h"
#include<windows.h>
#include"ntfs_controller.h"
#include<map>
using namespace std;
//��ʵ��

CNtfsController::CNtfsController(LPSTR lpszDiskPath, LONGLONG StartSector, LONGLONG NumberOfSectors, WORD SectorSzie)
/*++
��������:���캯��

����:WORD SectorSzie ������̵�������С

����ֵ:��

--*/
:CRepairController( lpszDiskPath,StartSector,NumberOfSectors ),
m_MftDataRuns(NULL),
m_MftDataRunsLength(0),
m_MftRecordLength(0),
m_Bitmap(NULL),
m_BitmapLength(0),
m_MftBitmap(NULL),
m_MftBitmapLength(0),
m_PhysicDiskSectorSize(SectorSzie)
{
    DbgPrint("CNtfsController constructor called!");
    BOOL    bOk = FALSE;

    //��ʼ��NTFS��DBR����
    bOk = ReadLogicalSector( &m_BootSect, sizeof(m_BootSect), 0, SectorSzie);
    assert( bOk );
    m_ClusterSizeInBytes = m_BootSect.bpb.sectors_per_cluster * m_BootSect.bpb.bytes_per_sector;

    if( !InitController())
        DbgPrint("init controller failed!");
}

CNtfsController::~CNtfsController()
/*++
��������:��������
--*/
{
    DbgPrint("CNtfsController destructor called!");

    ReleaseResources();
}

VOID CNtfsController::PrepareUpdateBadBlockList()
/*++
����������׼�����»�������

��������

����ֵ����

˵������ÿ��Ҫˢ�»�������ǰ��Ҫ���ô˺���
--*/
{
	LPBYTE buffer = NULL;

    DbgPrint("prepare update badblocklist!");

    DestroyListNodes( &m_BlockInforHead.BadBlockList);
    m_BlockInforHead.BadBlockSize.QuadPart = 0;

    LONGLONG last_value=0;                  //���ڼ��BadBlockList����������Ķ���

    NTFS_FILE   file = OpenNtfsFile( FILE_BadClus );
    if( file == NULL )
        goto exit;

    DWORD valueLength = GetAttributeValue( file,AT_DATA,NULL,0,NULL,L"$Bad");
    if( valueLength == -1 )
        goto exit;
    assert( valueLength > 0 );
    
    buffer = (LPBYTE)malloc( valueLength );
    assert( buffer != NULL);
    BOOL bDataruns = FALSE;
    if( 0 != GetAttributeValue( file,AT_DATA,buffer,valueLength,&bDataruns,L"$Bad"))
        goto exit;
    assert( bDataruns == TRUE );

    //��Dataruns����ȡ������Ϣ

    LONGLONG startLcn = 0,len = 0;
    for(DWORD i = 0;
        i < valueLength;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( buffer[i] == 0 )break;

        cStartLcnBytes = ( buffer[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (buffer[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        //��ȡ��ǰ����������
        len = 0;
        for( DWORD j = cLenLcnBytes;j > 0;j--)
        {
            len = (len << 8) | buffer[i + j ]; 
        }

        //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
        LONGLONG tmp = 0;
        if( buffer[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
            tmp = -1ll;
        for( DWORD j = cStartLcnBytes;j > 0;j-- )
        {
            tmp = ( tmp << 8 ) | buffer[i + cLenLcnBytes + j ];
        }
        startLcn = startLcn + tmp;
        if( cStartLcnBytes > 0 )
        {
            assert( startLcn > last_value );
            last_value = startLcn;
            FreeBlock( startLcn ,len);
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }
exit:
    if( file != NULL)CloseFile( file );
    file = NULL;

    if( buffer != NULL)free(buffer);
    buffer = NULL;
    return;
}

VOID CNtfsController::AddBadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors )
/*++
��������:�򻵿������������������,������Bitmap

����
    StartLsn:��ʼ�߼�������
    NumberOfSectors:������

����ֵ:��

˵�����뱣֤��������Lsn��������

--*/
{
    //�������ض���
    LONGLONG sectors_per_cluster = m_BootSect.bpb.sectors_per_cluster;
    StartLsn = StartLsn / sectors_per_cluster * sectors_per_cluster;
    NumberOfSectors = NumberOfSectors % sectors_per_cluster == 0?
                        NumberOfSectors:(NumberOfSectors/sectors_per_cluster+1)*sectors_per_cluster;
#if 0
    PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof(BLOCK_DESCRIPTOR));
    assert( node != NULL );
    RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR));
    node->StartSector.QuadPart = StartLsn;
    node->TotalSectors.QuadPart = NumberOfSectors;
    node->type = BLOCK_TYPE_BAD;
    m_BlockInforHead.BadBlockSize.QuadPart += NumberOfSectors * m_BootSect.bpb.bytes_per_sector;
    InsertTailList( &m_BlockInforHead.BadBlockList,&node->List);
    node = NULL;
#endif

    //����Bitmap
    for(LONGLONG i = StartLsn / sectors_per_cluster;
        i < (StartLsn + NumberOfSectors) / sectors_per_cluster;
        i++)
    {
        m_Bitmap[ i / 8 ] |= (1 << (i % 8));
    }

    //������뵽��������
 
    if( IsListEmpty( &m_BlockInforHead.BadBlockList))
    {
        PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
        assert( node != NULL );

        RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
        node->StartSector.QuadPart = StartLsn;
        node->TotalSectors.QuadPart = NumberOfSectors;
        node->type = BLOCK_TYPE_BAD;
        InsertHeadList( &m_BlockInforHead.BadBlockList,&node->List );
        node = NULL;
        return;
    }

    PLIST_ENTRY list = NULL;
    PBLOCK_DESCRIPTOR first_block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
        m_BlockInforHead.BadBlockList.Flink,
        BLOCK_DESCRIPTOR,
        List);
    PBLOCK_DESCRIPTOR last_block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
            m_BlockInforHead.BadBlockList.Blink,
            BLOCK_DESCRIPTOR,
            List);

    if( StartLsn <= first_block->StartSector.QuadPart )
    {
        if( StartLsn + NumberOfSectors >= 
            first_block->StartSector.QuadPart )
        {
            first_block->TotalSectors.QuadPart = 
                max(first_block->StartSector.QuadPart + first_block->TotalSectors.QuadPart,
                    StartLsn + NumberOfSectors)
                - StartLsn;
            first_block->StartSector.QuadPart = StartLsn;
            
            PBLOCK_DESCRIPTOR block_prev = first_block;
            PBLOCK_DESCRIPTOR block_next =(PBLOCK_DESCRIPTOR)CONTAINING_RECORD(block_prev->List.Flink,
                                                BLOCK_DESCRIPTOR,
                                                List );
            while( (&m_BlockInforHead.BadBlockList != &block_next->List) &&
                (block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart
                >= block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart) )
            {
                PBLOCK_DESCRIPTOR tmp = block_next;
                block_next = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(block_next->List.Flink,
                                                                BLOCK_DESCRIPTOR,
                                                                List );
                RemoveEntryList( &tmp->List );
                free( tmp );tmp = NULL;
            }
            if((&m_BlockInforHead.BadBlockList != &block_next->List) && 
                ( block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart
                >= block_next->StartSector.QuadPart))
            {
                block_prev->TotalSectors.QuadPart = 
                    max( block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart,
                        block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart)
                    - block_prev->StartSector.QuadPart;
                RemoveEntryList( &block_next->List );
                free( block_next );
            }
        }
        else
        {
            PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
            assert( node != NULL );

            RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
            node->StartSector.QuadPart = StartLsn;
            node->TotalSectors.QuadPart = NumberOfSectors;
            node->type = BLOCK_TYPE_BAD;
            InsertHeadList( &m_BlockInforHead.BadBlockList,&node->List );
            node = NULL;
        }
    }
    else if(StartLsn >= last_block->StartSector.QuadPart)
    {
        if( (last_block->StartSector.QuadPart + last_block->TotalSectors.QuadPart)
            >= StartLsn )
        {
            last_block->TotalSectors.QuadPart =
                max(StartLsn + NumberOfSectors,
                    last_block->StartSector.QuadPart + last_block->TotalSectors.QuadPart)
                - last_block->StartSector.QuadPart;
        }
        else
        {
            PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
            assert( node != NULL );

            RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
            node->StartSector.QuadPart = StartLsn;
            node->TotalSectors.QuadPart = NumberOfSectors;
            node->type = BLOCK_TYPE_BAD;
            InsertTailList( &m_BlockInforHead.BadBlockList,&node->List );
            node = NULL;
        }
    }
    else{

        for( list = m_BlockInforHead.BadBlockList.Flink;
            list != &m_BlockInforHead.BadBlockList;
            )
        {
            //�ϱ��Ѿ��ų��������
            assert( list != m_BlockInforHead.BadBlockList.Blink );

            PBLOCK_DESCRIPTOR block_prev = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                        BLOCK_DESCRIPTOR,
                                                                        List);
            list = list->Flink;
            PBLOCK_DESCRIPTOR block_next = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                            BLOCK_DESCRIPTOR,
                                                                            List);
            //Ѱ�Ҳ����
            if( StartLsn > block_next->StartSector.QuadPart )
                continue;
                
            //����鲢����������

            BOOLEAN bAdjPrev = (
                StartLsn > block_prev->StartSector.QuadPart &&
                StartLsn <= (block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart)
                );
            BOOLEAN bAdjNext = (
                StartLsn + NumberOfSectors >= block_next->StartSector.QuadPart /*&&
                StartLsn + NumberOfSectors < (block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart)*/
                );

            if( bAdjPrev && bAdjNext )
            {
                //ǰ�������
                block_prev->TotalSectors.QuadPart = 
                    max( block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart,
                        StartLsn + NumberOfSectors )
                    - block_prev->StartSector.QuadPart;
                while( (&m_BlockInforHead.BadBlockList != &block_next->List) &&
                    (block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart
                    >= block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart) )
                {
                    PBLOCK_DESCRIPTOR tmp = block_next;
                    block_next = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(block_next->List.Flink,
                                                                    BLOCK_DESCRIPTOR,
                                                                    List );
                    RemoveEntryList( &tmp->List );
                    free( tmp );tmp = NULL;
                }
                if((&m_BlockInforHead.BadBlockList != &block_next->List) && 
                    ( block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart
                    >= block_next->StartSector.QuadPart))
                {
                    block_prev->TotalSectors.QuadPart = 
                        max( block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart,
                            block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart)
                            - block_prev->StartSector.QuadPart;
                    RemoveEntryList( &block_next->List );
                    free( block_next );
                }
            }
            else if ( bAdjPrev )
            {
                block_prev->TotalSectors.QuadPart = 
                    (StartLsn + NumberOfSectors) - block_prev->StartSector.QuadPart;
            }
            else if( bAdjNext )
            {
                block_next->TotalSectors.QuadPart = 
                    max( block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart,
                         StartLsn + NumberOfSectors )
                    - StartLsn;
                block_next->StartSector.QuadPart = StartLsn;

                block_prev = block_next;
                block_next =(PBLOCK_DESCRIPTOR)CONTAINING_RECORD(block_prev->List.Flink,
                                                BLOCK_DESCRIPTOR,
                                                List );
                while( (&m_BlockInforHead.BadBlockList != &block_next->List) &&
                    (block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart
                    >= block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart) )
                {
                    PBLOCK_DESCRIPTOR tmp = block_next;
                    block_next = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(block_next->List.Flink,
                                                                    BLOCK_DESCRIPTOR,
                                                                    List );
                    RemoveEntryList( &tmp->List );
                    free( tmp );tmp = NULL;
                }
                if((&m_BlockInforHead.BadBlockList != &block_next->List) && 
                    ( block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart
                    >= block_next->StartSector.QuadPart))
                {
                    block_prev->TotalSectors.QuadPart = 
                        max( block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart,
                            block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart)
                            - block_prev->StartSector.QuadPart;
                    RemoveEntryList( &block_next->List );
                    free( block_next );
                }
            }
            else
            {
                PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
                assert( node != NULL );

                RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
                node->StartSector.QuadPart = StartLsn;
                node->TotalSectors.QuadPart = NumberOfSectors;
                node->type = BLOCK_TYPE_BAD;
                InsertHeadList( &block_prev->List,&node->List );
                node = NULL;
            }// end if bAdj....
                
            break;
        }// end for list

    }//else end

    //_ShowList();
}

VOID CNtfsController::AddDeadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors )
/*++
��������:�����������������������

����
    StartLsn:��ʼ�߼�������
    NumberOfSectors:������

����ֵ:��

˵��:������ָ������ȫ�𻵵�����,�޷����ʡ���ӦMHDDһ������б�ʾΪERROR������
--*/
{
    PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof(BLOCK_DESCRIPTOR));
    assert( node != NULL );
    RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR));
    node->StartSector.QuadPart = StartLsn;
    node->TotalSectors.QuadPart = NumberOfSectors;
    node->type = BLOCK_TYPE_BAD;
    InsertTailList( &m_BlockInforHead.UsedBlockList,&node->List);
    node = NULL;

}

BOOL CNtfsController::ProbeForRepair()
/*++
��������:����Ƿ���ϱ����Ҫ����������

����:��

����ֵ:���Ϸ���TRUE,ʧ�ܷ���FALSE
--*/
{
    BOOL bResult = TRUE;

    //У���ļ�ϵͳ
    if( !VerifyFileSystem() )
    {
        bResult = FALSE;
        goto exit;
    }



exit:
    return bResult;
}

extern FILE *hLogFile;
VOID CNtfsController::_ShowList()
{
#if 1
    fprintf(hLogFile,"////////////////////////////////////////////\n");
    fprintf(hLogFile,"Bad Block List\n");
    for( PBLOCK_DESCRIPTOR p = GetFirstBadBlock();
        p != NULL;
        p = GetNextBadBlock( p ))
    {
        fprintf(hLogFile,"start:%lld,len:%lld\n",p->StartSector.QuadPart,p->TotalSectors.QuadPart );
    }
    fprintf(hLogFile,"========================================\n");
#endif

#if 1
    fprintf(hLogFile,"Free Block List size = %.1lf GB\n",(double)(GetFreeBlockSize()/1024/1024)/1024);
    for( PBLOCK_DESCRIPTOR p = GetFirstFreeBlock();
        p != NULL;
        p = GetNextFreeBlock( p ))
    {
        fprintf(hLogFile,"start:%lld,len:%lld\n",p->StartSector.QuadPart,p->TotalSectors.QuadPart );
    }
    fprintf(hLogFile,"========================================\n");

    fprintf(hLogFile,"Used Block List size =%.1lf GB \n",(double)(GetUsedBlockSize()/1024/1024)/1024);
    for( PBLOCK_DESCRIPTOR p = GetFirstUsedBlock();
        p != NULL;
        p = GetNextUsedBlock( p ))
    {
        fprintf(hLogFile,"start:%lld,len:%lld\n",p->StartSector.QuadPart,p->TotalSectors.QuadPart );
    }
    fprintf(hLogFile,"========================================\n");
#endif
    fprintf(hLogFile,"////////////////////////////////////////////\n");

}

BOOL CNtfsController::VerifyFileSystem()
/*++
����������У���ļ�ϵͳ����ȷ��

��������

����ֵ���ļ�ϵͳ�������������������TRUE�����򷵻�FALSE

--*/
{
    ReportStateMessage("����У���ļ�ϵͳ...   ");
 
    BOOL bResult = FALSE;
    LPBYTE dataruns = NULL;
    LONG len_dataruns = 0;

    LONGLONG sum = 0;
    for( LONGLONG i = 0;
        i < (m_MftNumberOfRecord % 8==0?m_MftNumberOfRecord/8:m_MftNumberOfRecord/8 + 1);
        i++)
    {
        BYTE byte = m_MftBitmap[i];
        for( int j = 0;j < 8;j++)
        {
            LONGLONG file_id = i * 8 + j;
            ReportProgressState( (DWORD)file_id+1,(DWORD)m_MftNumberOfRecord );

            if( byte & (1 << j))
            {
                NTFS_FILE hFile = OpenNtfsFile( file_id );
                if( hFile == NULL)
                {
                    continue;
                }
                
                for( PLIST_ENTRY list = hFile->List.Flink;
                    list != &hFile->List;
                    list = list->Flink)
                {
                    PFILE_ATTRIBUTE_NODE node = (PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD(
                                                                list,
                                                                FILE_ATTRIBUTE_NODE,
                                                                List);
                    assert( node != NULL);
                    PATTR_RECORD pAttrRecord = (PATTR_RECORD)node->AttributeData;
                    if( pAttrRecord->non_resident == 0 )
                        continue;

                    dataruns = (LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset);
                    len_dataruns = node->Length - pAttrRecord->mapping_pairs_offset;
                    sum += GetNumberOfVcnsInDataRuns( dataruns,len_dataruns )
                          * m_ClusterSizeInBytes;
                    dataruns = NULL;len_dataruns = 0;
                }
                CloseFile( hFile );
            }
        }
    }
 
    //printf("\nsum = %lld\n",sum);
    bResult = ( sum == GetUsedBlockSize());
    if( bResult )
    {
        ReportStateMessage("\n�ļ�ϵͳУ��ɹ���\n");
        //_ShowList();
    }
    else
        ReportStateMessage("\n�ļ�ϵͳУ��ʧ��,������Chkdsk�޸�����\n");


    if( dataruns != NULL)free( dataruns );

    return bResult;
}

BOOL CNtfsController::StartRepairProgress()
/*++
��������:��ʼ�޸�����

����:��

����ֵ:�޸��ɹ�����TRUE,ʧ�ܷ���FALSE
--*/
{
    DbgPrint("Show list...");
    _ShowList();
    InitFreeAndUsedBlockList();
    DbgPrint("Show list after init again...");
    _ShowList();

    BOOL bResult = FALSE;
    LONG retValue=0;

    ReportStateMessage("���ڼ����Ӱ���ļ�...   ");

    //��������ļ���¼�Ƿ��ܻ���Ӱ����Ҫ�ƶ�����
    //ע�⣺�����$Mft,$Bitmap,��Ϊ�⼸���ļ�Ӱ�������ļ����޸�
    //������$Boot�ļ�

    for( LONGLONG i = 0;
        i < (m_MftNumberOfRecord % 8==0?m_MftNumberOfRecord/8:m_MftNumberOfRecord/8 + 1);
        i++)
    {
        BYTE byte = m_MftBitmap[i];
        for( int j = 0;j < 8;j++)
        {
            LONGLONG file_id = i * 8 + j;
            ReportProgressState( (DWORD)file_id+1,(DWORD)m_MftNumberOfRecord );
            if( file_id == FILE_MFT || file_id == FILE_Bitmap || file_id == FILE_BadClus || file_id == FILE_Boot)
                continue;

            if( byte & (1 << j))
            {
                CHAR buffer[256];
                retValue = CheckAndUpdateFile(file_id); 
                if( 1 == retValue)
                {
                    sprintf_s(buffer,256,"�ļ� %lld ��Ӱ�죬�����ƶ��ɹ�",file_id );
                }
                else if( 2 == retValue )
                {
                    sprintf_s(buffer,256,"�ļ� %lld ��Ӱ�죬���ƶ�ʧ��,�ļ����Ѿ�д����־!",file_id );
                }
                else if( retValue < 0 )
                {
                    sprintf_s(buffer,256,"�ļ� %lld �Ƿ�",file_id );
                }
                if( retValue != 0 )
                    ReportStateMessage( buffer );
            }
        }
    }

    //����$Bitmap�ļ�
    ReportStateMessage("���ڼ���ռ�λͼ�ļ�...   ");
    retValue = CheckAndUpdateFile( FILE_Bitmap );
    if( retValue == 1 )
    {
        DbgPrint("Bitmap file is influenced and updated!");
        ReportStateMessage("��ռ�λͼ�ļ����³ɹ���ɣ�   ");
    }
    else if( retValue == 2 )
    {
        DbgPrint("Bitmap file is influenced and updated failed!");
        ReportErrorMessage("��ռ�λͼ�ļ�����ʧ�ܣ�   ");
        goto exit;
    }
    else if( retValue == 0 )
    {
        DbgPrint("Bitmap file is not influenced.");
        ReportStateMessage("��ռ�λͼ�ļ�δ��Ӱ�죡   ");
    }
    else 
    {
        DbgPrint("Bitmap file is illegal");
        ReportErrorMessage("��ռ�λͼ�ļ��Ƿ�!   ");
        goto exit;
    }

    //����$Mft�ļ�
    ReportStateMessage("���ڼ��$Mft�ļ�...   ");
    retValue = this->CheckAndUpdateFile( FILE_MFT );
    if( retValue == 1 )
    {
        DbgPrint("Bitmap file is influenced and updated!");
        ReportStateMessage("$Mft�ļ����³ɹ���ɣ�   ");
    }
    else if( retValue == 2 )
    {
        DbgPrint("$Mft file is influenced and updated failed!");
        ReportErrorMessage("$Mft�ļ�����ʧ�ܣ�   ");
        goto exit;
    }
    else if( retValue == 0 )
    {
        DbgPrint("$Mft file is not influenced.");
        ReportStateMessage("$Mft�ļ�δ��Ӱ�죡   ");
    }
    else 
    {
        DbgPrint("$Mft file is illegal");
        ReportErrorMessage("$Mft�ļ��Ƿ�!   ");
        goto exit;
    }

    //����$BadClus �ļ�
    ReportStateMessage("���ڸ���$BadClus�ļ�...   ");
    bResult = UpdateBadClus();
    if(bResult)
    {
        ReportStateMessage("$BadClus�ļ�������ɣ�");
    }
    else
    {
        ReportStateMessage("$BadClus�ļ�����ʧ�ܣ�");
        goto exit;
    }

    //���´���λͼ
    ReportStateMessage("����д���µľ�λͼ...   ");
    bResult = UpdateBitmap();
    if(bResult)
    {
        ReportStateMessage("��λͼд�����!");
    }
    else
    {
        ReportErrorMessage("��λͼд��ʧ�ܣ�");
        goto exit;
    }

    //�����ļ���¼����λͼ
    ReportStateMessage("����д���µ��ļ���¼����λͼ...   ");
    bResult = UpdateMftBitmap();
    if(bResult)
    {
        ReportStateMessage("�ļ���¼����λͼд�����!");
    }
    else
    {
        ReportErrorMessage("�ļ���¼����λͼд��ʧ�ܣ�");
        goto exit;
    }

    //����������������
    ReportStateMessage("���ڸ�����������...   ");
    bResult = WriteLogicalSector( &m_BootSect, sizeof(m_BootSect), 0 ,this->m_PhysicDiskSectorSize);
    if( !bResult )
    {
        DbgPrint("update boot sector failed!");
        ReportErrorMessage("������������ʧ��!   ");
        goto exit;
    }
    else
        ReportStateMessage("���������������   ");

    //����$MFTMirr�ļ�,ʹ֮������$MFT�ļ�ͬ��
    ReportStateMessage("����ͬ��$MFTMirr�ļ�...   ");
    bResult = UpdateMftMirr();
    if( !bResult )
    {
        DbgPrint("update $MFTMirr failed!");
        ReportErrorMessage("ͬ��$MFTMirr�ļ�ʧ��!   ");
        goto exit;
    }
    else
    {
        ReportStateMessage("ͬ��$MFTMirr�ļ���ɣ�");
    }
    bResult = TRUE;
    
    ReportStateMessage("�޸���ɣ�");
exit:

    return bResult;
}

BOOL CNtfsController::StopRepairProgress()
/*++
��������:��ֹ�޸�����

����:��

����ֵ:��ֹ�ɹ�����TRUE,ʧ�ܷ���FALSE
--*/
{
    return TRUE;
}

BOOL CNtfsController::InitController()
/*++
��������:��ʼ��Controller,��ͬ���ļ�ϵͳ�в�ͬ�ĳ�ʼ������,������������
         ʵ�ִ˽ӿ�,����ʵ�ֶԲ�ͬ�ļ�ϵͳ��֧�֡�

����:��

����ֵ:�ɹ�����TRUE,ʧ�ܷ���FALSE

˵��:��������NTFS��InitController�ľ���ʵ��,���ܰ�����ʼ���ڲ���ص������
--*/
{
    BOOL    bStatus = TRUE;

    DbgPrint("init controller is called!\n");

    ReleaseResources();

    //��ʼ��Ѱַ$MFTҪ�õ��Ĺؼ�����

    //�ļ���¼��С
    if( m_BootSect.clusters_per_mft_record < 0 )
        m_MftRecordLength = 1 << -1 * m_BootSect.clusters_per_mft_record;
    else
        m_MftRecordLength = m_BootSect.clusters_per_mft_record
        * m_ClusterSizeInBytes;

    //��ʼ������$MFT���ļ���¼������
    LPBYTE  clusterBuffer = (LPBYTE)malloc( m_ClusterSizeInBytes );
    assert( clusterBuffer != NULL);
    bStatus = ReadLogicalCluster( clusterBuffer,m_ClusterSizeInBytes,
        m_BootSect.mft_lcn );
    if( !bStatus )
        goto exit;
    bStatus = ntfs_is_file_recordp( clusterBuffer );
    if( !bStatus )
        goto exit;

    //��ʼ��$MFT�ļ�,Ŀ���ǳ�ʼ��һЩ���Ա������eg,m_MftDataRuns...��,Ϊ��һ����NTFS���ļ�������׼��
    bStatus = InitMftFile( clusterBuffer,m_ClusterSizeInBytes );
    if( !bStatus )
        goto exit;

    bStatus = InitBitmap();
    if ( !bStatus )
        goto exit;

    bStatus = InitMftBitmap();
    if( !bStatus )
        goto exit;

    bStatus = InitFreeAndUsedBlockList();
    if( !bStatus )
        goto exit;

    bStatus = InitBadBlockList();
    if( !bStatus )
        goto exit;

    //========================================================================================

    DbgPrint("ShowList....");
    _ShowList();

exit:
    if( clusterBuffer != NULL)
    {
        free( clusterBuffer );
        clusterBuffer = NULL;
    }

    return bStatus;
}



VOID CNtfsController::ReleaseResources()
/*++
��������:�ͷű������������Դ

����:��

����ֵ:��
--*/
{
    DbgPrint("called!");

    DestroyListNodes( &m_BlockInforHead.BadBlockList);
    DestroyListNodes( &m_BlockInforHead.DeadBlockList);
    DestroyListNodes( &m_BlockInforHead.FreeBlockList);
    DestroyListNodes( &m_BlockInforHead.UsedBlockList);
    m_BlockInforHead.BadBlockSize.QuadPart = 
        m_BlockInforHead.FreeBlockSize.QuadPart = 
        m_BlockInforHead.UsedBlockSize.QuadPart = 0;

    if( m_MftDataRuns != NULL){
        free( m_MftDataRuns );
        m_MftDataRuns = NULL;
    }

    if( m_Bitmap != NULL){
        free( m_Bitmap );
        m_Bitmap = NULL;
    }

    if( m_MftBitmap != NULL)
    {
        free( m_MftBitmap );
        m_MftBitmap = NULL;
    }

}

BOOL CNtfsController::InitFreeAndUsedBlockList()
/*++
��������:��NTFS���λͼ�л��δ������ѷ���������������Ϣ

����:��

����ֵ:�ɹ�����TRUE,ʧ�ܷ���FALSE

˵��:λͼ�ļ������Դ�Ϊ��λ��,Ҫ����Ϊ������
    ������Ҫ����������Ӧ������( m_BlockInforHead )
--*/
{
    LONGLONG currBlockStart = 0,currBlockLen = 0;   //��λΪ��
    DWORD bit_test = 1;                             //����λ����

    //����ԭ������,׼�����³�ʼ��
    DestroyListNodes( &m_BlockInforHead.FreeBlockList);
    DestroyListNodes( &m_BlockInforHead.UsedBlockList);
    m_BlockInforHead.FreeBlockSize.QuadPart = 
        m_BlockInforHead.UsedBlockSize.QuadPart = 0;

    BYTE type = ((*(PDWORD)m_Bitmap & bit_test) != 0);     //1Ϊʹ��,0Ϊδ��
    BYTE tmp = m_Bitmap[ m_BitmapLength - 1];
    m_Bitmap[ m_BitmapLength - 1] &= 0x7f;//���ڽ������к�ռ�ÿ�����ʱ���㴦�����һ��ռ�ÿ顣

    for( LPBYTE p = m_Bitmap;
           p < m_Bitmap + m_BitmapLength;
           )          //m_BitmapLength��8�ֽڶ���
    {
        if( ((*(PDWORD)p & bit_test) != 0) != type )
        {
            //printf( "type:%d,start:%lld,len:%lld\n",type,currBlockStart,currBlockLen );
            
            //��ʼ����Ϣ���������,����������
            PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof(BLOCK_DESCRIPTOR));
            assert( node != NULL );
            RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
            node->StartSector.QuadPart = currBlockStart * m_BootSect.bpb.sectors_per_cluster;
            node->TotalSectors.QuadPart = currBlockLen * m_BootSect.bpb.sectors_per_cluster;
            if( type )
            {
                node->type = BLOCK_TYPE_USED;
                InsertTailList( &m_BlockInforHead.UsedBlockList,&node->List);
                node = NULL;
                m_BlockInforHead.UsedBlockSize.QuadPart += m_ClusterSizeInBytes * currBlockLen;
            }
            else
            {
                node->type = BLOCK_TYPE_FREE;
                InsertTailList( &m_BlockInforHead.FreeBlockList,&node->List);
                node = NULL;
                m_BlockInforHead.FreeBlockSize.QuadPart += m_ClusterSizeInBytes * currBlockLen;
            }

            type = ((*(PDWORD)p & bit_test) != 0);
            currBlockStart = currBlockStart + currBlockLen;
            currBlockLen = 0;
        }

        if( bit_test == 1 && (*(PDWORD)p == 0xfffffffful ||  *(PDWORD)p == 0) )
        {
            currBlockLen += 32;
            p += 4;
            continue;
        }
           
        for( ;bit_test != 0;bit_test <<=1  )
        {
            if( ((*(PDWORD)p & bit_test) != 0) != type )
                break;

            currBlockLen++;
        }
        if( bit_test == 0)
        {
            bit_test = 1;
            p += 4;
        }
    }
    m_Bitmap[ m_BitmapLength - 1] = tmp;

    //�������һ��ռ�ÿ�Ĵ�С����ȷֵ
    PLIST_ENTRY list = m_BlockInforHead.UsedBlockList.Blink;
    PBLOCK_DESCRIPTOR p = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                BLOCK_DESCRIPTOR,
                                                                List);
    p->TotalSectors.QuadPart -= (m_BitmapLength * 8 - 
                                m_BootSect.number_of_sectors / m_BootSect.bpb.sectors_per_cluster//��Ч����
                                - 1) * m_BootSect.bpb.sectors_per_cluster;
    m_BlockInforHead.UsedBlockSize.QuadPart -= 
                                    (m_BitmapLength * 8 - 
                                    m_BootSect.number_of_sectors / m_BootSect.bpb.sectors_per_cluster//��Ч����
                                    - 1) * m_ClusterSizeInBytes;
    if( p->TotalSectors.QuadPart == 0 )
    {
        RemoveEntryList( &p->List );
        free( p );
    }

    assert(  type == 0 );
    return TRUE;
}


VOID CNtfsController::DestroyListNodes(PLIST_ENTRY ListHead )
/*++
��������:�ͷſ�������Ϣ����Ľ���ڴ�

���� ListHead:����ͷ���ָ��

����ֵ:��
--*/
{
    while( !IsListEmpty( ListHead ))
    {
        PLIST_ENTRY list = RemoveHeadList( ListHead );
        PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
            BLOCK_DESCRIPTOR,
            List);
        assert( node );
        free(node);
    }
}

BOOL CNtfsController::ReadLogicalCluster( OUT LPVOID Buffer,
                                         IN DWORD BufferSize,
                                         IN LONGLONG Lcn,
                                         IN DWORD TryTime,
                                         IN BYTE BadByte)
/*++
��������:��ȡ�߼���

����:
    Buffer:���������,����һ�صĴ�С
    BufferSize:ָ������������Ĵ�С,����Ϊһ��
    Lcn:�߼��غ�
    TryTime:������ȡʧ�ܺ����Դ���,Ĭ��Ϊ1��
    BadByte:����������ȡʧ�ܺ������ַ�

����ֵ:�ɹ���һ�ص�������������ȷ��ȡ������TRUE,ʧ�ܷ���FALSE

--*/
{
    BOOL bOk = FALSE,bResult = TRUE;
    DWORD   sector_size = m_BootSect.bpb.bytes_per_sector;
    DWORD   sectors_per_cluster = m_BootSect.bpb.sectors_per_cluster;

    assert( BufferSize >= sector_size * sectors_per_cluster );

    for( DWORD i = 0;i < sectors_per_cluster;i++)
    {
        for( DWORD count = 0;count < TryTime;count++)
        {
            bOk = ReadLogicalSector( (LPBYTE)Buffer + i * sector_size,
                sector_size,
                Lcn * sectors_per_cluster + i,
				this->m_PhysicDiskSectorSize);
            if( bOk )break;
        }
        if( !bOk )
        {
            memset( (LPBYTE)Buffer + i * sector_size,BadByte,sector_size );
            bResult = FALSE;
        }
    }

    return bResult;
}

BOOL CNtfsController::WriteLogicalCluster( IN LPVOID Buffer,
                                          IN DWORD DataLen,
                                          IN LONGLONG Lcn,
                                          IN DWORD TryTime /*= 1*/)
/*++
��������:���д���߼���

����:
    Buffer:���뻺����
    DataLen:���ݳ��ȣ��ֽڣ�,������һ�ش�С
    Lcn:�߼��غ�
    TryTime:������ȡʧ�ܺ����Դ���,Ĭ��Ϊ1��

����ֵ:�ɹ���һ�ص�������������ȷд�룩����TRUE,ʧ�ܷ���FALSE
--*/
{
    BOOL bOk = FALSE,bResult = TRUE;
    DWORD   sector_size = m_BootSect.bpb.bytes_per_sector;
    DWORD   sectors_per_cluster = m_BootSect.bpb.sectors_per_cluster;

    assert( DataLen <= sector_size * sectors_per_cluster );
    BYTE *buf = (BYTE *)malloc( sector_size * sectors_per_cluster );
    assert( buf != NULL);
    RtlZeroMemory( buf,sector_size * sectors_per_cluster );
    memcpy( buf,Buffer,DataLen );

    for( DWORD i = 0;i < sectors_per_cluster;i++)
    {
        for( DWORD count = 0;count < TryTime;count++)
        {
            bOk = WriteLogicalSector( (LPBYTE)buf + i * sector_size,
                sector_size,
                Lcn * sectors_per_cluster + i, 
				this->m_PhysicDiskSectorSize);
            if( bOk )break;
        }
        if( !bOk )
        {
            char buffer[256];
            sprintf_s( buffer,256,"write logical sector %d failed!\n",
                Lcn * sectors_per_cluster + i );
            ReportErrorMessage( buffer );
            bResult = FALSE;
        }
    }
    free( buf );

    return bResult;
}

BOOL CNtfsController::CopyLogicalClusterBlock( LONGLONG SourceLcn,LONGLONG DestLcn,LONGLONG NumberOfLcns)
/*++
--*/
{
    BOOL bOk = TRUE;
    bOk = CopyBlock( m_hDisk,
        m_VolumeStartSector.QuadPart + SourceLcn * m_BootSect.bpb.sectors_per_cluster,
        m_VolumeStartSector.QuadPart + DestLcn * m_BootSect.bpb.sectors_per_cluster,
        NumberOfLcns * m_BootSect.bpb.sectors_per_cluster, this->m_PhysicDiskSectorSize);

    return bOk;
}

LONGLONG CNtfsController::GetNumberOfVcnsInDataRuns( LPBYTE DataRuns,DWORD Length )
/*++
��������:��ȡDataruns�������ݵĴ�����

����:
    DataRuns:NTFS�е�DataRuns�ṹ
    Length:DataRuns�����鳤��(��һ����dataruns��ʵ�ʳ��ȣ�

����ֵ:�ɹ����ض�Ӧ�Ĵ�����,ʧ�ܷ���0
--*/
{
    LONGLONG  len = 0,totalLen = 0;

    for(DWORD i = 0;
        i < Length;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( DataRuns[i] == 0 )break;

        cStartLcnBytes = ( DataRuns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (DataRuns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        if( cStartLcnBytes != 0 )
        {
            //��ȡ��ǰ����������
            len = 0;
            for( DWORD j = cLenLcnBytes;j > 0;j--)
            {
                len = (len << 8) | DataRuns[i + j ]; 
            }
            totalLen += len;
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    return totalLen;
}

LONGLONG CNtfsController::GetLastStartLcnInDataruns( LPBYTE DataRuns,DWORD Length )
/*++
��������:��ȡDataruns�������������һ����Ч���ݿ����ʼLCN

����:
    DataRuns:NTFS�е�DataRuns�ṹ
    Length:DataRuns�����鳤��(��һ����dataruns��ʵ�ʳ��ȣ�

����ֵ:�ɹ����ض�Ӧ��LCN��ʧ�ܷ���-1

--*/
{
    LONGLONG startLcn = 0;

    if( DataRuns == NULL)return -1;

    for(DWORD i = 0;
        i < Length;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( DataRuns[i] == 0 )break;

        cStartLcnBytes = ( DataRuns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (DataRuns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        if( cStartLcnBytes != 0)
        {
            //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
            LONGLONG tmp = 0;
            if( DataRuns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                tmp = -1ll;
            for( DWORD j = cStartLcnBytes;j > 0;j-- )
            {
                tmp = ( tmp << 8 ) | DataRuns[i + cLenLcnBytes + j ];
            }
            startLcn = startLcn + tmp;
            assert( startLcn >= 0 );
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    return startLcn<0?-1:startLcn;
}

DWORD    CNtfsController::GetDataRunsLength( IN LPBYTE DataRuns,DWORD Length )
/*++
��������:��ȡDataruns�������Ч���ȣ���������β��һ��0�ֽڣ�

����:
    DataRuns:NTFS�е�DataRuns�ṹ
    Length:DataRuns�����鳤��(��һ����dataruns��ʵ�ʳ��ȣ�

����ֵ:�ɹ����ض�Ӧ���ֽ���,ʧ�ܷ���0
--*/
{
    DWORD i = 0;
    for(i = 0;
        i < Length;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( DataRuns[i] == 0 )break;

        cStartLcnBytes = ( DataRuns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (DataRuns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    return i;

}

LONGLONG CNtfsController::GetDataRunsValue(
    IN LPBYTE DataRuns,
    IN DWORD Length,
    OUT LPVOID Buffer,
    IN LONGLONG BufferLength )
/*++
��������:��Dataruns����ȡ���������ݡ�

����:
    DataRuns:NTFS�е�DataRuns�ṹ
    Length:DataRuns�����鳤��(��һ����dataruns��ʵ�ʳ��ȣ�
    Buffer:��������������ڽ�������
    BufferLength���������������

����ֵ:�ɹ�����0,ʧ�ܷ��� -1,���BufferΪ��,�����������ٵ�Buffer���ȣ�����0)

--*/
{
    LONGLONG vcns = GetNumberOfVcnsInDataRuns( DataRuns,Length );
    assert( vcns > 0 );
    if( Buffer == NULL)
        return vcns * m_ClusterSizeInBytes;

    if( BufferLength < vcns * m_ClusterSizeInBytes )
    {
        DbgPrint(" buffer length is too small!,will return -1");
        return -1;
    }

    BOOL bOk = TRUE;
    for( LONGLONG i = 0;i < vcns;i++)
    {
        LONGLONG lcn = VcnToLcn( i,DataRuns,Length );
        bOk = ReadLogicalCluster( (LPBYTE)Buffer + i * m_ClusterSizeInBytes,
                            m_ClusterSizeInBytes,
                            lcn );
        if( !bOk )break;
    }

    return bOk?0:-1;
}

LONGLONG CNtfsController::VcnToLcn( LONGLONG Vcn,LPBYTE DataRuns,DWORD Length )
/*++
��������:����������ת��Ϊ�߼�������

����:
    Vcn:����������
    DataRuns:NTFS�е�DataRuns�ṹ
    Length:DataRuns�����鳤��(��һ����dataruns��ʵ�ʳ��ȣ�

����ֵ:ת���ɹ�����Vcn��Ӧ��Lcn,���򷵻� -1

--*/
{
    LONGLONG startLcn = 0,len = 0,totalLen = 0,result = -1;

    if( DataRuns == NULL)return -1;

    for(DWORD i = 0;
        i < Length;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( DataRuns[i] == 0 )break;

        cStartLcnBytes = ( DataRuns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (DataRuns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        if( cStartLcnBytes != 0)
        {
            //��ȡ��ǰ����������
            len = 0;
            for( DWORD j = cLenLcnBytes;j > 0;j--)
            {
                len = (len << 8) | DataRuns[i + j ]; 
            }

            //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
            LONGLONG tmp = 0;
            if( DataRuns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                tmp = -1ll;
            for( DWORD j = cStartLcnBytes;j > 0;j-- )
            {
                tmp = ( tmp << 8 ) | DataRuns[i + cLenLcnBytes + j ];
            }
            startLcn = startLcn + tmp;
            assert( startLcn >= 0 );

            if( Vcn >= totalLen && Vcn < totalLen + len )
            {
                result = Vcn - totalLen + startLcn;
                break;
            }
            totalLen += len;
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    return result;
}

LONG CNtfsController::BlockListToDataRuns(PLIST_ENTRY BlockListHead, LPBYTE Dataruns, LONGLONG DatarunsLength)
/*++
��������������BlockList����������ת��Ϊ��Ӧ��Dataruns����

������
    BlockListHead������Ϣ����ͷ���ָ��
    Dataruns:���������ָ�룬���ڽ���ת����ɵ�Dataruns
    DatarunsLength:ָ������������ĳ���

����ֵ:�ɹ�����0,ʧ�ܷ��� -1,���DatarunsΪNULL,��������Dataruns���ȣ�����0)

--*/
{
    LONG length = 0;
    DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0,i = 0;
    LONGLONG startLcn = 0,lenLcn = 0,prevLcn = 0;

    for( PLIST_ENTRY list = BlockListHead->Flink;
        list != BlockListHead;
        list = list->Flink)
    {
        PBLOCK_DESCRIPTOR block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                    BLOCK_DESCRIPTOR,
                                                                    List);
        assert( block != NULL);

        BYTE    sectors_per_cluster = m_BootSect.bpb.sectors_per_cluster;
        LONGLONG startCluster = block->StartSector.QuadPart / sectors_per_cluster;
        LONGLONG lenInCluster = block->TotalSectors.QuadPart % sectors_per_cluster==0?
            block->TotalSectors.QuadPart / sectors_per_cluster:block->TotalSectors.QuadPart/sectors_per_cluster+1;

        startLcn = startCluster - prevLcn;
        prevLcn = startCluster;
        lenLcn = lenInCluster;
        assert( lenLcn > 0);

        //��������startLcn�������ٵ��ֽ���
        cStartLcnBytes = CompressLongLong( startLcn );

        //��������lenLcn�������ٵ��ֽ��� 
        cLenLcnBytes = CompressLongLong( lenLcn );

        length += cStartLcnBytes + cLenLcnBytes + 1;
    }
    length++;
    if( length % 8 != 0 )length = (length / 8 + 1)*8;

    if( Dataruns == NULL)
        return length;
    if( DatarunsLength < length )
        return -1;


    //������仺����:-)
    cStartLcnBytes = 0,cLenLcnBytes = 0,i = 0;
    startLcn = 0,lenLcn = 0,prevLcn = 0;
    for( PLIST_ENTRY list = BlockListHead->Flink;
        list != BlockListHead;
        list = list->Flink)
    {
        PBLOCK_DESCRIPTOR block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                    BLOCK_DESCRIPTOR,
                                                                    List);
        assert( block != NULL);

        BYTE    sectors_per_cluster = m_BootSect.bpb.sectors_per_cluster;
        LONGLONG startCluster = block->StartSector.QuadPart / sectors_per_cluster;
        LONGLONG lenInCluster = block->TotalSectors.QuadPart % sectors_per_cluster==0?
            block->TotalSectors.QuadPart / sectors_per_cluster:block->TotalSectors.QuadPart/sectors_per_cluster+1;

        startLcn = startCluster - prevLcn;
        prevLcn = startCluster;
        lenLcn = lenInCluster;
        assert( lenLcn > 0 );

        //��������startLcn�������ٵ��ֽ���
        cStartLcnBytes = CompressLongLong( startLcn );

        //��������lenLcn�������ٵ��ֽ��� 
        cLenLcnBytes = CompressLongLong( lenLcn );

        Dataruns[i++] = (BYTE)((cStartLcnBytes << 4) | cLenLcnBytes);
        LONGLONG tmp = lenLcn;
        for( BYTE j = 0;j < cLenLcnBytes;j++)
        {
            Dataruns[i++] = (BYTE)(tmp & 0xff);
            tmp >>= 8;
        }
        tmp = startLcn;
        for( BYTE j = 0;j < cStartLcnBytes;j++)
        {
            Dataruns[i++] = (BYTE)(tmp & 0xff);
            tmp >>= 8;
        }
    }
    Dataruns[i++] = 0;

    return 0;
}

LONG CNtfsController::DataRunsToSpaceDataRuns(LPBYTE dataruns, LONGLONG len_dataruns, LPBYTE bad_dataruns, LONGLONG len_bad_dataruns)
/*++
����������������Dataruns����ת��Ϊ���������ռ���Ϣ��dataruns,
           ������������Bitmap�б���������Ϊռ��

������
    dataruns������dataruns�Ļ�����ָ��
    len_dataruns:����dataruns�����Ļ��������ȣ��ֽڣ�
    bad_dataruns:���������ָ�룬���ڽ���ת����ɵ�dataruns
    len_bad_dataruns:ָ������������ĳ���

����ֵ:�ɹ�����0,ʧ�ܷ��� -1,���bad_datarunsΪNULL,��������dataruns���ȣ�����0)

--*/
{
    
    //����ת�������Ҫ�Ļ���������
    LONG lengthRequired = 0;
    LONGLONG startLcn = 0,len = 0,prev_len = 0,curr_len = 0;
    BYTE cCurrLenBytes = 0;

    for(LONG i = 0;
        i < len_dataruns;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( dataruns[i] == 0 )break;

        cStartLcnBytes = ( dataruns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (dataruns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        if( cStartLcnBytes != 0)
        {
            //��ȡ��ǰ����������
            len = 0;
            for( DWORD j = cLenLcnBytes;j > 0;j--)
            {
                len = (len << 8) | dataruns[i + j ]; 
            }

            //��ȡ��ǰ��������ʼ�غţ��������һ����������ƫ��,�з��ţ�
            LONGLONG tmp = 0;
            if( dataruns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                tmp = -1ll;
            for( DWORD j = cStartLcnBytes;j > 0;j-- )
            {
                tmp = ( tmp << 8 ) | dataruns[i + cLenLcnBytes + j ];
            }
            startLcn = startLcn + tmp;
            
            curr_len = tmp - prev_len;
            prev_len = len;
            cCurrLenBytes = CompressLongLong( curr_len );
            if( curr_len < 0 )cCurrLenBytes--;
            //bad_dataruns[len_bad_dataruns++]=cCurrLenBytes;
            lengthRequired++;
            //memcpy_s( bad_dataruns+len_bad_dataruns,m_MftRecordLength,&curr_len,cCurrLenBytes);
            //len_bad_dataruns += cCurrLenBytes;
            lengthRequired += cCurrLenBytes;
            //memcpy_s( bad_dataruns+len_bad_dataruns,
            //    m_MftRecordLength,
            //    &dataruns[i],
            //    cStartLcnBytes + cLenLcnBytes + 1);
            //len_bad_dataruns += cStartLcnBytes + cLenLcnBytes + 1;
            lengthRequired += cStartLcnBytes + cLenLcnBytes + 1;
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    curr_len = /*m_VolumeTotalSectors.QuadPart*/m_BootSect.number_of_sectors / m_BootSect.bpb.sectors_per_cluster
                - startLcn
                - prev_len;
    cCurrLenBytes = CompressLongLong( curr_len );
    if( curr_len < 0 )cCurrLenBytes--;

    //bad_dataruns[len_bad_dataruns++]=cCurrLenBytes;
    lengthRequired++;
    //memcpy_s( bad_dataruns+len_bad_dataruns,m_MftRecordLength,&curr_len,cCurrLenBytes);
    //len_bad_dataruns += cCurrLenBytes;
    lengthRequired += cCurrLenBytes;

    //bad_dataruns[len_bad_dataruns++] = 0;
    //len_bad_dataruns++;
    lengthRequired++;
    if( lengthRequired % 8 != 0 )
        lengthRequired = (lengthRequired / 8 + 1)*8;

    if( bad_dataruns == NULL)
        return lengthRequired;
    else if( len_bad_dataruns < lengthRequired )
        return -1;

    //������������

    startLcn = 0,len = 0,prev_len = 0,curr_len = 0;
    cCurrLenBytes = 0;
    len_bad_dataruns = 0;

    for(LONG i = 0;
        i < len_dataruns;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( dataruns[i] == 0 )break;

        cStartLcnBytes = ( dataruns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (dataruns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        if( cStartLcnBytes != 0)
        {
            //��ȡ��ǰ����������
            len = 0;
            for( DWORD j = cLenLcnBytes;j > 0;j--)
            {
                len = (len << 8) | dataruns[i + j ]; 
            }

            //��ȡ��ǰ��������ʼ�غţ��������һ����������ƫ��,�з��ţ�
            LONGLONG tmp = 0;
            if( dataruns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                tmp = -1ll;
            for( DWORD j = cStartLcnBytes;j > 0;j-- )
            {
                tmp = ( tmp << 8 ) | dataruns[i + cLenLcnBytes + j ];
            }
            startLcn = startLcn + tmp;
            
            curr_len = tmp - prev_len;
            prev_len = len;
            cCurrLenBytes = CompressLongLong( curr_len );
            bad_dataruns[len_bad_dataruns++]=cCurrLenBytes;
            memcpy_s( bad_dataruns+len_bad_dataruns,m_MftRecordLength,&curr_len,cCurrLenBytes);
            len_bad_dataruns += cCurrLenBytes;
            memcpy_s( bad_dataruns+len_bad_dataruns,
                m_MftRecordLength,
                &dataruns[i],
                cStartLcnBytes + cLenLcnBytes + 1);
            len_bad_dataruns += cStartLcnBytes + cLenLcnBytes + 1;
            
            //��Bitmap����Ӧ��λ���Ϊռ��
            for(LONGLONG ii = startLcn;
                ii < startLcn + len;
                ii++)
            {
                m_Bitmap[ ii / 8 ] |= (1 << (ii % 8));
            }
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    curr_len = /*m_VolumeTotalSectors.QuadPart*/m_BootSect.number_of_sectors / m_BootSect.bpb.sectors_per_cluster
                - startLcn
                - prev_len;
    cCurrLenBytes = CompressLongLong( curr_len );
    bad_dataruns[len_bad_dataruns++]=cCurrLenBytes;
    memcpy_s( bad_dataruns+len_bad_dataruns,m_MftRecordLength,&curr_len,cCurrLenBytes);
    len_bad_dataruns += cCurrLenBytes;
    bad_dataruns[len_bad_dataruns++] = 0;

    return 0;
}

BOOL CNtfsController::InitMftFile( IN LPVOID MftRecordCluster,IN DWORD BufferLength )
/*++
��������:��ʼ��$MFT�ļ���������Ϣ

����:
    MftRecordCluster:ָ�����$MFT�ļ���¼�Ĵػ�����
    BufferLength:ָ����������С

����ֵ:�ɹ�����TRUE���������Ա����m_MftDataRuns��m_MftDataRunsLength.
        ʧ�ܷ���FALSE

--*/
{
    PFILE_INFORMATION   pFileInfor = InitNtfsFile( MftRecordCluster,BufferLength,FILE_MFT );
    if( pFileInfor == NULL)return FALSE;
    pFileInfor->FileRecordId = FILE_MFT;

    //��ʼ������Ѱַ$MFT�ļ���Dataruns�ṹ
    PLIST_ENTRY list;
    for( list = pFileInfor->List.Flink;
        list != &pFileInfor->List;
        list = list->Flink )
    {
        if(((PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD( list,FILE_ATTRIBUTE_NODE,List ))
            ->AttributeType == AT_DATA ) break;
    }
    if( list == &pFileInfor->List )return FALSE;

    PATTR_RECORD pAttrRecord = (PATTR_RECORD)((PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD( list,FILE_ATTRIBUTE_NODE,List ))
        ->AttributeData;
    assert( pAttrRecord->non_resident == 1 );
    m_MftDataRunsLength = pAttrRecord->length - pAttrRecord->mapping_pairs_offset;
    assert( m_MftDataRuns == NULL );
    m_MftDataRuns = (LPBYTE)malloc( m_MftDataRunsLength );
    assert( m_MftDataRuns != NULL );
    memcpy_s( m_MftDataRuns,m_MftDataRunsLength,
        (LPVOID)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset),
        m_MftDataRunsLength );

    //����$MFT�ļ����ļ���¼��
    m_MftNumberOfRecord = pFileInfor->FileSize / m_MftRecordLength;
    CloseFile( pFileInfor );
    pFileInfor = NULL;

    return TRUE;

}

BOOL CNtfsController::InitBitmap()
/*++
��������:��ʼ��Bitmap,���ں�������ռ�ͳ��,����Ȳ���

����:��

����ֵ:�ɹ�����TRUE,����ʼ�����Ա����m_Bitmap��m_BitmapLength
        ʧ�ܷ���FALSE
--*/
{
	LPVOID buffer = NULL;
    BOOL bResult = TRUE;

    NTFS_FILE file = OpenNtfsFile( FILE_Bitmap );
    if( file == NULL)
    {
        bResult = FALSE;
        goto exit;
    }

    LONG length = GetAttributeValue( file,AT_DATA,NULL,0 );
    if( length <= 0 )
    {
        bResult = FALSE;
        goto exit;
    }

    buffer = malloc( length );
    assert( buffer != NULL );
    BOOL bDataruns = FALSE;
    if( 0 != GetAttributeValue( file,AT_DATA,buffer,length,&bDataruns ))
    {
        bResult = FALSE;
        goto exit;
    }
    assert( bDataruns == TRUE );

    LONGLONG vcns = GetNumberOfVcnsInDataRuns( (LPBYTE)buffer,length );
    if( vcns <= 0 )
    {
        bResult = FALSE;
        goto exit;
    }

    m_Bitmap = (LPBYTE)malloc( (size_t)(vcns * m_ClusterSizeInBytes));
    assert( m_Bitmap != NULL );
    RtlZeroMemory( m_Bitmap,(size_t)(vcns * m_ClusterSizeInBytes));

    for( LONGLONG i = 0;i < vcns;i++)
    {
        LONGLONG lcn = VcnToLcn( i,(LPBYTE)buffer,length );
        if( lcn == -1 ){
            bResult = FALSE;
            free( m_Bitmap );
            m_Bitmap = NULL;
            goto exit;
        }

        bResult = ReadLogicalCluster( m_Bitmap + i * m_ClusterSizeInBytes,m_ClusterSizeInBytes,lcn );
        if( !bResult )
        {
            free( m_Bitmap );
            m_Bitmap = NULL;
            goto exit;
        }
    }

    m_BitmapLength = file->FileSize;//����һ����8�ֽڶ����ֵ

exit:
    CloseFile( file );
    file = NULL;

    if( buffer != NULL){
        free(buffer );
        buffer = NULL;
    }

    return bResult;
}

BOOL CNtfsController::InitMftBitmap()
/*++
��������:��ʼ��MftBitmap,���ں��������ļ���¼��ķ�����յȡ�

����:��

����ֵ:�ɹ�����TRUE,����ʼ�����Ա����m_MftBitmap��m_MftBitmapLength
        ʧ�ܷ���FALSE
--*/
{
    BOOL bResult = TRUE,bDataruns = FALSE;;
    LPBYTE dataruns = NULL;
    LONG len_dataruns = 0;

    NTFS_FILE hMft = OpenNtfsFile( FILE_MFT );
    if( hMft == NULL)
    {
        bResult = FALSE;
        DbgPrint("open mft file failed!");
        ReportErrorMessage("���ļ����ʧ��!   ");
        goto exit;
    }

    len_dataruns = GetAttributeValue( hMft,AT_BITMAP,NULL,0,&bDataruns);
    assert( len_dataruns > 0 );
    assert( bDataruns );
    dataruns = (LPBYTE)malloc( len_dataruns );
    assert( dataruns > 0 );

    if( 0 != GetAttributeValue( hMft,AT_BITMAP,dataruns,len_dataruns ))
    {
        bResult = FALSE;
        DbgPrint("get mft bitmap failed!");
        ReportErrorMessage("��ȡ�ļ���¼λͼʧ��!   ");
        free( dataruns );dataruns = NULL;
        len_dataruns = 0;
        CloseFile( hMft );hMft = NULL;
        goto exit;
    }

    m_MftBitmapLength = GetDataRunsValue( dataruns,len_dataruns,NULL,0);
    assert( m_MftBitmapLength > 0 );
    m_MftBitmap = (LPBYTE)malloc( (DWORD)m_MftBitmapLength );
    assert( m_MftBitmap != NULL);
    GetDataRunsValue( dataruns,len_dataruns,m_MftBitmap,m_MftBitmapLength);
    
exit:
    if( hMft != NULL)
    {
        CloseFile( hMft );
        hMft = NULL;
    }

    if( dataruns != NULL)
    {
        free( dataruns );
        dataruns = NULL;
    }

    return bResult;
}

BOOL CNtfsController::UpdateBitmap()
/*++
��������������NTFS���̿ռ�λͼ�������Ĺ���λͼд������У�

��������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    BOOL bResult = TRUE;

    NTFS_FILE file = OpenNtfsFile( FILE_Bitmap );
    if( file == NULL)
    {
        bResult = FALSE;
        goto exit;
    }

    LONG length = GetAttributeValue( file,AT_DATA,NULL,0 );
    if( length <= 0 )
    {
        bResult = FALSE;
        goto exit;
    }

    LPVOID buffer = malloc( length );
    assert( buffer != NULL );
    BOOL bDataruns = FALSE;
    if( 0 != GetAttributeValue( file,AT_DATA,buffer,length,&bDataruns ))
    {
        bResult = FALSE;
        goto exit;
    }
    assert( bDataruns == TRUE );

    LONGLONG vcns = GetNumberOfVcnsInDataRuns( (LPBYTE)buffer,length );
    if( vcns <= 0 )
    {
        bResult = FALSE;
        goto exit;
    }

    assert( m_Bitmap != NULL && m_BitmapLength > 0 && m_BitmapLength <= vcns * m_ClusterSizeInBytes );

    for( LONGLONG i = 0;i < vcns;i++)
    {
        LONGLONG lcn = VcnToLcn( i,(LPBYTE)buffer,length );
        if( lcn == -1 ){
            bResult = FALSE;
            goto exit;
        }

        bResult = WriteLogicalCluster( m_Bitmap + i * m_ClusterSizeInBytes,m_ClusterSizeInBytes,lcn );
        if( !bResult )
        {
            goto exit;
        }
    }

exit:
    CloseFile( file );
    file = NULL;

    if( buffer != NULL){
        free(buffer );
        buffer = NULL;
    }

    return bResult;

}

BOOL CNtfsController::UpdateMftBitmap()
/*++
��������������NTFS�ļ���¼�����λͼ�������Ĺ���λͼд������У�

��������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    BOOL bResult = TRUE;

    NTFS_FILE file = OpenNtfsFile( FILE_MFT );
    if( file == NULL)
    {
        bResult = FALSE;
        goto exit;
    }

    LONG length = GetAttributeValue( file,AT_BITMAP,NULL,0 );
    if( length <= 0 )
    {
        bResult = FALSE;
        goto exit;
    }

    LPVOID buffer = malloc( length );
    assert( buffer != NULL );
    BOOL bDataruns = FALSE;
    if( 0 != GetAttributeValue( file,AT_BITMAP,buffer,length,&bDataruns ))
    {
        bResult = FALSE;
        goto exit;
    }
    assert( bDataruns == TRUE );

    LONGLONG vcns = GetNumberOfVcnsInDataRuns( (LPBYTE)buffer,length );
    if( vcns <= 0 )
    {
        bResult = FALSE;
        goto exit;
    }

    assert( m_MftBitmap != NULL && m_MftBitmapLength > 0 && m_MftBitmapLength <= vcns * m_ClusterSizeInBytes );

    for( LONGLONG i = 0;i < vcns;i++)
    {
        LONGLONG lcn = VcnToLcn( i,(LPBYTE)buffer,length );
        if( lcn == -1 ){
            bResult = FALSE;
            goto exit;
        }

        bResult = WriteLogicalCluster( m_MftBitmap + i * m_ClusterSizeInBytes,m_ClusterSizeInBytes,lcn );
        if( !bResult )
        {
            goto exit;
        }
    }

exit:
    CloseFile( file );
    file = NULL;

    if( buffer != NULL){
        free(buffer );
        buffer = NULL;
    }

    return bResult;

}

BOOL CNtfsController::UpdateBadClus()
/*++
��������������NTFS���̻����ļ�$BadClus�������Ĺ��Ļ���������Ϣд������У�

��������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    LPBYTE dataruns = NULL,bad_dataruns = NULL;
    LONG len_dataruns = 0,len_bad_dataruns = 0;

    len_dataruns = BlockListToDataRuns( &m_BlockInforHead.BadBlockList,NULL,0);
    assert( len_dataruns != 0 );

    if( len_dataruns < 0 )
    {
        DbgPrint("len_dataruns is -1");
        goto error_exit;
    }

    dataruns = (LPBYTE)malloc( len_dataruns );
    assert( dataruns != NULL);
    RtlZeroMemory( dataruns,len_dataruns );
    LONG result = BlockListToDataRuns( &this->m_BlockInforHead.BadBlockList,
                                        dataruns,
                                        len_dataruns);
    if( result != 0 )
    {
        DbgPrint("get dataruns from blocklist failed!");
        goto error_exit;
    }

    //������datarunsת��Ϊ�ռ��������͵�dataruns

    len_bad_dataruns = DataRunsToSpaceDataRuns( dataruns,len_dataruns,NULL,0);
    assert( len_bad_dataruns > 0 );
    bad_dataruns = (LPBYTE)malloc( len_bad_dataruns );
    assert( bad_dataruns != NULL);
    RtlZeroMemory( bad_dataruns,len_bad_dataruns );
    if( -1 == DataRunsToSpaceDataRuns( dataruns,len_dataruns,bad_dataruns,len_bad_dataruns ))
    {
        ReportErrorMessage("dataruns to spacedataruns failed!");
        goto error_exit;
    }
    free( dataruns );dataruns = NULL;len_dataruns = 0;

    //���ռ��������͵�dataruns,��bad_datarunsд���ļ�$BadClus��$Bad��������
    //��Ϊ$Bad��������$BadClus�ļ������һ������

    //�ͷ����$BadClus�ļ��ķǻ����ļ���¼
    NTFS_FILE hBadClusFile = OpenNtfsFile( FILE_BadClus );
    assert( hBadClusFile != NULL);
    for(PLIST_ENTRY list = hBadClusFile->List.Flink;
        list != &hBadClusFile->List;
        list = list->Flink)
    {
        PFILE_ATTRIBUTE_NODE node = (PFILE_ATTRIBUTE_NODE)
            CONTAINING_RECORD( list,
                               FILE_ATTRIBUTE_NODE,
                               List);
        if(node->OwnerRecordId != FILE_BadClus )
            FreeFileRecordId( node->OwnerRecordId );
    }
    CloseFile( hBadClusFile );
    hBadClusFile = NULL;

    //�ؽ�$BadClus�ļ����ļ���¼
    
    LPBYTE buffer = NULL;
    buffer = (LPBYTE)malloc( this->m_MftRecordLength );
    assert( buffer != NULL);
    BOOL bOk = ReadMftRecord( FILE_BadClus,buffer,m_MftRecordLength );
    assert( bOk );
    PMFT_RECORD pRecordHeader = (PMFT_RECORD)buffer;
            
    PWORD   pUsa = (PWORD)((DWORD_PTR)pRecordHeader + pRecordHeader->usa_ofs);
    WORD    cUsa = pRecordHeader->usa_count;

    //��USA�����������ĩβ�����ֽڵ�����
    for( WORD i = 1;i < cUsa;i++)
    {
        assert( *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) == pUsa[0]);
        *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[i];
    }

    PATTR_RECORD pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader + pRecordHeader->attrs_offset);
    assert(pAttrRecord->type == AT_STANDARD_INFORMATION);
    pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
    if( pAttrRecord->type == AT_ATTRIBUTE_LIST )
    {
        FreeBlockInDataruns( (LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset),
            pAttrRecord->length - pAttrRecord->mapping_pairs_offset);
        PATTR_RECORD pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
        assert( pAttrRecord2->type == AT_FILE_NAME );
        pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pAttrRecord2 + pAttrRecord2->length);
        assert( pAttrRecord2->type == AT_DATA && pAttrRecord2->name_length == 0 );
        pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pAttrRecord2 + pAttrRecord2->length);
        assert( pAttrRecord2->type == AT_DATA && pAttrRecord2->name_length == 4 );
        pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pAttrRecord2 + pAttrRecord2->length);
        assert( pAttrRecord2->type == AT_END );
        RtlMoveMemory( pAttrRecord,
                (LPVOID)((DWORD_PTR)pAttrRecord + pAttrRecord->length),
                (DWORD_PTR)pAttrRecord2 + 8 - ((DWORD_PTR)pAttrRecord + pAttrRecord->length));
    }

    assert( pAttrRecord->type == AT_FILE_NAME);
    pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
    assert( pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 0);
    pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
    assert( pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 4);
    assert(pAttrRecord->non_resident == 1);
    PATTR_RECORD pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
    assert( pAttrRecord2->type == AT_END );

    LONG bytesCanBeUse = (LONG)
        (((DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated - 8)
        - ((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset));
    if( bytesCanBeUse >= len_bad_dataruns )
    {  
        //һ���ļ���¼�ռ乻�õ����

        memcpy_s( (LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset),
                   bytesCanBeUse,
                   bad_dataruns,
                   len_bad_dataruns );
        pAttrRecord->length = pAttrRecord->mapping_pairs_offset + (DWORD)len_bad_dataruns;
        pAttrRecord->lowest_vcn = 0;
        pAttrRecord->highest_vcn = 
            m_BootSect.number_of_sectors / m_BootSect.bpb.sectors_per_cluster -1;
        *(PDWORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length) = 0xffffffff;
        pRecordHeader->bytes_in_use = (DWORD)(((DWORD_PTR)pAttrRecord + pAttrRecord->length)
                                        - (DWORD_PTR)pRecordHeader
                                        + 8);

        //����USA���鼰����ĩβ�����ֽڵ�����
        for( WORD i = 1;i < cUsa;i++)
        {
            pUsa[i] = *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD));
            *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[0];
        }

        bOk = WriteMftRecord( FILE_BadClus,buffer,m_MftRecordLength );
        if(!bOk )
        {
            DbgPrint("write mftrecord failed!");
            goto error_exit;
        }
    }
    else
    {
        //�����ļ���¼�ռ䲻���ã���Ҫ���ATTRIBUTE_LIST���Լ�ִ����ز���
        
        //���������ļ���¼�ж�Ӧ��ATTRIBUTE_LIST_ENTRY��
        LPBYTE attributeListData = NULL;
        //LONG len_attributeListData = 3 * (sizeof(ATTR_LIST_ENTRY) + 6)+sizeof(ATTR_LIST_ENTRY)+4*sizeof(WCHAR)+6;
        LONG len_attributeListData = 4 * (sizeof(ATTR_LIST_ENTRY) + 6)+4*sizeof(WCHAR);
        attributeListData = (LPBYTE)malloc( len_attributeListData );
        assert( attributeListData != NULL);
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader + pRecordHeader->attrs_offset);
        PATTR_LIST_ENTRY p = (PATTR_LIST_ENTRY)attributeListData;
        int count = 0;
        for( ;pAttrRecord->type != AT_END && !(pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 4);
            pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length))
        {
            p->type = pAttrRecord->type;
            p->length = sizeof( ATTR_LIST_ENTRY ) + 6;//�������������뵽8�ֽڱ߽�
            p->lowest_vcn = 0;
            p->mft_reference = MK_MREF( FILE_BadClus,pRecordHeader->sequence_number);
            p->name_length = 0;
            p->name_offset = sizeof(ATTR_LIST_ENTRY );
            p->instance = pAttrRecord->instance;
            
            p = (PATTR_LIST_ENTRY)((DWORD_PTR)p + p->length);
            count++;
        }
        assert( count == 3 );
        assert( pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 4);
        p->type = pAttrRecord->type;
        p->length = sizeof( ATTR_LIST_ENTRY)+4*sizeof(WCHAR)+6;
        p->lowest_vcn = 0;
        p->mft_reference = MK_MREF( FILE_BadClus,pRecordHeader->sequence_number);
        p->name_length = 4;
        p->name_offset = sizeof( ATTR_LIST_ENTRY );
        p->instance = pAttrRecord->instance;
        memcpy_s( p->name,
                4*sizeof(WCHAR),
                (LPVOID)((DWORD_PTR)pAttrRecord + pAttrRecord->name_offset),
                4*sizeof(WCHAR));

        //���������ļ���¼

        //��AT_FILE_NAME���Կ�ʼ��������������ƶ���ΪATTRIBUTE_LIST���Ա����ռ�
        PATTR_RECORD tmp = pAttrRecord;
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader + pRecordHeader->attrs_offset);
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
        assert( pAttrRecord->type == AT_FILE_NAME );
        RtlMoveMemory((LPVOID)((DWORD_PTR)pAttrRecord + sizeof(ATTR_RECORD)+0x10),//0x10��Ϊdataruns�����Ŀռ��С
            pAttrRecord,
            (DWORD_PTR)tmp +sizeof(ATTR_RECORD) + 4*sizeof(WCHAR) - (DWORD_PTR)pAttrRecord);

        //���ATTRIBUTE_LIST������ͷ��Ϣ
        pAttrRecord->type = AT_ATTRIBUTE_LIST;
        pAttrRecord->length = sizeof(ATTR_RECORD)+0x10;
        pAttrRecord->non_resident = 1;
        pAttrRecord->name_length = 0;
        pAttrRecord->name_offset = sizeof(ATTR_RECORD);
        pAttrRecord->flags = ATTR_NORMAL;
        pAttrRecord->instance = pRecordHeader->next_attr_instance++;
        pAttrRecord->lowest_vcn
            = pAttrRecord->highest_vcn = 0;
        pAttrRecord->mapping_pairs_offset = sizeof( ATTR_RECORD );
        pAttrRecord->compression_unit = 0;
        pAttrRecord->allocated_size = m_ClusterSizeInBytes;//һ����
        pAttrRecord->data_size = 
            pAttrRecord->initialized_size =0;//���ATTR_LIST������ȷ�����ٸ�ֵ

        LONGLONG newBlock = AllocateBlock( 1 );
        LPBYTE pDataruns = (LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset);
        assert( newBlock > 0 );
        BYTE len_newBlock = CompressLongLong( newBlock );
        pDataruns[0] = (len_newBlock << 4) | 0x01;
        pDataruns[1] = 1;
        memcpy_s( &pDataruns[2],
                  16 -2 -1,
                  &newBlock,
                  len_newBlock );
        pDataruns[len_newBlock + 2]=0;//ATTR_LIST���Ե�dataruns��ֵ���

        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
        assert( pAttrRecord->type == AT_FILE_NAME );
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
        assert( pAttrRecord->type == AT_DATA && pAttrRecord->name_length==0 );
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
        assert( pAttrRecord->type == AT_DATA && pAttrRecord->name_length==4 );

        pDataruns = (LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset);
        DWORDLONG curr_vcn = 0,len = 0;
        pAttrRecord->lowest_vcn = 0;
        LONGLONG curr_rec_id = FILE_BadClus;
        WORD baseSeq = pRecordHeader->sequence_number;
        for( LONG i = 0;i < len_bad_dataruns;)
        {
            DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

            if( bad_dataruns[i] == 0 )break;

            cStartLcnBytes = ( bad_dataruns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
            cLenLcnBytes = (bad_dataruns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

            //��ȡ��ǰ����������
            len = 0;
            for( DWORD j = cLenLcnBytes;j > 0;j--)
            {
                len = (len << 8) | bad_dataruns[i + j ]; 
            }

            if(  (cStartLcnBytes + cLenLcnBytes + 1 ) >
                ((DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated-8-1-(DWORD_PTR)pDataruns))
            {
                //��ǰ�ļ���¼�ռ��Ѿ����꣬��Ҫ�����ļ���¼�������浱ǰ�ļ���¼
                *pDataruns = 0;
                pAttrRecord->highest_vcn = curr_vcn - 1;
                pAttrRecord->length = (DWORD)((DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated - 8
                                      - (DWORD_PTR)pAttrRecord);
                *(PLONG)((DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated-8)
                    = AT_END;
                pAttrRecord->allocated_size =
                    pAttrRecord->data_size = 
                    pAttrRecord->initialized_size = 0;
                pRecordHeader->bytes_in_use = pRecordHeader->bytes_allocated;

                //����ǰ�ļ���¼д�����

                //����USA���鼰����ĩβ�����ֽڵ�����
                for( WORD j = 1;j < cUsa;j++)
                {
                    pUsa[j] = *(PWORD)((DWORD_PTR)pRecordHeader + j * m_BootSect.bpb.bytes_per_sector - sizeof(WORD));
                    *(PWORD)((DWORD_PTR)pRecordHeader + j * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[0];
                }

                bOk = WriteMftRecord( curr_rec_id,pRecordHeader,m_MftRecordLength );
                if(!bOk )
                {
                    DbgPrint("write mftrecord failed!");
                    goto error_exit;
                }

                //�����µ��ļ���¼
                curr_rec_id = AllocateFileRecordId();
                if( curr_rec_id < 0 )
                {
                    DbgPrint("allocate mftrecord failed!");
                    goto error_exit;
                }
                bOk = ReadMftRecord( curr_rec_id,buffer,m_MftRecordLength );
                assert( bOk );
                pRecordHeader = (PMFT_RECORD)buffer;
                //��USA�����������ĩβ�����ֽڵ�����
                for( WORD j = 1;j < cUsa;j++)
                {
                    assert( *(PWORD)((DWORD_PTR)pRecordHeader + j * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) == pUsa[0]);
                    *(PWORD)((DWORD_PTR)pRecordHeader + j * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[j];
                }

                pRecordHeader->flags = MFT_RECORD_IN_USE;
                pRecordHeader->link_count = 0;
                pRecordHeader->next_attr_instance = 0;
                pRecordHeader->base_mft_record = MK_MREF( FILE_BadClus,baseSeq );
                pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader + pRecordHeader->attrs_offset);
                pAttrRecord->type = AT_DATA;
                pAttrRecord->instance = pRecordHeader->next_attr_instance++;
                pAttrRecord->compression_unit = 0;
                pAttrRecord->flags = ATTR_NORMAL;
                pAttrRecord->lowest_vcn = curr_vcn;
                pAttrRecord->name_length = 4;
                pAttrRecord->name_offset = sizeof(ATTR_RECORD );
                pAttrRecord->non_resident = 1;
                memcpy_s( 
                    (LPVOID)((DWORD_PTR)pAttrRecord + pAttrRecord->name_offset),
                    8,
                    L"$Bad",
                    8);
                pAttrRecord->mapping_pairs_offset = sizeof(ATTR_RECORD)+8;
                pDataruns =(LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset);

                LONGLONG tmp_len = 0;
                if( cStartLcnBytes == 0 )
                {
                    curr_vcn += len;
                    memcpy_s( pDataruns,
                        (DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated-8-1-(DWORD_PTR)pDataruns,
                        bad_dataruns + i,
                        cStartLcnBytes + cLenLcnBytes + 1);
                    pDataruns += cStartLcnBytes + cLenLcnBytes + 1;
                    i += cStartLcnBytes + cLenLcnBytes + 1;
                    tmp_len = len;
                }
                if( bad_dataruns[i] != 0 )
                {
                    assert( (bad_dataruns[i] & 0xf0) != 0 );
                    cLenLcnBytes = bad_dataruns[i] & 0x0f;
                    len = 0;
                    for( DWORD j = cLenLcnBytes;j > 0;j--)
                    {
                        len = (len << 8) | bad_dataruns[i + j ]; 
                    }
                    LONGLONG curr_lcn = pAttrRecord->lowest_vcn + tmp_len;
                    cStartLcnBytes = CompressLongLong( curr_lcn );
                    *pDataruns++ = ((BYTE)cStartLcnBytes << 4 ) | (BYTE)cLenLcnBytes;
                    memcpy_s( pDataruns,
                        (DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated-8-1-(DWORD_PTR)pDataruns,
                        bad_dataruns + i+1,
                        cLenLcnBytes);
                    pDataruns += cLenLcnBytes;
                    memcpy_s( pDataruns,
                        (DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated-8-1-(DWORD_PTR)pDataruns,
                        &curr_lcn,
                        cStartLcnBytes);
                    pDataruns += cStartLcnBytes;
                    curr_vcn += len;
                    i += (bad_dataruns[i] & 0x0f) + 
                         ((bad_dataruns[i] & 0xf0) >> 4) + 1;
                }

                len_attributeListData += sizeof(ATTR_LIST_ENTRY)+6+4*sizeof(WCHAR);
                LPVOID p_xx = realloc( attributeListData,
                    len_attributeListData );
                assert( p_xx != NULL);
                attributeListData = (LPBYTE)p_xx;
                p = (PATTR_LIST_ENTRY)((DWORD_PTR)attributeListData+
                        len_attributeListData
                        - (sizeof(ATTR_LIST_ENTRY)+6+4*sizeof(WCHAR)));
                p->type = pAttrRecord->type;
                p->length = sizeof(ATTR_LIST_ENTRY)+6+4*sizeof(WCHAR);
                p->lowest_vcn = pAttrRecord->lowest_vcn;
                p->mft_reference = MK_MREF(curr_rec_id,pRecordHeader->sequence_number);
                p->name_length = 4;
                p->name_offset = sizeof(ATTR_LIST_ENTRY);
                p->instance = 0;
                memcpy_s( p->name,
                    4*sizeof(WCHAR),
                    L"$Bad",
                    4*sizeof(WCHAR));
                
                continue;
            }// end if ��ǰ�ļ���¼�ռ�����

            curr_vcn += len;
            memcpy_s( pDataruns,
                (DWORD_PTR)pRecordHeader + pRecordHeader->bytes_allocated-8-1-(DWORD_PTR)pDataruns,
                bad_dataruns + i,
                cStartLcnBytes + cLenLcnBytes + 1);
            pDataruns += cStartLcnBytes + cLenLcnBytes + 1;
            i += cStartLcnBytes + cLenLcnBytes + 1;
        }// end for i
        
        *pDataruns++ = 0;
        pAttrRecord->highest_vcn = curr_vcn - 1;
        while( (DWORD_PTR)pDataruns % 8 != 0)pDataruns++;
        *(PULONG)pDataruns = AT_END;
        pAttrRecord->length = (DWORD)( (DWORD_PTR)pDataruns - (DWORD_PTR)pAttrRecord);
        pAttrRecord->allocated_size =
            pAttrRecord->data_size = 
            pAttrRecord->initialized_size = 0;
        pRecordHeader->bytes_in_use = (DWORD)((DWORD_PTR)pDataruns + 8 - (DWORD_PTR)pRecordHeader);

        //����ǰ�ļ���¼д�����

        //����USA���鼰����ĩβ�����ֽڵ�����
        for( WORD j = 1;j < cUsa;j++)
        {
            pUsa[j] = *(PWORD)((DWORD_PTR)pRecordHeader + j * m_BootSect.bpb.bytes_per_sector - sizeof(WORD));
            *(PWORD)((DWORD_PTR)pRecordHeader + j * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[0];
        }

        bOk = WriteMftRecord( curr_rec_id,pRecordHeader,m_MftRecordLength );
        if(!bOk )
        {
            DbgPrint("write mftrecord failed!");
            goto error_exit;
        }
        
        //ATTR_LIST������д�����,�غ�ΪnewBlock
        bOk = WriteLogicalCluster(attributeListData
                ,len_attributeListData,
                newBlock);
        if( !bOk )
        {
            free( attributeListData );
            DbgPrint("write attr_list_data failed!");
            goto error_exit;
        }

        bOk = ReadMftRecord( FILE_BadClus,buffer,m_MftRecordLength );
        assert( bOk );
        //û��Ҫ���USA��USN��
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader +pRecordHeader->attrs_offset);
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord +pAttrRecord->length);
        assert( pAttrRecord->type == AT_ATTRIBUTE_LIST );
        assert( pAttrRecord->data_size == 0 );
        pAttrRecord->initialized_size 
            = pAttrRecord->data_size = len_attributeListData;
        pAttrRecord->allocated_size = m_ClusterSizeInBytes * 1;
        
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord +pAttrRecord->length);
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord +pAttrRecord->length);
        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord +pAttrRecord->length);
        assert( pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 4 );
        pAttrRecord->data_size = 
            pAttrRecord->allocated_size = curr_vcn * m_ClusterSizeInBytes;
        pAttrRecord->initialized_size = 0;
        bOk = WriteMftRecord( FILE_BadClus,buffer,m_MftRecordLength );
        assert( bOk );

        free( attributeListData );
        attributeListData = NULL;
        len_attributeListData = 0;

    }//else if byteCanBeUse

    free( buffer );buffer = NULL;
    free( bad_dataruns);bad_dataruns = NULL;len_bad_dataruns = 0;

    return TRUE;

error_exit:
    if( dataruns != NULL){
        free(dataruns);
        dataruns = NULL;
        len_dataruns = 0;
    }
    if( bad_dataruns != NULL){
        free( bad_dataruns);
        bad_dataruns = NULL;
        len_bad_dataruns = 0;
    }

    if( buffer != NULL)
    {
        free(buffer);
        buffer = NULL;
    }

    return FALSE;

//����ˣ�����Ĵ��룡����������������������������
}

BOOL CNtfsController::UpdateMftMirr()
/*++
����������ʹ$MFTMirr�ļ���������$Mft�ļ�ͬ��

��������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    LPBYTE buffer = NULL;
    DWORD  numberOfCluster = 0,i = 0;                 //$MFTMirr�ļ��Ĵ���
    NTFS_FILE   hFile = OpenNtfsFile( FILE_MFTMirr );
    if( hFile == NULL)
        return FALSE;
    numberOfCluster = (DWORD)(hFile->FileSize / m_ClusterSizeInBytes);
    CloseFile( hFile );
    hFile = NULL;

    assert( numberOfCluster >= 1 );
    buffer = (LPBYTE)malloc( m_ClusterSizeInBytes );
    RtlZeroMemory( buffer,m_ClusterSizeInBytes );
    
    for( i = 0;i < numberOfCluster;i++)
    {
        BOOL bOk = ReadLogicalCluster( buffer,m_ClusterSizeInBytes,
            m_BootSect.mft_lcn + i);
        if( !bOk )
            break;
        bOk = WriteLogicalCluster(buffer,m_ClusterSizeInBytes,m_BootSect.mftmirr_lcn + i );
        if( !bOk )
            break;
    }

    free( buffer );buffer = NULL;
    if( i == numberOfCluster )
        return TRUE;
    else
        return FALSE;
}

BOOL CNtfsController::InitBadBlockList()
/*++
������������NTFS��Ԫ�ļ�$Bad�г�ʼ��������Ϣ����

��������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    BOOL bResult = FALSE;
    LONGLONG last_value=0;                  //���ڼ��BAdBlockList����������Ķ���

    NTFS_FILE   file = OpenNtfsFile( FILE_BadClus );
    if( file == NULL )
    {
        bResult = FALSE;
        goto exit;
    }

    DWORD valueLength = GetAttributeValue( file,AT_DATA,NULL,0,NULL,L"$Bad");
    if( valueLength == -1 )
    {
        bResult = FALSE;
        goto exit;
    }
    assert( valueLength > 0 );
    
    LPBYTE buffer = (LPBYTE)malloc( valueLength );
    BOOL bDataruns = FALSE;
    if( 0 != GetAttributeValue( file,AT_DATA,buffer,valueLength,&bDataruns,L"$Bad"))
    {
        bResult = FALSE;
        goto exit;
    }
    assert( bDataruns == TRUE );

    //��Dataruns����ȡ������Ϣ

    DestroyListNodes( &m_BlockInforHead.BadBlockList);
    m_BlockInforHead.BadBlockSize.QuadPart = 0;

    LONGLONG startLcn = 0,len = 0;
    for(DWORD i = 0;
        i < valueLength;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( buffer[i] == 0 )break;

        cStartLcnBytes = ( buffer[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (buffer[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        //��ȡ��ǰ����������
        len = 0;
        for( DWORD j = cLenLcnBytes;j > 0;j--)
        {
            len = (len << 8) | buffer[i + j ]; 
        }

        //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
        LONGLONG tmp = 0;
        if( buffer[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
            tmp = -1ll;
        for( DWORD j = cStartLcnBytes;j > 0;j-- )
        {
            tmp = ( tmp << 8 ) | buffer[i + cLenLcnBytes + j ];
        }
        startLcn = startLcn + tmp;
        if( cStartLcnBytes > 0 )
        {
            assert( startLcn > last_value );
            last_value = startLcn;
            AddBadBlock( startLcn * m_BootSect.bpb.sectors_per_cluster,
                        len * m_BootSect.bpb.sectors_per_cluster );
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }

    bResult = TRUE;

exit:
    if( buffer != NULL)
    {
        free( buffer );
        buffer = NULL;
    }
    
    if( file != NULL)
    {
        CloseFile( file );
        file = NULL;
    }

    return bResult;
}

PFILE_INFORMATION CNtfsController::InitNtfsFile( IN LPVOID MftRecordCluster,IN DWORD BufferLength,LONGLONG RecordId )
/*++
��������:��ʼ���ļ���������Ϣ

����:
    MftRecordCluster:ָ������ļ���¼ͷ�Ļ�����
    BufferLength:ָ����������С
    RecordId:�ļ���¼ID

����ֵ:�ɹ�����ָ���ļ�������Ϣ��ָ�루PFILE_INFORMATION),ʧ�ܷ���NULL

˵����֮���Բ����ļ���¼ͷ���������ļ���¼ID��Ϊ�˼��ݵͰ汾��NTFS�ļ�ϵͳ
--*/
{
    PMFT_RECORD pRecordHeader = (PMFT_RECORD)MftRecordCluster;
    assert( pRecordHeader != NULL);

    //����Ƿ�Ϊ�ļ���¼
    if( !ntfs_is_file_record( pRecordHeader->magic ))
        return NULL;

    //����ļ���¼�Ƿ���ʹ����
    if( !(pRecordHeader->flags & MFT_RECORD_IN_USE) )
        return NULL;

    //����ļ���¼�Ƿ�Ϊ�����ļ���¼
    if( (pRecordHeader->base_mft_record & 0x0000ffffffffffffull)!= 0 )
        return NULL;

	//Fixup Value lcqomit
    PWORD   pUsa = (PWORD)((DWORD_PTR)pRecordHeader + pRecordHeader->usa_ofs);
    WORD    cUsa = pRecordHeader->usa_count;

    //��USA�����������ĩβ�����ֽڵ�����
    for( WORD i = 1;i < cUsa;i++)
    {
		//(m_BootSect.bpb.bytes_per_sector)
		//m_BootSect.bpb.bytes_per_sector
        assert( *(PWORD)((DWORD_PTR)pRecordHeader + i * 512 - sizeof(WORD)) == pUsa[0]);
        *(PWORD)((DWORD_PTR)pRecordHeader + i * 512 - sizeof(WORD)) = pUsa[i];
    }

    PFILE_INFORMATION   pFileInfor = (PFILE_INFORMATION )
        malloc( sizeof( FILE_INFORMATION ));
    assert( pFileInfor != NULL );
    RtlZeroMemory( pFileInfor,sizeof( FILE_INFORMATION ));
    InitializeListHead( &pFileInfor->List );

    //��ȡ�ļ��и���������
    BOOL    bAttributeListFound = FALSE;        //�����ж��Ƿ���ATTRIBUTE_LIST(0X20)����
    PATTR_RECORD pAttr20 = NULL;                //ָ��0x20���Ե�����
    PATTR_RECORD pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader + 
        pRecordHeader->attrs_offset);
    while( pAttrRecord->type != AT_END )
    {
        PFILE_ATTRIBUTE_NODE node = (PFILE_ATTRIBUTE_NODE)malloc( sizeof( FILE_ATTRIBUTE_NODE) );
        assert( node != NULL);
        RtlZeroMemory( node ,sizeof( FILE_ATTRIBUTE_NODE) );

        node->Length = pAttrRecord->length;
        node->AttributeType = pAttrRecord->type;
        node->AttributeData = malloc( pAttrRecord->length );
        node->AttrOffset = (WORD)((DWORD_PTR)pAttrRecord - (DWORD_PTR)pRecordHeader);
        node->OwnerRecordId = RecordId;
        assert( node->AttributeData !=  NULL );
        memcpy_s( node->AttributeData,pAttrRecord->length,pAttrRecord,
            node->Length );

        //���0x30����(��פ��,����ļ�����Ϣ
        if( pAttrRecord->type == AT_FILE_NAME && pAttrRecord->name_length == 0 )
        {
            assert( pAttrRecord->non_resident == 0 );
            PFILE_NAME_ATTR pFileNameAttr = (PFILE_NAME_ATTR)((DWORD_PTR)node->AttributeData + pAttrRecord->value_offset);
            
            if( pFileNameAttr->file_name_type == FILE_NAME_WIN32_AND_DOS ||
                pFileNameAttr->file_name_type == FILE_NAME_WIN32 )
            {
                pFileInfor->FileName = pFileNameAttr->file_name;
                pFileInfor->FileNameLength = pFileNameAttr->file_name_length;
            }
        }

        //���0x80����,����ļ���С(��������������
        if( pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 0 )
        {
            if( pAttrRecord->non_resident == 0 )
            {
                //��פ
                pFileInfor->FileSize += pAttrRecord->value_length;
            }
            else
            {
                //�ǳ�פ
                pFileInfor->FileSize += pAttrRecord->data_size;
            }
        }


        //����Ƿ�ΪATTRIBUTE_LIST����,��������Ӧ��ǽ��к�̴���
        if( !bAttributeListFound && pAttrRecord->type == AT_ATTRIBUTE_LIST )
        {
            bAttributeListFound = TRUE;
            pAttr20 = (PATTR_RECORD)node->AttributeData;
        }

        InsertTailList( &pFileInfor->List,&node->List );
        node = NULL;

        pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
    }

    //if( bAttributeListFound )
    //{
     //   printf("%ld\n",pRecordHeader->mft_record_number );
      //  goto exit;
   // }

    if( bAttributeListFound )
    {
        //������ATTRIBUTE_LIST���Ե����
        //_asm int 3;
        DbgPrint("Warning:ATTRIBUTE_LIST found!");

        //��ȡATTRIBUTE_LIST����ֵ����(ע��:ATTRIBUTE_LIST���Լ�ʹΪ�ǳ�פ��datarunsҲ���ᳬ���ļ���¼�ķ�Χ��
        DWORD AttrListSize = GetAttributeListValue( pAttr20,NULL,0,NULL);
        assert( AttrListSize > 0 );
        LPBYTE  pValueBuffer = (LPBYTE)malloc(AttrListSize);
        assert( pValueBuffer != NULL);
        if( 0 > GetAttributeListValue( pAttr20,pValueBuffer,AttrListSize,&AttrListSize))
        {
            DbgPrint("GetAttrbuteList failed!");
            free( pValueBuffer );
            pValueBuffer = NULL;
            goto exit;
        }

        //��������ATTR_LIST_ENTRY,�����ձ������򽫷ǻ����ļ���¼�е�������ӵ�pFileInfor��
        //LONGLONG last_rec_id = -1;
        map<LONGLONG,BYTE> mymap;
        for( PATTR_LIST_ENTRY pAttrListEntry = (PATTR_LIST_ENTRY)pValueBuffer;
            pAttrListEntry < (PATTR_LIST_ENTRY)((DWORD_PTR)pValueBuffer + AttrListSize );
            pAttrListEntry = (PATTR_LIST_ENTRY)((DWORD_PTR)pAttrListEntry + pAttrListEntry->length))
        {
            //������ɣ��˳�
            if( pAttrListEntry->type == AT_UNUSED ||
                pAttrListEntry->length == 0 ||
                pAttrListEntry->mft_reference == 0)
                break;

            //�Ѿ�����������ٴ���
            //if( last_rec_id == (pAttrListEntry->mft_reference & 0x0000ffffffffffffull) )
            //    continue;
            //last_rec_id = pAttrListEntry->mft_reference & 0x0000ffffffffffffull;

            if( mymap.find(pAttrListEntry->mft_reference & 0x0000ffffffffffffull) != mymap.end())
                continue;
            mymap[pAttrListEntry->mft_reference & 0x0000ffffffffffffull]=1;

            BOOL    bOk = FALSE;
            PMFT_RECORD pRecordHeader2 = (PMFT_RECORD)malloc( m_MftRecordLength );
            assert( pRecordHeader2 != NULL );
            RtlZeroMemory( pRecordHeader2,m_MftRecordLength );
            bOk = ReadMftRecord( pAttrListEntry->mft_reference & 0x0000ffffffffffffull,
                pRecordHeader2,
                m_MftRecordLength );
            assert( bOk );                  /*ע��:ReadMftRecord��Ҫm_MftDataRuns���ȱ���ʼ��,Ȼ����ʼ����
                                            �����ĺ���ҲҪ���ñ�����InitNtfsFile.�����ʱReadMftRecord����ʧ��
                                            �������m_MftDataRuns��δ����ʼ�������������Ӧ$MFT���ļ���¼�а���
                                            ATTRIBUTE_LIST 0X20����,�������$MFT���Ậ�и�����*/

            //��������ڻ����ļ���¼��,�����,��Ϊ�ϱ��Ѿ���ȡ����������
            if( pRecordHeader2->base_mft_record == 0 )
            {
                //last_rec_id = pAttrListEntry->mft_reference & 0x0000ffffffffffffull;
                mymap[pAttrListEntry->mft_reference & 0x0000ffffffffffffull] = 1;
                free( pRecordHeader2 );
                pRecordHeader2 = NULL;
                continue;
            }


            PWORD   pUsa2 = (PWORD)((DWORD_PTR)pRecordHeader2 + pRecordHeader2->usa_ofs);
            WORD    cUsa2 = pRecordHeader2->usa_count;
            
            //��USA�����������ĩβ�����ֽڵ�����
            for( WORD i = 1;i < cUsa2;i++)
            {
                assert( *(PWORD)((DWORD_PTR)pRecordHeader2 + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) == pUsa2[0]);
                *(PWORD)((DWORD_PTR)pRecordHeader2 + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa2[i];
            }

            pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pRecordHeader2 + 
                pRecordHeader2->attrs_offset);
            while( pAttrRecord->type != AT_END )
            {
                PFILE_ATTRIBUTE_NODE node = (PFILE_ATTRIBUTE_NODE)malloc( sizeof( FILE_ATTRIBUTE_NODE) );
                assert( node != NULL);
                RtlZeroMemory( node ,sizeof( FILE_ATTRIBUTE_NODE) );

                node->Length = pAttrRecord->length;
                node->AttributeType = pAttrRecord->type;
                node->AttrOffset = (WORD)((DWORD_PTR)pAttrRecord - (DWORD_PTR)pRecordHeader2);
                node->OwnerRecordId = pAttrListEntry->mft_reference & 0x0000ffffffffffffull;
                node->AttributeData = malloc( pAttrRecord->length );
                assert( node->AttributeData !=  NULL );
                memcpy_s( node->AttributeData,pAttrRecord->length,pAttrRecord,
                    node->Length );

                //���0x30����(��פ��,����ļ���
                if( pAttrRecord->type == AT_FILE_NAME && pAttrRecord->name_length == 0 )
                {
                    assert( pAttrRecord->non_resident == 0 );
                    PFILE_NAME_ATTR pFileNameAttr = (PFILE_NAME_ATTR)((DWORD_PTR)node->AttributeData + pAttrRecord->value_offset);
                    
                    if( pFileNameAttr->file_name_type == FILE_NAME_WIN32_AND_DOS ||
                        pFileNameAttr->file_name_type == FILE_NAME_WIN32 )
                    {
                        pFileInfor->FileName = pFileNameAttr->file_name;
                        pFileInfor->FileNameLength = pFileNameAttr->file_name_length;
                    }
                }

                //���0x80����,����ļ���С(��������������
                if( pAttrRecord->type == AT_DATA && pAttrRecord->name_length == 0 )
                {
                    if( pAttrRecord->non_resident == 0 )
                    {
                        //��פ
                        pFileInfor->FileSize += pAttrRecord->value_length;
                    }
                    else
                    {
                        //�ǳ�פ
                        pFileInfor->FileSize += pAttrRecord->data_size;
                    }
                }

                InsertTailList( &pFileInfor->List,&node->List );
                node = NULL;

                pAttrRecord = (PATTR_RECORD)((DWORD_PTR)pAttrRecord + pAttrRecord->length);
            }//end while

            free( pRecordHeader2 );
            pRecordHeader2 = NULL;

        }//end for ����ATTR_LIST_ENTRY

        free( pValueBuffer );
        pValueBuffer = NULL;

        //ע��:�ڽ�����ȡ�ǳ�פ����ֵ��ʱ��,ע����ļ���¼��dataruns�Ĵ���
    }//end if bAttributeListFound

exit:
    //�ָ���������������ʼ״̬
    for( WORD i = 1;i < cUsa;i++)
    {
        *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[0];
    }

    return pFileInfor;
}

PFILE_INFORMATION CNtfsController::OpenNtfsFile( IN LONGLONG RecordId )
/*++
��������:���ļ�,�����ļ�������Ϣ�ṹָ��

����:RecordId:�ļ���¼��

����ֵ:�ɹ������ļ�������Ϣ�ṹָ��,ʧ�ܷ���NULL
--*/
{
    BOOL    bResult = TRUE;
    LPVOID  buffer = malloc( m_MftRecordLength );
    assert( buffer != NULL );
    bResult = ReadMftRecord( RecordId,buffer,m_MftRecordLength );
    if( !bResult )
    {
        free( buffer );
        return NULL;
    }
    PFILE_INFORMATION file = InitNtfsFile( buffer,m_MftRecordLength,RecordId);
    if( file != NULL )
        file->FileRecordId = RecordId;

    free( buffer );
    return file;
}

BOOL CNtfsController::ReadMftRecord( IN LONGLONG RecordId,OUT PVOID Buffer,IN DWORD BufferLength )
/*++
��������:��ȡ$MFT�ļ���ָ���ļ���¼�ŵ��ļ���¼

����:
    RecordId:�ļ���¼��
    Buffer:���������,�����߸����ڴ�ķ�����ͷ�
    BufferLength:������������ȣ���λ:�ֽڣ�,����Ϊһ���ļ���¼��С

����ֵ:�ɹ�����TRUE,ʧ�ܷ���FALSE

--*/
{
    assert( Buffer != NULL );
    assert( BufferLength >= m_MftRecordLength );

    if( m_MftDataRuns == NULL ){
        DbgPrint("dataruns == null!\n");
        return FALSE;                       //$MFT��δ����ʼ������ʧ��
    }

    BOOL bResult = TRUE;

	//lcq note:һ���ļ���¼�����ж��������ͬ��һ������Ҳ���Դ洢����ļ���¼
	
    //RecordId -> VCN
	LONGLONG    vcn = -1;
	LONGLONG   offsetInSectors = -1;
	if (m_MftRecordLength >= m_BootSect.bpb.bytes_per_sector)
	{
		//������512NӲ���� һ���ļ���¼��1024�ֽڣ�ռ��2��512�ֽڵ�������
		vcn = m_MftRecordLength / m_BootSect.bpb.bytes_per_sector * RecordId
			/ m_BootSect.bpb.sectors_per_cluster;

		//�����ļ���¼����������ڴص�ƫ��������λΪ������
		offsetInSectors = RecordId                                           //�ļ���¼��
			* (m_MftRecordLength / m_BootSect.bpb.bytes_per_sector) //ÿ�ļ���¼������
			% m_BootSect.bpb.sectors_per_cluster;                   //ÿ��������
	}
	else
	{
		//��4KNӲ���У�һ���������Դ洢4��1024�ֽڵ��ļ���¼��
		vcn = (RecordId / (m_BootSect.bpb.bytes_per_sector / m_MftRecordLength)) / m_BootSect.bpb.sectors_per_cluster;
		offsetInSectors = (RecordId % (m_BootSect.bpb.bytes_per_sector / m_MftRecordLength));
	}

    //VCN -> LCN
    LONGLONG    lcn = VcnToLcn(vcn, m_MftDataRuns, m_MftDataRunsLength );
    if( lcn == -1 )
    {
        DbgPrint("vcn to lcn failed!\n");

        return FALSE;
    }
    bResult = TRUE;

	//��ȡ����
	if (m_MftRecordLength >= m_BootSect.bpb.bytes_per_sector)
	{
		//һ������λ�ڶ������
		for (DWORD i = 0; i < (m_MftRecordLength / m_BootSect.bpb.bytes_per_sector); i++)
		{
			bResult = ReadLogicalSector((LPVOID)((DWORD_PTR)Buffer + i * m_BootSect.bpb.bytes_per_sector),
				m_BootSect.bpb.bytes_per_sector,
				lcn * m_BootSect.bpb.sectors_per_cluster + offsetInSectors + i,
				this->m_PhysicDiskSectorSize);
			if (!bResult) {
				printf("read failed!\n");
				goto exit;
			}
		}
	}
	else
	{
		//һ�������洢�������
		LPVOID  tmpbuffer = malloc(this->m_PhysicDiskSectorSize);
		if (tmpbuffer == NULL) return 0;

		bResult = ReadLogicalSector(tmpbuffer, this->m_PhysicDiskSectorSize, lcn,
			this->m_PhysicDiskSectorSize);

		if (!bResult) {
			printf("read failed!\n");
			goto exit;
		}

		memcpy_s(Buffer, m_MftRecordLength, 
			((BYTE*)tmpbuffer + offsetInSectors*m_MftRecordLength), m_MftRecordLength);

		free(tmpbuffer);
	}
    

    bResult = ntfs_is_file_recordp(Buffer);
    if( bResult==FALSE){
        DbgPrint("Not file record,return false!");
    }

exit:
    return bResult;

}

BOOL CNtfsController::WriteMftRecord( IN LONGLONG RecordId,IN PVOID Buffer,IN DWORD BufferLength )
/*++
��������:д$MFT�ļ���ָ���ļ���¼�ŵ��ļ���¼

����:
    RecordId:�ļ�����¼��
    Buffer:���뻺����,�����߸����ڴ�ķ�����ͷ�
    BufferLength:���뻺�������ȣ���λ:�ֽڣ�,����Ϊһ���ļ���¼��С

����ֵ:�ɹ�����TRUE,ʧ�ܷ���FALSE

--*/
{
    BOOL bResult = TRUE;

    assert( Buffer != NULL );
    assert( BufferLength >= m_MftRecordLength );

    bResult = ntfs_is_file_recordp(Buffer);
    if( bResult==FALSE){
        DbgPrint("Not file record,return false!");
        goto exit;
    }

    if( m_MftDataRuns == NULL ){
        DbgPrint("dataruns == null!\n");
        bResult = FALSE;
        goto exit;                  //$MFT��δ����ʼ������ʧ��
    }

    //����RecordId��Ӧ�ļ���¼���ڵ�VCN
	//lcq note:һ���ļ���¼�����ж��������ͬ��һ������Ҳ���Դ洢����ļ���¼

	//RecordId -> VCN
	LONGLONG    vcn = -1;
	LONGLONG   offsetInSectors = -1;
	if (m_MftRecordLength >= m_BootSect.bpb.bytes_per_sector)
	{
		//������512NӲ���� һ���ļ���¼��1024�ֽڣ�ռ��2��512�ֽڵ�������
		vcn = m_MftRecordLength / m_BootSect.bpb.bytes_per_sector * RecordId
			/ m_BootSect.bpb.sectors_per_cluster;

		//�����ļ���¼����������ڴص�ƫ��������λΪ������
		offsetInSectors = RecordId                                           //�ļ���¼��
			* (m_MftRecordLength / m_BootSect.bpb.bytes_per_sector) //ÿ�ļ���¼������
			% m_BootSect.bpb.sectors_per_cluster;                   //ÿ��������
	}
	else
	{
		//��4KNӲ���У�һ���������Դ洢4��1024�ֽڵ��ļ���¼��
		vcn = (RecordId / (m_BootSect.bpb.bytes_per_sector / m_MftRecordLength)) / m_BootSect.bpb.sectors_per_cluster;
		offsetInSectors = (RecordId % (m_BootSect.bpb.bytes_per_sector / m_MftRecordLength));
	}

    //ת��ΪLCN,������ʧ��
    LONGLONG    lcn = VcnToLcn( vcn,m_MftDataRuns,m_MftDataRunsLength );
    if( lcn == -1 )
    {
        DbgPrint("vcn to lcn failed!\n");
        bResult = FALSE;
        goto exit;
    }

    bResult = TRUE;

	//д������
	if (m_MftRecordLength >= m_BootSect.bpb.bytes_per_sector)
	{
		//һ������λ�ڶ������
		for (DWORD i = 0; i < (m_MftRecordLength / m_BootSect.bpb.bytes_per_sector); i++)
		{
			bResult = WriteLogicalSector((LPVOID)((DWORD_PTR)Buffer + i * m_BootSect.bpb.bytes_per_sector),
				m_BootSect.bpb.bytes_per_sector,
				lcn * m_BootSect.bpb.sectors_per_cluster + offsetInSectors + i,
				this->m_PhysicDiskSectorSize);
			if (!bResult) {
				printf("write failed! Err:%d\n", GetLastError());
				goto exit;
			}
		}
	}
	else
	{
		//һ�������洢�������
		//���ȶ�ȡ������������Ȼ���޸��������ݣ����д����������

		LPVOID  tmpbuffer = malloc(this->m_PhysicDiskSectorSize);
		if (tmpbuffer == NULL) return 0;

		bResult = ReadLogicalSector(tmpbuffer, this->m_PhysicDiskSectorSize, lcn,
			this->m_PhysicDiskSectorSize);

		if (!bResult) {
			printf("write: read failed!\n");
			goto exit;
		}

		memcpy_s(((BYTE*)tmpbuffer + offsetInSectors*m_MftRecordLength), m_MftRecordLength,
			Buffer, m_MftRecordLength);

		bResult = WriteLogicalSector(tmpbuffer,
			this->m_PhysicDiskSectorSize,
			lcn,
			this->m_PhysicDiskSectorSize);
		if (!bResult) {
			printf("write failed! Err:%d\n", GetLastError());
			goto exit;
		}

		free(tmpbuffer);
	}


exit:
    return bResult;
}

VOID CNtfsController::CloseFile(PFILE_INFORMATION File )
/*++
��������:�ر��ļ�,�ͷ���Դ

����:File:�ļ�������Ϣ�ṹָ��

����ֵ:��

˵��:�����ظ��ر��ļ�,���򽫻����

--*/
{
    PLIST_ENTRY     list = NULL;

    if( File == NULL )return;

    while( !IsListEmpty( &File->List ))
    {
        list = RemoveHeadList( &File->List );
        assert( list != NULL );
        PFILE_ATTRIBUTE_NODE p = (PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD( list,
            FILE_ATTRIBUTE_NODE,
            List );
        if( p->AttributeData != NULL )
            free( p->AttributeData );
        free( p );
    }
    free( File );
}

LONG CNtfsController::GetAttributeListValue( IN PATTR_RECORD AttrRecord,
                                            OUT PVOID Buffer,
                                            IN DWORD BufferLength,
                                            OUT PDWORD BytesReturned )
/*++
��������:��ȡATTRIBUTE_LIST������ֵ����

����˵��:
    AttrRecord:ָ��ATTRIBUTE_LIST�������ݵ�ָ��
    Buffer:���������
    BufferLength:������������ȣ��ֽڣ�
    BytesReturned:ָ�����ڽ��������������Ч�����ֽ�����DWORD����

����ֵ:�ɹ�����0,ʧ�ܷ��� -1,���BufferΪ��,�����������ٵ�Buffer���ȣ�����0)

--*/
{

    if( AttrRecord == NULL || AttrRecord->type != AT_ATTRIBUTE_LIST )
    {
        return -1;
    }

    if( AttrRecord->non_resident == 0 )
    {
        //ATTRIBUTE_LISTΪ��פ
        if( Buffer == NULL )
        {
            return AttrRecord->value_length;
        }

        if( BufferLength < AttrRecord->value_length )
        {
            return -1;
        }

        memcpy_s( Buffer,
            BufferLength,
            (LPVOID)((DWORD_PTR)AttrRecord + AttrRecord->value_offset),
            AttrRecord->value_length );
        if( BytesReturned != NULL)
            *BytesReturned = AttrRecord->value_length;

        return 0;
    }//��פ����
    else
    {
        //ATTRIBUTE_LISTΪ�ǳ�פ
        LPBYTE  DataRuns = (LPBYTE)((DWORD_PTR)AttrRecord + AttrRecord->mapping_pairs_offset);
        DWORD   DataRunsLength = AttrRecord->length - AttrRecord->mapping_pairs_offset;
        LONGLONG NumberOfClusters = GetNumberOfVcnsInDataRuns(DataRuns,DataRunsLength);
        DWORD bytesSize = (DWORD)NumberOfClusters * m_BootSect.bpb.sectors_per_cluster *
            m_BootSect.bpb.bytes_per_sector;

        if(Buffer == NULL )
        {
            return bytesSize;
        }

        if( BufferLength < bytesSize )
        {
            return -1;
        }

        for( LONGLONG vcn = 0;vcn < NumberOfClusters;vcn++)
        {
            LONGLONG lcn = VcnToLcn( vcn,DataRuns,DataRunsLength );
            if( lcn == -1 )break;

            if( !ReadLogicalCluster( (LPBYTE)Buffer + vcn * m_ClusterSizeInBytes,
                m_ClusterSizeInBytes,
                lcn ))
                return -1;
        }
        if( BytesReturned != NULL)
            *BytesReturned = (DWORD)AttrRecord->data_size;

        return 0;
    }//�ǳ�פ����

    return 0;
}

LONG CNtfsController::GetAttributeValue( IN NTFS_FILE File,
                                        IN ATTR_TYPES Type,
                                        OUT PVOID Buffer,
                                        IN DWORD BufferLength,
                                        OUT PBOOL IsDataruns,
                                        IN PWCHAR AttrName,
                                        IN WORD Instance,
                                        OUT PDWORD BytesReturned)
/*++
��������:��ȡ����ֵ����,��פֱ�ӷ�������,�ǳ�פ����dataruns����,���ڽ�һ����ȡ

����:
    File:NTFS_FILE �����ļ���Ϣ�Ľṹ
    Type:��������
    Buffer:���������
    BufferLength:ָ���������������
    IsDataruns:ָ��BOOL����,���ڽ�������������������Ƿ�ΪDataruns
    BytesReturned:ʵ�ʷ��ص��ֽ���
    AttrName:ָ����������UNICODE�ַ���(��L'\0'��β��,Ĭ��ΪNULL������������
    Instance:����ʵ��ID,Ĭ��Ϊ0,��ʾ����,����0x10���Ժ��Դ˲���

����ֵ:�ɹ�����0,ʧ�ܷ��� -1,���BufferΪ��,�����������ٵ�Buffer���ȣ�����0)

˵��:Ҫ�Կ��ļ���¼�����Խ��д���
--*/
{
    LONG result = -1;

    for( PLIST_ENTRY list = File->List.Flink;
        list != &File->List;
        list = list->Flink)
    {
        PFILE_ATTRIBUTE_NODE node = 
            (PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD( list,FILE_ATTRIBUTE_NODE,List);
        PATTR_RECORD AttrRecord = (PATTR_RECORD)node->AttributeData;

        if( node->AttributeType != Type)continue;

        if( AttrName != NULL )
        {
            if( AttrRecord->name_length == 0 )continue;
            if( wcsncmp( (PWCHAR)((DWORD_PTR)AttrRecord + AttrRecord->name_offset),
                AttrName,
                AttrRecord->name_length ) != 0 )
                continue;
        }

        if( node->AttributeType != AT_STANDARD_INFORMATION
            && Instance !=0 && Instance != AttrRecord->instance)
            continue;

        if( AttrRecord->non_resident == 0 )
        {
            //��פ���ԵĴ���,һ�㳣פ���Բ�����ֿ��ļ���¼�����
            if( Buffer == NULL )
            {
                result = AttrRecord->value_length;
                break;
            }

            if( BufferLength < AttrRecord->value_length )
            {
                result = -1;
                break;
            }

            memcpy_s(   Buffer,
                BufferLength,
                (LPVOID)((DWORD_PTR)AttrRecord + AttrRecord->value_offset),
                AttrRecord->value_length );
            if( BytesReturned != NULL)*BytesReturned = AttrRecord->value_length;
            if( IsDataruns != NULL )*IsDataruns = FALSE;

            result = 0;
            break;

        }
        else
        {
            //�ǳ�פ���ԵĴ���,ע����ļ���¼�����
            DWORD valueLength = AttrRecord->length - AttrRecord->mapping_pairs_offset;
            LPVOID tmpBuffer = malloc( valueLength );
            assert( tmpBuffer != NULL);
            memcpy_s( tmpBuffer,
                valueLength,
                (LPVOID)((DWORD_PTR)AttrRecord + AttrRecord->mapping_pairs_offset),
                valueLength );

            PLIST_ENTRY list2 = NULL;
            for(list2 = list->Flink;
                list2 != &File->List;
                list2 = list2->Flink )
            {
                PFILE_ATTRIBUTE_NODE node2 = 
                    (PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD( list2,FILE_ATTRIBUTE_NODE,List);
                PATTR_RECORD AttrRecord2 = (PATTR_RECORD)node2->AttributeData;

                if( node2->AttributeType != Type )break;
                if( AttrRecord->name_length != AttrRecord2->name_length)break;
                if( AttrRecord->name_length > 0 )
                {
                    if( wcsncmp( (PWCHAR)((DWORD_PTR)AttrRecord2 + AttrRecord2->name_offset),
                        (PWCHAR)((DWORD_PTR)AttrRecord + AttrRecord->name_offset),
                        AttrRecord2->name_length ) != 0 )
                        break;
                }
                if( AttrRecord2->non_resident == 0 )break;
                assert( AttrRecord2->lowest_vcn > 0 && AttrRecord2->instance == 0 );

                //ƴ��dataruns
                LONGLONG lastLcn = GetLastStartLcnInDataruns( (LPBYTE)tmpBuffer,valueLength );
                LPBYTE dataruns2 = (LPBYTE)((DWORD_PTR)AttrRecord2 + AttrRecord2->mapping_pairs_offset);
                DWORD_PTR offset_p = GetDataRunsLength( (LPBYTE)tmpBuffer,valueLength );
                LPBYTE p = (LPBYTE)((DWORD_PTR)tmpBuffer + offset_p);
                WORD cBytes = 0;
                if( (*dataruns2 & 0xf0) == 0 )
                {
                    valueLength += *dataruns2;
                    tmpBuffer = realloc( tmpBuffer,valueLength );
                    assert( tmpBuffer != NULL);
                    p = (LPBYTE)((DWORD_PTR)tmpBuffer + offset_p);
                    memcpy_s( p,
                        *dataruns2 + 1,
                        dataruns2,
                        *dataruns2 + 1);
                    cBytes = *dataruns2 + 1;
                    p+= cBytes;
                    dataruns2 += cBytes;
                }
                *p = 0;
                if( *dataruns2 != 0 ){
                    LONGLONG newStartLcn = VcnToLcn( 0,dataruns2,AttrRecord2->length - AttrRecord2->mapping_pairs_offset - cBytes)
                                            -lastLcn;
                    BYTE len_newStartLcn = CompressLongLong( newStartLcn );
                    cBytes = *dataruns2 & 0x0f;
                    valueLength += cBytes +len_newStartLcn+1;
                    offset_p = (DWORD_PTR)p - (DWORD_PTR)tmpBuffer;
                    tmpBuffer = realloc( tmpBuffer,valueLength );
                    assert( tmpBuffer != NULL);
                    p = (LPBYTE)((DWORD_PTR)tmpBuffer + offset_p);
                    *p++ = (len_newStartLcn << 4) | (BYTE)cBytes;
                    memcpy_s( p,
                            cBytes,
                            dataruns2+1,
                            cBytes);
                    p += cBytes;
                    memcpy_s( p,
                            len_newStartLcn,
                            &newStartLcn,
                            len_newStartLcn );
                    p += len_newStartLcn;
                    *p = 0;
                    cBytes = (*dataruns2 & 0x0f)+((*dataruns2 & 0xf0)>>4)+1;
                    dataruns2 += cBytes;
                    offset_p = (DWORD_PTR)p - (DWORD_PTR)tmpBuffer;
                    valueLength += AttrRecord2->length - AttrRecord2->mapping_pairs_offset;//����˵㣬���þ�ȷ������
                    tmpBuffer = realloc( tmpBuffer,valueLength );
                    assert( tmpBuffer != NULL);
                    p = (LPBYTE)((DWORD_PTR)tmpBuffer + offset_p);
                    DWORD remain_len = (DWORD)(((DWORD_PTR)AttrRecord2 + AttrRecord2->length)
                                            - (DWORD_PTR)dataruns2);
                    memcpy_s( p,
                             remain_len,
                             dataruns2,
                             remain_len );
                    p+= remain_len;
                    *p = 0;
                    while( valueLength % 8 != 0 )
                        valueLength++;
                    tmpBuffer = realloc( tmpBuffer,valueLength);
                    assert( tmpBuffer != NULL);
                }
                    
            }// end for list2

            if( IsDataruns != NULL )*IsDataruns = TRUE;

            if( Buffer == NULL)
            {
                result = valueLength;
                free( tmpBuffer );
                tmpBuffer = NULL;
                break;
            }

            if( BufferLength < valueLength )
            {
                result = -1;
                free( tmpBuffer );
                tmpBuffer = NULL;
                break;
            }

            memcpy_s( Buffer,
                BufferLength,
                tmpBuffer,
                valueLength );
            if( BytesReturned != NULL)*BytesReturned = valueLength;

            free( tmpBuffer );
            tmpBuffer = NULL;
            result = 0;
            break;
        }//end else non_resident

    }//end for list

    return result;
}

VOID CNtfsController::UpdateBitmapFromBlockList( PLIST_ENTRY ListHead )
/*++
�����������ӿ���Ϣ�����и���Bitmap

����������Ϣ����ͷ

����ֵ����

˵����������������ΪBLOCK_TYPE_FREE������Ӧλ��0����ΪBLOCK_TYPE_USED/BAD/DEAD����1
--*/
{
    assert( ListHead != NULL);

    for( PLIST_ENTRY list = ListHead->Flink;
        list != ListHead;
        list = list->Flink)
    {
        PBLOCK_DESCRIPTOR block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                        BLOCK_DESCRIPTOR,
                                                                        List );
        LONGLONG startCluster = block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster;
        LONGLONG totalClusters = block->TotalSectors.QuadPart % m_BootSect.bpb.sectors_per_cluster == 0 ?
                                 block->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster:
                                 block->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster + 1;

        if( block->type == BLOCK_TYPE_FREE )
        {
            for( LONGLONG i = startCluster;i < startCluster+totalClusters;i++)
                m_Bitmap[ i / 8 ] &= ~(1 << (i % 8));
        }
        else
        {
            for( LONGLONG i = startCluster;i < startCluster+totalClusters;i++)
                m_Bitmap[ i / 8 ] |= (1 << (i % 8));
        }

    }// end for list
}

LONGLONG CNtfsController::AllocateBlock(LONGLONG LengthInCluster)
/*++
��������������һ��ָ�����ȵĿ��п飨����Bitmap��

��������������Ĵ�С����λΪ��

����ֵ���ɹ��������������״غţ�ʧ�ܷ��ظ�ֵ�������ֵΪĿǰ�ɷ�������鳤

˵������Ҫ����Bitmap��FreeBlockList
--*/
{
    LONGLONG maxBlock = -1,result = -1;
    PLIST_ENTRY list = NULL;
    char message[1024]={0};
    sprintf_s( message,1024,"allocate %x clusters",LengthInCluster );
    DbgPrint( message);
    DbgPrint("show list ...");
    _ShowList();

    for( list = m_BlockInforHead.FreeBlockList.Flink;
        list != &m_BlockInforHead.FreeBlockList;
        )
    {
        PBLOCK_DESCRIPTOR block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                        BLOCK_DESCRIPTOR,
                                                                        List);
        list = list->Flink;

        LONGLONG start = block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster;
        LONGLONG len = block->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster;


        if( LengthInCluster < len )
        {
            block->TotalSectors.QuadPart -= LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
            m_BlockInforHead.FreeBlockSize.QuadPart -= LengthInCluster * m_ClusterSizeInBytes;
            start += block->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster;

            result =  start;
            break;
        }
        else if( LengthInCluster == len )
        {
            m_BlockInforHead.FreeBlockSize.QuadPart -= LengthInCluster * m_ClusterSizeInBytes;
            RemoveEntryList( &block->List );
            free( block );
            block = NULL;

            result =  start;
            break;
        }

        else
        {
            if( maxBlock < len )
                maxBlock = len;
        }
    }

    if( result != -1 )
    {
        //����Bitmap
        for(LONGLONG i = result;i < result + LengthInCluster;i++)
            m_Bitmap[ i / 8 ] |= (1 << (i % 8));

        //�������ÿ�����
        m_BlockInforHead.UsedBlockSize.QuadPart += LengthInCluster * m_ClusterSizeInBytes;
        
        if( IsListEmpty( &m_BlockInforHead.UsedBlockList))
        {
            PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
            assert( node != NULL );

            RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
            node->StartSector.QuadPart = result * m_BootSect.bpb.sectors_per_cluster;
            node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
            node->type = BLOCK_TYPE_USED;
            InsertHeadList( &m_BlockInforHead.UsedBlockList,&node->List );
            node = NULL;

            return result;
        }

        PBLOCK_DESCRIPTOR first_block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
            m_BlockInforHead.UsedBlockList.Flink,
            BLOCK_DESCRIPTOR,
            List);
        PBLOCK_DESCRIPTOR last_block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
            m_BlockInforHead.UsedBlockList.Blink,
            BLOCK_DESCRIPTOR,
            List);

        if( result <= first_block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster )
        {
            if( result + LengthInCluster >= 
                first_block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster )
            {
                first_block->TotalSectors.QuadPart = 
                    first_block->StartSector.QuadPart + first_block->TotalSectors.QuadPart
                    - result * m_BootSect.bpb.sectors_per_cluster;
                first_block->StartSector.QuadPart = result * m_BootSect.bpb.sectors_per_cluster;
            }
            else
            {
                PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
                assert( node != NULL );

                RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
                node->StartSector.QuadPart = result * m_BootSect.bpb.sectors_per_cluster;
                node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
                node->type = BLOCK_TYPE_USED;
                InsertHeadList( &m_BlockInforHead.UsedBlockList,&node->List );
                node = NULL;
            }
        }
        else if(result >= last_block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster)
        {
            if( (last_block->StartSector.QuadPart + last_block->TotalSectors.QuadPart)
                / m_BootSect.bpb.sectors_per_cluster 
                >= result )
            {
                last_block->TotalSectors.QuadPart = (result + LengthInCluster)
                    * m_BootSect.bpb.sectors_per_cluster - last_block->StartSector.QuadPart;
            }
            else
            {
                PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
                assert( node != NULL );

                RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
                node->StartSector.QuadPart = result * m_BootSect.bpb.sectors_per_cluster;
                node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
                node->type = BLOCK_TYPE_USED;
                InsertTailList( &m_BlockInforHead.UsedBlockList,&node->List );
                node = NULL;
            }
        }
        else{

            for( list = m_BlockInforHead.UsedBlockList.Flink;
                list != &m_BlockInforHead.UsedBlockList;
                )
            {
                //�ϱ��Ѿ��ų��������
                assert( list != m_BlockInforHead.UsedBlockList.Blink );

                PBLOCK_DESCRIPTOR block_prev = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                            BLOCK_DESCRIPTOR,
                                                                            List);
                list = list->Flink;
                PBLOCK_DESCRIPTOR block_next = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                            BLOCK_DESCRIPTOR,
                                                                            List);
                //Ѱ�Ҳ����
                if( result > block_next->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster)
                    continue;
                
                //����鲢����������

                BOOLEAN bAdjPrev = (
                    result > block_prev->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster &&
                    result <= (block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart)
                    / m_BootSect.bpb.sectors_per_cluster);
                BOOLEAN bAdjNext = (
                    result + LengthInCluster >= block_next->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster &&
                    result + LengthInCluster < (block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart)
                    / m_BootSect.bpb.sectors_per_cluster);

                if( bAdjPrev && bAdjNext )
                {
                    //ǰ�������
                    block_prev->TotalSectors.QuadPart = 
                        block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart
                        - block_prev->StartSector.QuadPart;
                    RemoveEntryList( &block_next->List );
                    free( block_next );
                    block_next = NULL;
                }
                else if ( bAdjPrev )
                {
                    block_prev->TotalSectors.QuadPart = 
                        (result + LengthInCluster) * m_BootSect.bpb.sectors_per_cluster
                        - block_prev->StartSector.QuadPart;
                }
                else if( bAdjNext )
                {
                    block_next->TotalSectors.QuadPart = 
                        block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart
                        - result * m_BootSect.bpb.sectors_per_cluster;
                    block_next->StartSector.QuadPart = result * m_BootSect.bpb.sectors_per_cluster;
                }
                else
                {
                    PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
                    assert( node != NULL );

                    RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
                    node->StartSector.QuadPart = result * m_BootSect.bpb.sectors_per_cluster;
                    node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
                    node->type = BLOCK_TYPE_USED;
                    InsertHeadList( &block_prev->List,&node->List );
                    node = NULL;
                }// end if bAdj....
                
                break;
            }// end for list

        }//end if
        sprintf_s( message,1024,"allocate: %lld %lld\n",result,LengthInCluster );
        DbgPrint( message);
        DbgPrint("show list 2");
        _ShowList();
        return result;
    }//end if result != -1

    DbgPrint(" allocate failed!");
    return -maxBlock;
}

BOOL CNtfsController::FreeBlock( LONGLONG StartCluster,LONGLONG LengthInCluster )
/*++
�����������ͷſ��ÿռ�

������
    StartCluster:��ʼ�غ�
    LengthInCluster:�鳤�ȣ���λΪ��

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE

--*/
{
    CHAR buffer[1024] = {0};
    BOOL bResult = FALSE;

    sprintf_s(buffer,sizeof(buffer),"FreeBlock(%lld,%lld)",StartCluster,LengthInCluster);
    DbgPrint( buffer );
    DbgPrint("show list...");
    _ShowList();
    PLIST_ENTRY list = NULL;
    for( list = m_BlockInforHead.UsedBlockList.Flink;
        list != &m_BlockInforHead.UsedBlockList;
        )
    {
        PBLOCK_DESCRIPTOR block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                        BLOCK_DESCRIPTOR,
                                                                        List);
        list = list->Flink;

        LONGLONG start = block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster;
        LONGLONG len = block->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster;
        
        //�ͷſ��������ĳռ�ÿ�
        if(!( StartCluster >= start && StartCluster + LengthInCluster <= start + len))
            continue;
        
        m_BlockInforHead.UsedBlockSize.QuadPart -= LengthInCluster * m_ClusterSizeInBytes;
        
        if( StartCluster == start )
        {
            block->StartSector.QuadPart += LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
            block->TotalSectors.QuadPart -= LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
            if( block->TotalSectors.QuadPart == 0 )
            {
                RemoveEntryList(&block->List);
                free( block );
            }

        }
        else
        {

            if( start + len > StartCluster + LengthInCluster)
            {
                //���ӽڵ�

                PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
                assert( node != NULL );
                RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));

                node->StartSector.QuadPart = 
                    (StartCluster + LengthInCluster) * m_BootSect.bpb.sectors_per_cluster;
                node->TotalSectors.QuadPart = 
                    (start + len - StartCluster - LengthInCluster ) * m_BootSect.bpb.sectors_per_cluster;
                node->type = BLOCK_TYPE_USED;
                InsertHeadList( &block->List,&node->List );
                node = NULL;
            }
            
            block->TotalSectors.QuadPart = 
                (StartCluster - start ) * m_BootSect.bpb.sectors_per_cluster;

        }

        bResult = TRUE;
        break;

    }

    if( !bResult )goto exit;

    //����Bitmap
    for(LONGLONG i = StartCluster;i < StartCluster + LengthInCluster;i++)
        m_Bitmap[ i / 8 ] &= ~(1 << (i % 8));

    //�������п�����
    m_BlockInforHead.FreeBlockSize.QuadPart += LengthInCluster * m_ClusterSizeInBytes;
    
    if( IsListEmpty( &m_BlockInforHead.FreeBlockList))
    {
        PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
        assert( node != NULL );

        RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
        node->StartSector.QuadPart = StartCluster * m_BootSect.bpb.sectors_per_cluster;
        node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
        node->type = BLOCK_TYPE_USED;
        InsertHeadList( &m_BlockInforHead.FreeBlockList,&node->List );
        node = NULL;

        DbgPrint("notice!");
        return bResult;
    }

    PBLOCK_DESCRIPTOR first_block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
        m_BlockInforHead.FreeBlockList.Flink,
        BLOCK_DESCRIPTOR,
        List);
    PBLOCK_DESCRIPTOR last_block = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD(
            m_BlockInforHead.FreeBlockList.Blink,
            BLOCK_DESCRIPTOR,
            List);

    if( StartCluster <= first_block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster )
    {
        if( StartCluster + LengthInCluster >= 
            first_block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster )
        {
            first_block->TotalSectors.QuadPart = 
                first_block->StartSector.QuadPart + first_block->TotalSectors.QuadPart
                - StartCluster * m_BootSect.bpb.sectors_per_cluster;
            first_block->StartSector.QuadPart = StartCluster * m_BootSect.bpb.sectors_per_cluster;

        }
        else
        {
            PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
            assert( node != NULL );

            RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
            node->StartSector.QuadPart = StartCluster * m_BootSect.bpb.sectors_per_cluster;
            node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
            node->type = BLOCK_TYPE_USED;
            InsertHeadList( &m_BlockInforHead.FreeBlockList,&node->List );
            node = NULL;
        }
    }
    else if(StartCluster >= last_block->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster)
    {
        if( (last_block->StartSector.QuadPart + last_block->TotalSectors.QuadPart)
            / m_BootSect.bpb.sectors_per_cluster 
            >= StartCluster )
        {
            last_block->TotalSectors.QuadPart += LengthInCluster
                * m_BootSect.bpb.sectors_per_cluster;
        }
        else
        {
            PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
            assert( node != NULL );

            RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
            node->StartSector.QuadPart = StartCluster * m_BootSect.bpb.sectors_per_cluster;
            node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
            node->type = BLOCK_TYPE_USED;
            InsertTailList( &m_BlockInforHead.FreeBlockList,&node->List );
            node = NULL;
        }
    }
    else{

        for( list = m_BlockInforHead.FreeBlockList.Flink;
            list != &m_BlockInforHead.FreeBlockList;
            )
        {
            //�ϱ��Ѿ��ų��������
            assert( list != m_BlockInforHead.FreeBlockList.Blink );

            PBLOCK_DESCRIPTOR block_prev = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                        BLOCK_DESCRIPTOR,
                                                                        List);
            list = list->Flink;
            PBLOCK_DESCRIPTOR block_next = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list,
                                                                            BLOCK_DESCRIPTOR,
                                                                            List);
            //Ѱ�Ҳ����
            if( StartCluster > block_next->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster)
                continue;
                
            //����鲢����������

            BOOLEAN bAdjPrev = (
                StartCluster > block_prev->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster &&
                StartCluster <= (block_prev->StartSector.QuadPart + block_prev->TotalSectors.QuadPart)
                / m_BootSect.bpb.sectors_per_cluster);
            BOOLEAN bAdjNext = (
                StartCluster + LengthInCluster >= block_next->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster &&
                StartCluster + LengthInCluster < (block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart)
                / m_BootSect.bpb.sectors_per_cluster);

            if( bAdjPrev && bAdjNext )
            {
                //ǰ�������
                block_prev->TotalSectors.QuadPart = 
                    block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart
                    - block_prev->StartSector.QuadPart;
                RemoveEntryList( &block_next->List );
                free( block_next );
                block_next = NULL;
            }
            else if ( bAdjPrev )
            {
                block_prev->TotalSectors.QuadPart = 
                    (StartCluster + LengthInCluster) * m_BootSect.bpb.sectors_per_cluster
                    - block_prev->StartSector.QuadPart;
            }
            else if( bAdjNext )
            {
                block_next->TotalSectors.QuadPart = 
                    block_next->StartSector.QuadPart + block_next->TotalSectors.QuadPart
                    - StartCluster * m_BootSect.bpb.sectors_per_cluster;
                block_next->StartSector.QuadPart = StartCluster * m_BootSect.bpb.sectors_per_cluster;
            }
            else
            {
                PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)malloc( sizeof( BLOCK_DESCRIPTOR));
                assert( node != NULL );

                RtlZeroMemory( node,sizeof( BLOCK_DESCRIPTOR ));
                node->StartSector.QuadPart = StartCluster * m_BootSect.bpb.sectors_per_cluster;
                node->TotalSectors.QuadPart = LengthInCluster * m_BootSect.bpb.sectors_per_cluster;
                node->type = BLOCK_TYPE_USED;
                InsertHeadList( &block_prev->List,&node->List );
                node = NULL;
            }// end if bAdj....
                
            break;
        }// end for list

    }//else end

exit:
    if( bResult)
        DbgPrint("return true");
    else 
        DbgPrint("return false");
    DbgPrint("show list2...");
    _ShowList();

    return bResult;
}

BOOL CNtfsController::FreeBlockInDataruns(LPBYTE DataRuns,DWORD Length)
/*++
�����������ͷ�dataruns�����Ŀ�ռ�õĿռ�

������
    Dataruns:ָ����dataruns���ݵĻ�����ָ��
    Length:dataruns���ݵĳ���

����ֵ���ɹ�����TRUE,ʧ�ܷ���FALSE
--*/
{
    LONGLONG startLcn = 0,len = 0;
    BOOL bResult = TRUE;

    if( DataRuns == NULL)return FALSE;

    for(DWORD i = 0;
        i < Length;
        )
    {
        DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

        if( DataRuns[i] == 0 )break;

        cStartLcnBytes = ( DataRuns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
        cLenLcnBytes = (DataRuns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

        if( cStartLcnBytes != 0)
        {
            //��ȡ��ǰ����������
            len = 0;
            for( DWORD j = cLenLcnBytes;j > 0;j--)
            {
                len = (len << 8) | DataRuns[i + j ]; 
            }

            //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
            LONGLONG tmp = 0;
            if( DataRuns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                tmp = -1ll;
            for( DWORD j = cStartLcnBytes;j > 0;j-- )
            {
                tmp = ( tmp << 8 ) | DataRuns[i + cLenLcnBytes + j ];
            }
            startLcn = startLcn + tmp;
            assert( startLcn >= 0 );

            bResult = FreeBlock( startLcn,len );
            if( !bResult )
            {
                DbgPrint("free block in dataruns failed!");
                goto exit;
            }
        }

        i += cStartLcnBytes + cLenLcnBytes + 1;
    }
exit:
    return bResult;
}

LONGLONG CNtfsController::AllocateFileRecordId()
/*++
�������������ļ���¼����һ�����õ��ļ���¼�ţ�������Ӧ��λ���Ϊռ��

��������

����ֵ���ɹ�������������ļ���¼�ţ�ʧ�ܷ���-1
--*/
{
    LONGLONG file_id = -1;

    for( LONGLONG i = 3;
        i < (m_MftNumberOfRecord % 8==0?m_MftNumberOfRecord/8:m_MftNumberOfRecord/8 + 1);
        i++)
    {
        BYTE byte = m_MftBitmap[i];
        if( byte == 0xff)
            continue;

        for( int j = 0;j < 8;j++)
        {
            if( byte & (1 << j))
                continue;
            file_id = i * 8 + j;
            break;
        }
        break;
    }
    if( file_id != -1 )
        m_MftBitmap[ file_id / 8 ] |= (1 << file_id % 8);
    
    return file_id;
}

VOID CNtfsController::FreeFileRecordId( LONGLONG FileRecordId )
/*++
�������������ļ���¼����λͼ���ͷ�ָ�����ļ���¼��

��������

����ֵ����
--*/
{
    BOOL bOk = TRUE;
    assert( m_MftBitmap[ FileRecordId/8] & (1 << (FileRecordId % 8)));
    m_MftBitmap[ FileRecordId / 8 ] &= ~(1 << FileRecordId % 8);
    PMFT_RECORD pRecordHeader = (PMFT_RECORD)malloc( this->m_MftRecordLength);
    assert( pRecordHeader != NULL);

    bOk = ReadMftRecord( FileRecordId,pRecordHeader,m_MftRecordLength );
    assert( bOk );
    pRecordHeader->flags = MFT_RECORD_UNUSED;
    bOk = WriteMftRecord( FileRecordId,pRecordHeader,m_MftRecordLength );
    assert( bOk );
    free( pRecordHeader );
    pRecordHeader = NULL;

}

LONG CNtfsController::CheckAndUpdateFile(LONGLONG FileId )
/*++
��������������ļ��Ĵ洢�ռ��Ƿ��ڻ����������ڣ�������������̿ռ䲢ת�����ݣ�����dataruns

����:FileId:�ļ���¼ID

����ֵ��
    0���ļ����ڻ����������У�����Ҫ����
    1���ļ��ܵ�������Ӱ�죬�������ɹ�
    2���ļ��ܵ�������Ӱ�죬���޷�����
    -1:��Ч�ļ�
--*/
{
    LPBYTE dataruns = NULL;
    LONGLONG len_dataruns = 0;
    LONG result = 0;

    NTFS_FILE hFile = OpenNtfsFile( FileId );
    if( hFile == NULL)
    {
        result = -1;
        goto exit;
    }

    for( PLIST_ENTRY list = hFile->List.Flink;
        list != &hFile->List;
        list = list->Flink)
    {
        PFILE_ATTRIBUTE_NODE node = (PFILE_ATTRIBUTE_NODE)CONTAINING_RECORD(
                                                    list,
                                                    FILE_ATTRIBUTE_NODE,
                                                    List);
        assert( node != NULL);
        PATTR_RECORD pAttrRecord = (PATTR_RECORD)node->AttributeData;
        if( pAttrRecord->non_resident == 0 )
            continue;

        dataruns = (LPBYTE)((DWORD_PTR)pAttrRecord + pAttrRecord->mapping_pairs_offset);
        len_dataruns = node->Length - pAttrRecord->mapping_pairs_offset;
        LONGLONG startLcn = 0,len = 0;

//===================================================================================          
        //�ж�dataruns�����Ĵر��Ƿ��ڻ���������

        BOOL bFound = FALSE;
        for(DWORD i = 0;
            i < len_dataruns;
            )
        {
            DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

            if( dataruns[i] == 0 )break;

            cStartLcnBytes = ( dataruns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
            cLenLcnBytes = (dataruns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

            if( cStartLcnBytes != 0)
            {
                //��ȡ��ǰ����������
                len = 0;
                for( DWORD j = cLenLcnBytes;j > 0;j--)
                {
                    len = (len << 8) | dataruns[i + j ]; 
                }

                //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
                LONGLONG tmp = 0;
                if( dataruns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                    tmp = -1ll;
                for( DWORD j = cStartLcnBytes;j > 0;j-- )
                {
                    tmp = ( tmp << 8 ) | dataruns[i + cLenLcnBytes + j ];
                }
                startLcn = startLcn + tmp;
                assert( startLcn >= 0 );
                
                for( PLIST_ENTRY list2 = m_BlockInforHead.BadBlockList.Flink;
                    list2 != &m_BlockInforHead.BadBlockList;
                    list2 = list2->Flink )
                {
                    PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list2,
                                                            BLOCK_DESCRIPTOR,
                                                            List );
                    assert( node != NULL);

                    LONGLONG startLcn2 = node->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster;
                    LONGLONG len2 = node->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster;

                    if( (startLcn < startLcn2 + len2) &&
                        ( startLcn2 < startLcn + len ))
                    {
                        bFound = TRUE;
                        result = 1;
                        break;
                    }
                }//end for list2

                if( bFound )break;
            }//end if cStartLcn > 0 

            i += cStartLcnBytes + cLenLcnBytes + 1;
        }//end for i

//====================================================================================

        if( bFound  )
        {
            //Ŀǰ�޷�����ѹ���ļ�
            if( pAttrRecord->compression_unit != 0 )
            {
                result = 2;
                goto exit;
            }

            LONGLONG vcns = GetNumberOfVcnsInDataRuns( dataruns,(DWORD)len_dataruns );
            assert( vcns > 0 );
            //printf("vcns = %lld\n",vcns );
            LONGLONG newBlock = AllocateBlock( vcns );
            //printf("newBlock = %lld\n",newBlock );
            if( newBlock < 0 || CompressLongLong(newBlock)+CompressLongLong( vcns) + 2 > len_dataruns )                          //�д����µĵط�
            {
                if( newBlock >= 0 )
                    FreeBlock( newBlock,vcns );
                result = 2;
                goto exit;
            }

//====================================================================================
            BOOL bOk=TRUE;
            CHAR message_buf[1024]={0};
            sprintf_s( message_buf,1024,"�����ƶ��ļ�%lld ...   ",FileId);
            ReportStateMessage( message_buf);
            LONGLONG dstLcn = newBlock;
            startLcn = 0;

            for(DWORD i = 0;
                i < len_dataruns;
                )
            {
                DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

                if( dataruns[i] == 0 )break;

                cStartLcnBytes = ( dataruns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
                cLenLcnBytes = (dataruns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

                if( cStartLcnBytes != 0)
                {
                    //��ȡ��ǰ����������
                    len = 0;
                    for( DWORD j = cLenLcnBytes;j > 0;j--)
                    {
                        len = (len << 8) | dataruns[i + j ]; 
                    }

                    //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
                    LONGLONG tmp = 0;
                    if( dataruns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                        tmp = -1ll;
                    for( DWORD j = cStartLcnBytes;j > 0;j-- )
                    {
                        tmp = ( tmp << 8 ) | dataruns[i + cLenLcnBytes + j ];
                    }
                    startLcn = startLcn + tmp;
                    assert( startLcn >= 0 );
                    bOk = CopyLogicalClusterBlock( startLcn,dstLcn,len );
                    if( !bOk )
                    {
                        FreeBlock( newBlock,vcns );
                        result = 2;
                        goto exit;
                    }
                    dstLcn += len;
                    ReportNotifyMessage();

                }//end if cStartLcn > 0 

                i += cStartLcnBytes + cLenLcnBytes + 1;
            }//end for i

//===============================================================================

            //�ͷ�ԭʼdataruns�еĿ��ÿռ�
            startLcn = 0;len = 0;
            for(DWORD i = 0;
                i < len_dataruns;
               )
            {
                DWORD   cStartLcnBytes = 0,cLenLcnBytes = 0;

                if( dataruns[i] == 0 )break;

                cStartLcnBytes = ( dataruns[i] & 0xf0) >> 4;//ѹ���ֽڵĸ�4λ
                cLenLcnBytes = (dataruns[i] & 0x0f);        //ѹ���ֽڵĵ�4λ

                if( cStartLcnBytes != 0)
                {
                    //��ȡ��ǰ����������
                    len = 0;
                    for( DWORD j = cLenLcnBytes;j > 0;j--)
                    {
                        len = (len << 8) | dataruns[i + j ]; 
                    }

                    //��ȡ��ǰ��������ʼ�غţ������������һ����������ƫ��,�з��ţ�
                    LONGLONG tmp = 0;
                    if( dataruns[i + cLenLcnBytes + cStartLcnBytes ] & 0x80 )
                        tmp = -1ll;
                    for( DWORD j = cStartLcnBytes;j > 0;j-- )
                    {
                        tmp = ( tmp << 8 ) | dataruns[i + cLenLcnBytes + j ];
                    }
                    startLcn = startLcn + tmp;
                    assert( startLcn >= 0 );
                    FreeBlock( startLcn,len );
#if 0
                    for( PLIST_ENTRY list2 = m_BlockInforHead.BadBlockList.Flink;
                        list2 != &m_BlockInforHead.BadBlockList;
                        list2 = list2->Flink )
                    {
                        PBLOCK_DESCRIPTOR node = (PBLOCK_DESCRIPTOR)CONTAINING_RECORD( list2,
                                                                BLOCK_DESCRIPTOR,
                                                                List );
                        assert( node != NULL);

                        LONGLONG startLcn2 = node->StartSector.QuadPart / m_BootSect.bpb.sectors_per_cluster;
                        LONGLONG len2 = node->TotalSectors.QuadPart / m_BootSect.bpb.sectors_per_cluster;
                        
                        if( (startLcn < startLcn2 + len2) &&
                            ( startLcn2 < startLcn + len ))
                        {
                            //���ص������

                            LONGLONG overlappedStart
                                = max( startLcn,startLcn2 );
                            LONGLONG overlappedLen = 
                                min( startLcn + len,startLcn2 + len2)  - overlappedStart;

                            if( startLcn < overlappedStart )
                                FreeBlock( startLcn,overlappedStart - startLcn );
                            if( startLcn + len > overlappedStart + overlappedLen )
                                FreeBlock( overlappedStart + overlappedLen,
                                            (startLcn + len )-(overlappedStart + overlappedLen));
                        }
                    }//end for list2
#endif
                }//end if cStartLcn > 0;

                i += cStartLcnBytes + cLenLcnBytes + 1;
            }//end for i
//=================================================================================

            //�޸���������Ӧ��datarunsָ��newBlock

            LPBYTE buffer = (LPBYTE)malloc( this->m_MftRecordLength );
            assert( buffer != NULL);
            bOk = ReadMftRecord( node->OwnerRecordId,buffer,m_MftRecordLength );
            assert( bOk );
            PMFT_RECORD pRecordHeader = (PMFT_RECORD)buffer;
            
            PWORD   pUsa = (PWORD)((DWORD_PTR)pRecordHeader + pRecordHeader->usa_ofs);
            WORD    cUsa = pRecordHeader->usa_count;

            //��USA�����������ĩβ�����ֽڵ�����
            for( WORD i = 1;i < cUsa;i++)
            {
                assert( *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) == pUsa[0]);
                *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[i];
            }

            PATTR_RECORD pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pRecordHeader + pRecordHeader->attrs_offset);
            for( ;
                pAttrRecord2->type != AT_END ;
                pAttrRecord2 = (PATTR_RECORD)((DWORD_PTR)pAttrRecord2 + pAttrRecord2->length))
            {
                if( pAttrRecord->type == pAttrRecord2->type
                    && pAttrRecord->resident_flags == pAttrRecord2->resident_flags
                    && pAttrRecord->name_length == pAttrRecord2->name_length
                    && pAttrRecord->instance == pAttrRecord2->instance
                    && pAttrRecord->data_size == pAttrRecord2->data_size
                    && pAttrRecord->lowest_vcn == pAttrRecord2->lowest_vcn)
                    break;
            }
            assert( pAttrRecord2->type != AT_END );
            LPBYTE p = (LPBYTE)((DWORD_PTR)pAttrRecord2 + pAttrRecord2->mapping_pairs_offset);

            //����newBlock��vcns���ֽڳ���

            BYTE c_newBlock = 8,c_vcns = 8;
            c_newBlock = CompressLongLong( newBlock );
            c_vcns = CompressLongLong( vcns );
            //printf("c_newBlock = %d,c_vcns = %d\n",c_newBlock,c_vcns );

            p[0] = (c_newBlock << 4) | c_vcns;
            //printf("p[0] = 0x%.2x\n",p[0] );
            for( BYTE i = 0;i < c_vcns;i++)
            {
                p[i+1] = (BYTE)((vcns >> i*8) & 0xff);
                //printf(" 0x%.2x",p[i+1]);
            }
            for( BYTE i = 0;i < c_newBlock;i++)
            {
                p[c_vcns+i+1] = (BYTE)((newBlock >> i*8) & 0xff);
                //printf(" 0x%.2x",p[c_vcns+i+1]);
            }
            p[c_vcns + c_newBlock + 1] = 0;

            //���������ļ�$MFT
            if( node->OwnerRecordId == FILE_MFT && 
                pAttrRecord2->name_length == 0 &&
                pAttrRecord2->type == AT_DATA )
            {
                memcpy_s(   m_MftDataRuns,
                            m_MftDataRunsLength,
                            p,
                            c_vcns + c_newBlock + 2 );
                m_BootSect.mft_lcn = newBlock;
            }

            //���������ļ�$MFTMirr
            if( node->OwnerRecordId == FILE_MFTMirr && 
                pAttrRecord2->name_length == 0 &&
                pAttrRecord2->type == AT_DATA )
            {
                m_BootSect.mftmirr_lcn = newBlock;
            }

            for( WORD i = 1;i < cUsa;i++)
            {
                pUsa[i] = *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD));
                *(PWORD)((DWORD_PTR)pRecordHeader + i * m_BootSect.bpb.bytes_per_sector - sizeof(WORD)) = pUsa[0];
            }

            bOk = WriteMftRecord( FileId,buffer,m_MftRecordLength );
            assert( bOk );
            free( buffer);buffer = NULL;

//=================================================================================

        }//end if result == 1

    }//end for attribute list

exit:
    if( result == 2 )
    {
        WCHAR filename[1024]={0};
        memcpy_s( filename,1024*sizeof(WCHAR),hFile->FileName,hFile->FileNameLength*sizeof(WCHAR));
        size_t len = wcslen( filename );
        filename[ len ]=L'\r';
        filename[ len + 1] = L'\n';
        ReportFileNameMessage( filename );
    }

    if( hFile != NULL)
        CloseFile( hFile );

    return result;

//�������̫���ˡ�������
}


