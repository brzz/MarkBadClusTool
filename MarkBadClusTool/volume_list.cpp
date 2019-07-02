//volume_list.cpp for class---CVolumeList
//author:lzc
//date:2012/11/10
//e-mail:hackerlzc@126.com

#include"stdafx.h"
#include<windows.h>
#include<winioctl.h>
#include<assert.h>
#include"layout_mbr.h"
#include"volume_list.h"

//��ʵ��


CVolumeList::CVolumeList(LPSTR DiskPath,DWORD DiskId)
/*++
�������������캯��

���� 
    DiskPath:�����豸·��

����ֵ����
--*/
:m_VolumeCount(0),
m_DiskId(DiskId)
{
    assert( DiskPath != NULL);

    m_hDisk = CreateFile( DiskPath,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if( m_hDisk == INVALID_HANDLE_VALUE ) {
        DbgPrint("open disk device failed!");
    }
    RtlZeroMemory( m_tbl_VolumeOffset,sizeof(m_tbl_VolumeOffset));
    memset( &m_tbl_VolumeOwnerDiskId,0xcc,sizeof(m_tbl_VolumeOwnerDiskId));
    CHAR volumePath[]="\\\\.\\C:";
    DWORD bytesReturned = 0;
    for( CHAR letter = 'C';letter <='Z';letter++)
    {
        volumePath[4]=letter;
        HANDLE hVolume = CreateFile( volumePath,
                            GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
        if( hVolume == INVALID_HANDLE_VALUE )
            continue;
        
        VOLUME_DISK_EXTENTS     volumeExtents={0};
        BOOL bOk = DeviceIoControl(
          hVolume,
          IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
          NULL,
          0,         
          &volumeExtents,
          sizeof(volumeExtents),
          &bytesReturned,
          NULL
        );
        if( !bOk )
        {
            m_tbl_VolumeOffset[letter - 'A'] = 0;
        }
        else
        {
            assert( volumeExtents.NumberOfDiskExtents == 1);
            m_tbl_VolumeOffset[letter - 'A'] = 
                volumeExtents.Extents[0].StartingOffset.QuadPart;
            m_tbl_VolumeOwnerDiskId[letter - 'A'] = 
                volumeExtents.Extents[0].DiskNumber;
        }

        CloseHandle( hVolume );
    }

    InitVolumeList();
}

CVolumeList::~CVolumeList()
/*++
�����������ع��������ͷű��ද̬������ڴ���Դ

��������

����ֵ����

--*/
{
    ReleaseAllResources();
}

WORD CVolumeList::GetVolumeCount()
/*++
���������������о�����

��������

����ֵ�������о�����

--*/
{
    return m_VolumeCount;
}

BOOL CVolumeList::GetVolumeByIndex(WORD index, PVOLUME_NODE *result)
/*++
����������ͨ��������������Ӧ����Ϣ���

����
    index:�����
    result:�������ṩ��ָ��ռ䣬���Դ�Ž������Ϣ����ָ��

����ֵ��
    TRUE:�����ɹ���*resultָ����ȷ�Ľ��
    FALSE:����ʧ�ܣ�*result��ΪNULL
--*/
{
    PLIST_ENTRY pEntry = NULL;

    for( pEntry = m_VolumeListHead.Flink;
        pEntry != (PLIST_ENTRY)&m_VolumeListHead;
        pEntry = pEntry->Flink)
    {
        PVOLUME_NODE    pVolumeNode = (PVOLUME_NODE)
            CONTAINING_RECORD(pEntry,VOLUME_NODE,List);
        if( pVolumeNode->Index == index )
        {
            *result = pVolumeNode;
            break;
        }
    }
    if( pEntry != (PLIST_ENTRY)&m_VolumeListHead )
        return TRUE;
    else
        return FALSE;
}

PVOLUME_NODE CVolumeList::GetFirstVolume()
/*++
�������������ص�һ������Ϣ���

��������

����ֵ���ɹ��򷵻ص�һ������Ϣ���ָ��
        ʧ�ܷ���NULL
--*/
{
    if( IsListEmpty( &m_VolumeListHead ))
        return NULL;

    return (PVOLUME_NODE)CONTAINING_RECORD( m_VolumeListHead.Flink,
        VOLUME_NODE,List );
}

PVOLUME_NODE CVolumeList::GetNextVolume(PVOLUME_NODE curVolume)
/*++
����������ͨ����ǰ���о���Ϣ���ָ�룬������һ������Ϣ���ָ��

����    curVolume:��ǰ����Ϣ���ָ��

����ֵ����һ������Ϣ���ָ�룬ʧ�ܷ���NULL����ʾ�Ѿ������β��

--*/
{
    assert( curVolume != NULL );

    if( curVolume->List.Flink == &m_VolumeListHead )
        return NULL;
    return (PVOLUME_NODE)CONTAINING_RECORD( curVolume->List.Flink,
                                            VOLUME_NODE,
                                            List);
}


VOID CVolumeList::UpdateVolumeList()
/*++
�������������¾�����Ϣ

��������

����ֵ����

--*/
{
    ReleaseAllResources();
    InitVolumeList();
}

VOID CVolumeList::ReleaseAllResources()
/*++
�����������ͷ��������ж�̬������ڴ���Դ

��������

����ֵ����

--*/
{
    PLIST_ENTRY entry = NULL;
    for( entry = RemoveHeadList( &m_VolumeListHead );
        entry != NULL;
        entry = RemoveHeadList( &m_VolumeListHead))
    {
        PVOLUME_NODE node = (PVOLUME_NODE)CONTAINING_RECORD(
            entry,
            VOLUME_NODE,
            List);
        if( node->VolumeName != NULL)free( node->VolumeName );
        free( node );
        node = NULL;
        m_VolumeCount--;
    }

    if( m_hDisk != INVALID_HANDLE_VALUE )
        CloseHandle( m_hDisk );

    assert( m_VolumeCount == 0 );
    assert( IsListEmpty( &m_VolumeListHead ));
}

VOID CVolumeList::InitVolumeList()
/*++
������������ʼ�����б�

��������

����ֵ����

--*/
{
    InitializeListHead( &m_VolumeListHead );
    m_VolumeCount = (WORD)SearchMbrVolume( 0 );

}

DWORD CVolumeList::SearchMbrVolume(DWORD BaseSector, DWORD BaseEbrSector /*= 0*/)
/*++
�������������������еľ���������Ϣ����

������
    BaseSector:MBR ���� EBR���ڵľ���������
    BaseEbrSector: ����EBR�����������Ժ�

����ֵ���������ľ�����

ע�⣺*�˺������Ϊ�ݹ���ú�����
      
      *EBR���������߼������������������ڵ�EBR����������Ϊ��ַ�ġ�
       EBR����������DOS��չ�������Ի���EBR����������Ϊ��ַ��
      *����EBR��ָMBR��������EBR��
--*/
{
    DWORD   i = 0;
    BOOL    bOk = FALSE;
    MBR_SECTOR  mbrSector = {0};    //ͬʱ��ΪEBRʹ��  
    DWORD   VolumeCount = 0;

    if( m_hDisk == INVALID_HANDLE_VALUE )
    {
        DbgPrint("Invalid handle value!");
        return 0;
    }

    bOk = ReadSector( m_hDisk,&mbrSector,sizeof( mbrSector),BaseSector);
    if( !bOk )
    {
        DbgPrint("Read sector failed!");
        return 0;
    }

    if( mbrSector.end_flag != 0xaa55 )
    {
        DbgPrint("mbr sector is invalid!");
        return 0;
    }

    for( i = 0;i < 4;i++)
    {
        if( mbrSector.dpt[i].partition_type_indicator == PARTITION_TYPE_ILLEGAL)
            continue;

        if( IsVolumeTypeSupported( mbrSector.dpt[i].partition_type_indicator))
        {
            //֧�ֵľ�����
            PVOLUME_NODE    node = {0};
            CHAR            buffer[256];

            node = (PVOLUME_NODE)malloc( sizeof( VOLUME_NODE ));
            assert( node != NULL);
            node->Index = m_VolumeCount;
            VolumeCount++;
            m_VolumeCount++;
            node->TotalSectors.QuadPart = mbrSector.dpt[i].total_sectors;
            node->StartSector.QuadPart = BaseSector + mbrSector.dpt[i].sectors_precding;
            node->Type = mbrSector.dpt[i].partition_type_indicator;
            sprintf_s( buffer,"Volume%d",m_VolumeCount );
            size_t len = strlen( buffer ) + 1;
            node->VolumeName = (LPSTR)malloc( len );
            assert( node->VolumeName != NULL);
            strcpy_s( node->VolumeName,len,buffer );
            
            if( node->Type == PARTITION_TYPE_NTFS 
                || node->Type == PARTITION_TYPE_NTFS_HIDDEN)
                node->TypeName = "NTFS";
            else if( node->Type == PARTITION_TYPE_FAT32
                || node->Type == PARTITION_TYPE_FAT32_HIDDEN )
                node->TypeName = "FAT32";
            else node->TypeName = "Unknown";

            //����������Ӧ���̷�
            node->VolumeLetter='-';
            for( CHAR letter ='C';letter <='Z';letter++)
            {
                if( m_tbl_VolumeOwnerDiskId[letter-'A'] == m_DiskId &&
                    m_tbl_VolumeOffset[letter-'A'] == node->StartSector.QuadPart*MBR_SECTOR_SIZE)
                {
                    node->VolumeLetter = letter;
                    break;
                }
            }

            InsertTailList( &m_VolumeListHead,&node->List );
            
        }
        else
        {
            //��֧�ֵľ����ͣ��ж��Ƿ�����չ������
            if( mbrSector.dpt[i].partition_type_indicator ==
                            PARTITION_TYPE_EXTENDED ||
               mbrSector.dpt[i].partition_type_indicator == 
                            PARTITION_TYPE_EXTENDED_SMALL)
            {
                VolumeCount += SearchMbrVolume( mbrSector.dpt[i].sectors_precding + BaseEbrSector,
                    BaseEbrSector>0?BaseEbrSector:mbrSector.dpt[i].sectors_precding);
            }
        }//end if

    }//end for

    return VolumeCount;
}

BOOL CVolumeList::IsVolumeTypeSupported(BYTE type)
/*++
�����������ж��Ƿ�Ϊ�����֧�ֵľ�����

��������������

����ֵ��֧�ַ���TRUE�����򷵻�FALSE
--*/
{
    if( type == PARTITION_TYPE_NTFS )
        return TRUE;
    else if( type == PARTITION_TYPE_NTFS_HIDDEN )
        return TRUE;
//    else if( type == PARTITION_TYPE_FAT32)
//        return TRUE;
//    else if( type == PARTITION_TYPE_FAT32_HIDDEN )
//        return TRUE;
    else
        return FALSE;
}