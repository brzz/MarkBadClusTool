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

//lcq 2020-02-29
#include "GPT_GUID.h"
//��ʵ��


CVolumeList::CVolumeList(PDISK_DEVICE pdisk)
/*++
�������������캯��

���� 
    DiskPath:�����豸·��

����ֵ����
--*/
:m_VolumeCount(0),
m_pdisk(pdisk),
m_DiskId(pdisk->index)
{
	//LPSTR DiskPath,DWORD DiskId
	//(LPSTR)p->path, p->index
	
	LPSTR DiskPath = (LPSTR)pdisk->path;
    assert( DiskPath != NULL);
	
    m_hDisk = CreateFile( DiskPath,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if( m_hDisk == INVALID_HANDLE_VALUE )
        DbgPrint("open disk device failed!");

    RtlZeroMemory( m_tbl_VolumeOffset,sizeof(m_tbl_VolumeOffset));
    memset( &m_tbl_VolumeOwnerDiskId,0xcc,sizeof(m_tbl_VolumeOwnerDiskId));
    CHAR volumePath[]="\\\\.\\C:";
    DWORD bytesReturned = 0;
    for( CHAR letter = 'A';letter <='Z';letter++)
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
	//lcq 2020-0229 bug unfix �����ʩ
	//���BUG��ʱ���޸�
	if (m_VolumeCount == 0) return;

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
    m_VolumeCount = (WORD)SearchMbrVolume(this->m_pdisk, 0 );

}

DWORD CVolumeList::SearchGPTVolume(PDISK_DEVICE pdisk, DWORD BaseSector, MBR_SECTOR  mbrSector)
{
	//LCQ 2020-02-29 GUID
	BOOL    bOk = FALSE;
	gpt_header gptheader = { 0 }; //GPTͷ
								 

	DbgPrint("GPT disk dected!");
	printf("��⵽���ִ�GPT���̣�\n");

	//GPTһ����ʼ��1�������ҵ����λ��
	bOk = ReadSector(m_hDisk, &gptheader, pdisk->BytesPerSector, mbrSector.dpt[0].sectors_precding, 0, pdisk->BytesPerSector);
	if (!bOk)
	{
		DbgPrint("Read sector failed!");
		return 0;
	}
	show_gpt_header(&gptheader);
	printf("\n\n���Ӳ����Ч��СΪ %lf GB\n", (double)uint8to64(gptheader.backup_lba) * pdisk->BytesPerSector / 1024 / 1024 / 1024);

	printf("\n\n-------------��ȡ��������:-------------\n\n");
	ULONGLONG baseaddr = (ULONGLONG)uint8to64(gptheader.pation_table_first);//GPT��������ʼλ��


	{
		//׼���������Ϣ
		int entrynum = 0;
		DWORD dwCB;
		LARGE_INTEGER offset;
		partition_table the_partition_tables[4];
		ULONGLONG nextaddr = ((ULONGLONG)0 + (ULONGLONG)baseaddr) *(ULONGLONG)512;
		offset.QuadPart = nextaddr;//�ҵ���һ��Ҫ��ȡ�ĵ�ַ
		SetFilePointer(m_hDisk, offset.LowPart, &offset.HighPart, FILE_BEGIN);//����ƫ��׼����ȡ
																			  //ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL);
		if (!ReadFile(m_hDisk, &the_partition_tables, 512, &dwCB, NULL))
		{
			printf("��ȡ����");
			CloseHandle(m_hDisk);
			system("pause");
			return 0;
		}
		int endflag = 1;
		int j = 0;//���j=4�����¶�����Ϊĳ�����ƣ�һ�α����512�ֽ�������
		while (endflag > 0) {
			//printf("\n��%d��������:\n", ++entrynum);
			if (j == 4)
			{
				nextaddr = nextaddr + (ULONGLONG)512;
				offset.QuadPart = nextaddr;//�ҵ���һ��Ҫ��ȡ�ĵ�ַ
				SetFilePointer(m_hDisk, offset.LowPart, &offset.HighPart, FILE_BEGIN);//����ƫ��׼����ȡ
																					  //if (GetLastError())
																					  //{
																					  //	return 0;
																					  //}
				memset(&the_partition_tables, 0, 512);
				ReadFile(m_hDisk, &the_partition_tables, 512, &dwCB, NULL);
				j = 0;
			}

			//ѭ���������о�������ʽ��
			//ÿһ������������128�ֽڣ�����һ������512�ֽ�ֻ�ܴ�4��
			//endflag = show_partition_table(&the_partition_tables[j]);
			endflag = uint8to64(the_partition_tables[j].pation_start) == 0ll ? 0 : 1;

			//�������ء�ϵͳ���������������������
			if(uint8to64(the_partition_tables[j].pation_attr) == 0ll && endflag)
			{
				//�½����ʶ
				//֧�ֵľ�����
				PVOLUME_NODE    node = { 0 };
				CHAR            buffer[256];

				node = (PVOLUME_NODE)malloc(sizeof(VOLUME_NODE));
				assert(node != NULL);
				node->Index = m_VolumeCount;
				m_VolumeCount++;
				//�����
				printf("\n�÷�����ʼ������Ϊ%I64X\n", uint8to64(the_partition_tables[j].pation_start));

				node->StartSector.QuadPart = uint8to64(the_partition_tables[j].pation_start);
				//һ��Ҫ+1����������Բ���
				node->TotalSectors.QuadPart = uint8to64(the_partition_tables[j].pation_end) - uint8to64(the_partition_tables[j].pation_start) + 1;

				sprintf_s(buffer, "Volume%d", m_VolumeCount);
				size_t len = strlen(buffer) + 1;
				node->VolumeName = (LPSTR)malloc(len);
				assert(node->VolumeName != NULL);
				strcpy_s(node->VolumeName, len, buffer);

				//BUG: defualt all partion is NTFS
				node->Type = PARTITION_TYPE_NTFS;

				node->TypeName = "NTFS";
				//����������Ӧ���̷�
				node->VolumeLetter = '-';
				for (CHAR letter = 'C'; letter <= 'Z'; letter++)
				{
					if (m_tbl_VolumeOwnerDiskId[letter - 'A'] == m_DiskId &&
						m_tbl_VolumeOffset[letter - 'A'] == node->StartSector.QuadPart*MBR_SECTOR_SIZE)
					{
						node->VolumeLetter = letter;
						break;
					}
				}



				//����õľ��ʶ���뵽���б�
				InsertTailList(&m_VolumeListHead, &node->List);
			}


			j++;
		}
		return m_VolumeCount-1;


	}


	////����������Ӧ���̷�
	//node->VolumeLetter = '-';
	//for (CHAR letter = 'C'; letter <= 'Z'; letter++)
	//{
	//	if (m_tbl_VolumeOwnerDiskId[letter - 'A'] == m_DiskId &&
	//		m_tbl_VolumeOffset[letter - 'A'] == node->StartSector.QuadPart*MBR_SECTOR_SIZE)
	//	{
	//		node->VolumeLetter = letter;
	//		break;
	//	}
	//}

}


DWORD CVolumeList::SearchMbrVolume(PDISK_DEVICE pdisk, DWORD BaseSector, DWORD BaseEbrSector /*= 0*/)
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

	if (pdisk->BytesPerSector > sizeof(MBR_SECTOR))
	{
		DbgPrint("Disk Sector too large!");
		return 0;
	}
	
    bOk = ReadSector( m_hDisk, &mbrSector, pdisk->BytesPerSector, BaseSector, 0, pdisk->BytesPerSector);
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

	//LCQ 2020-02-29 GUID
	if (mbrSector.dpt[0].partition_type_indicator == Not_MBR_isGUID)
	{
		//Is not MBR DISK
		SearchGPTVolume(pdisk, 0, mbrSector);
	}
	else
	{
		DbgPrint("Legacy MBR disk dected!");
		printf("��⵽��Զ��MBR���̣�\n");
		for (i = 0; i < 4; i++)
		{
			if (mbrSector.dpt[i].partition_type_indicator == PARTITION_TYPE_ILLEGAL)
				continue;

			if (IsVolumeTypeSupported(mbrSector.dpt[i].partition_type_indicator))
			{
				//֧�ֵľ�����
				PVOLUME_NODE    node = { 0 };
				CHAR            buffer[256];

				node = (PVOLUME_NODE)malloc(sizeof(VOLUME_NODE));
				assert(node != NULL);
				node->Index = m_VolumeCount;
				VolumeCount++;
				m_VolumeCount++;
				node->TotalSectors.QuadPart = mbrSector.dpt[i].total_sectors;
				node->StartSector.QuadPart = BaseSector + mbrSector.dpt[i].sectors_precding;
				node->Type = mbrSector.dpt[i].partition_type_indicator;
				sprintf_s(buffer, "Volume%d", m_VolumeCount);
				size_t len = strlen(buffer) + 1;
				node->VolumeName = (LPSTR)malloc(len);
				assert(node->VolumeName != NULL);
				strcpy_s(node->VolumeName, len, buffer);

				if (node->Type == PARTITION_TYPE_NTFS
					|| node->Type == PARTITION_TYPE_NTFS_HIDDEN)
					node->TypeName = "NTFS";
				else if (node->Type == PARTITION_TYPE_FAT32
					|| node->Type == PARTITION_TYPE_FAT32_HIDDEN)
					node->TypeName = "FAT32";
				else node->TypeName = "Unknown";

				//����������Ӧ���̷�
				node->VolumeLetter = '-';
				for (CHAR letter = 'A'; letter <= 'Z'; letter++)
				{
					if (m_tbl_VolumeOwnerDiskId[letter - 'A'] == m_DiskId &&
						m_tbl_VolumeOffset[letter - 'A'] == node->StartSector.QuadPart*MBR_SECTOR_SIZE)
					{
						node->VolumeLetter = letter;
						break;
					}
				}

				InsertTailList(&m_VolumeListHead, &node->List);

			}
			else
			{
				//��֧�ֵľ����ͣ��ж��Ƿ�����չ������
				if (mbrSector.dpt[i].partition_type_indicator ==
					PARTITION_TYPE_EXTENDED ||
					mbrSector.dpt[i].partition_type_indicator ==
					PARTITION_TYPE_EXTENDED_SMALL)
				{
					VolumeCount += SearchMbrVolume(pdisk, mbrSector.dpt[i].sectors_precding + BaseEbrSector,
						BaseEbrSector > 0 ? BaseEbrSector : mbrSector.dpt[i].sectors_precding);
				}
			}//end if

		}//end for
	}

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