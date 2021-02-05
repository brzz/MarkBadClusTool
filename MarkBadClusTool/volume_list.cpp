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
//类实现


CVolumeList::CVolumeList(PDISK_DEVICE pdisk)
/*++
功能描述：构造函数

参数 
    DiskPath:磁盘设备路径

返回值：无
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
功能描述：柝构函数，释放本类动态申请的内存资源

参数：无

返回值：无

--*/
{
    ReleaseAllResources();
}

WORD CVolumeList::GetVolumeCount()
/*++
功能描述：磁盘中卷数量

参数：无

返回值：磁盘中卷数量

--*/
{
    return m_VolumeCount;
}

BOOL CVolumeList::GetVolumeByIndex(WORD index, PVOLUME_NODE *result)
/*++
功能描述：通过卷序数搜索相应卷信息结点

参数
    index:卷序号
    result:调用者提供的指针空间，用以存放结果卷信息结点的指针

返回值：
    TRUE:搜索成功，*result指向正确的结点
    FALSE:搜索失败，*result置为NULL
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
功能描述：返回第一个卷信息结点

参数：无

返回值：成功则返回第一个卷信息结点指针
        失败返回NULL
--*/
{
    if( IsListEmpty( &m_VolumeListHead ))
        return NULL;

    return (PVOLUME_NODE)CONTAINING_RECORD( m_VolumeListHead.Flink,
        VOLUME_NODE,List );
}

PVOLUME_NODE CVolumeList::GetNextVolume(PVOLUME_NODE curVolume)
/*++
功能描述：通过当前已有卷信息结点指针，返回下一个卷信息结点指针

参数    curVolume:当前卷信息结点指针

返回值：下一个卷信息结点指针，失败返回NULL（表示已经到达结尾）

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
功能描述：更新卷结点信息

参数：无

返回值：无

--*/
{
    ReleaseAllResources();
    InitVolumeList();
}

VOID CVolumeList::ReleaseAllResources()
/*++
功能描述：释放类中所有动态申请的内存资源

参数：无

返回值：无

--*/
{
    PLIST_ENTRY entry = NULL;
	//lcq 2020-0229 bug unfix 缓解措施
	//这个BUG暂时不修复
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
功能描述：初始化卷列表

参数：无

返回值：无

--*/
{
    InitializeListHead( &m_VolumeListHead );
    m_VolumeCount = (WORD)SearchMbrVolume(this->m_pdisk, 0 );

}

DWORD CVolumeList::SearchGPTVolume(PDISK_DEVICE pdisk, DWORD BaseSector, MBR_SECTOR  mbrSector)
{
	//LCQ 2020-02-29 GUID
	BOOL    bOk = FALSE;
	gpt_header gptheader = { 0 }; //GPT头
								 

	DbgPrint("GPT disk dected!");
	printf("检测到是现代GPT磁盘！\n");

	//GPT一般起始于1扇区，找到相对位置
	bOk = ReadSector(m_hDisk, &gptheader, pdisk->BytesPerSector, mbrSector.dpt[0].sectors_precding, 0, pdisk->BytesPerSector);
	if (!bOk)
	{
		DbgPrint("Read sector failed!");
		return 0;
	}
	show_gpt_header(&gptheader);
	printf("\n\n这块硬盘有效大小为 %lf GB\n", (double)uint8to64(gptheader.backup_lba) * pdisk->BytesPerSector / 1024 / 1024 / 1024);

	printf("\n\n-------------读取分区表项:-------------\n\n");
	ULONGLONG baseaddr = (ULONGLONG)uint8to64(gptheader.pation_table_first);//GPT分区表起始位置


	{
		//准备处理卷信息
		int entrynum = 0;
		DWORD dwCB;
		LARGE_INTEGER offset;
		partition_table the_partition_tables[4];
		ULONGLONG nextaddr = ((ULONGLONG)0 + (ULONGLONG)baseaddr) *(ULONGLONG)512;
		offset.QuadPart = nextaddr;//找到下一个要读取的地址
		SetFilePointer(m_hDisk, offset.LowPart, &offset.HighPart, FILE_BEGIN);//设置偏移准备读取
																			  //ReadFile(hDevice, &the_partition_tables, 512, &dwCB, NULL);
		if (!ReadFile(m_hDisk, &the_partition_tables, 512, &dwCB, NULL))
		{
			printf("读取错误");
			CloseHandle(m_hDisk);
			system("pause");
			return 0;
		}
		int endflag = 1;
		int j = 0;//如果j=4，重新读，因为某种限制，一次必须读512字节整数倍
		while (endflag > 0) {
			//printf("\n第%d个分区表:\n", ++entrynum);
			if (j == 4)
			{
				nextaddr = nextaddr + (ULONGLONG)512;
				offset.QuadPart = nextaddr;//找到下一个要读取的地址
				SetFilePointer(m_hDisk, offset.LowPart, &offset.HighPart, FILE_BEGIN);//设置偏移准备读取
																					  //if (GetLastError())
																					  //{
																					  //	return 0;
																					  //}
				memset(&the_partition_tables, 0, 512);
				ReadFile(m_hDisk, &the_partition_tables, 512, &dwCB, NULL);
				j = 0;
			}

			//循环遍历所有卷（链表形式）
			//每一个分区表中有128字节，所以一个扇区512字节只能存4个
			//endflag = show_partition_table(&the_partition_tables[j]);
			endflag = uint8to64(the_partition_tables[j].pation_start) == 0ll ? 0 : 1;

			//不管隐藏、系统、启动、保留等特殊分区
			if(uint8to64(the_partition_tables[j].pation_attr) == 0ll && endflag)
			{
				//新建卷标识
				//支持的卷类型
				PVOLUME_NODE    node = { 0 };
				CHAR            buffer[256];

				node = (PVOLUME_NODE)malloc(sizeof(VOLUME_NODE));
				assert(node != NULL);
				node->Index = m_VolumeCount;
				m_VolumeCount++;
				//处理卷
				printf("\n该分区起始扇区号为%I64X\n", uint8to64(the_partition_tables[j].pation_start));

				node->StartSector.QuadPart = uint8to64(the_partition_tables[j].pation_start);
				//一定要+1，否则分区对不上
				node->TotalSectors.QuadPart = uint8to64(the_partition_tables[j].pation_end) - uint8to64(the_partition_tables[j].pation_start) + 1;

				sprintf_s(buffer, "Volume%d", m_VolumeCount);
				size_t len = strlen(buffer) + 1;
				node->VolumeName = (LPSTR)malloc(len);
				assert(node->VolumeName != NULL);
				strcpy_s(node->VolumeName, len, buffer);

				//BUG: defualt all partion is NTFS
				node->Type = PARTITION_TYPE_NTFS;

				node->TypeName = "NTFS";
				//搜索分区对应的盘符
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



				//处理好的卷标识加入到主列表
				InsertTailList(&m_VolumeListHead, &node->List);
			}


			j++;
		}
		return m_VolumeCount-1;


	}


	////搜索分区对应的盘符
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
功能描述：搜索磁盘中的卷，建立卷信息链表

参数：
    BaseSector:MBR 或者 EBR所在的绝对扇区号
    BaseEbrSector: 基本EBR所在扇区绝对号

返回值：搜索到的卷数量

注意：*此函数设计为递归调用函数。
      
      *EBR中描述的逻辑驱动器都是以其所在的EBR的扇区号作为基址的。
       EBR中所描述的DOS扩展分区是以基本EBR的扇区号作为基址的
      *基本EBR是指MBR中描述的EBR。
--*/
{
    DWORD   i = 0;
    BOOL    bOk = FALSE;
    MBR_SECTOR  mbrSector = {0};    //同时作为EBR使用  
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
		printf("检测到是远古MBR磁盘！\n");
		for (i = 0; i < 4; i++)
		{
			if (mbrSector.dpt[i].partition_type_indicator == PARTITION_TYPE_ILLEGAL)
				continue;

			if (IsVolumeTypeSupported(mbrSector.dpt[i].partition_type_indicator))
			{
				//支持的卷类型
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

				//搜索分区对应的盘符
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
				//非支持的卷类型（判断是否是扩展分区）
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
功能描述：判断是否为本软件支持的卷类型

参数：卷类型码

返回值：支持返回TRUE，否则返回FALSE
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