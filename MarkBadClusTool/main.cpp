// main.cpp : 定义控制台应用程序的入口点。
//
//e-mail:hackerlzc@126.com

#include "stdafx.h"
#include"layout_ntfs.h"
#include"layout_mbr.h"
#include"disk_list.h"
#include"volume_list.h"
#include"repair_controller.h"
#include"ntfs_controller.h"
#include"utils.h"
#include<devguid.h>
#include<setupapi.h>
#include<winioctl.h>
#pragma comment(lib,"setupapi.lib")
#include<crtdbg.h>

HANDLE hErrorFile = NULL;
FILE *hLogFile = NULL;

VOID ShowStateMessage( DWORD code,DWORD_PTR para1,DWORD_PTR para2 )
{
    FILE *fp = NULL;
    switch( code ){
        case MESSAGE_CODE_REPORTSTATE:
            printf( "\n%s\n",(LPSTR)para1 );
            break;
        case MESSAGE_CODE_REPORTERROR:
            printf( "\n%s\n",(LPSTR)para1 );
            break;
        case MESSAGE_CODE_PROGRESS:
            printf("\b\b\b%2d%%",para1*100 / para2 );
            break;
        case MESSAGE_CODE_NOTIFY:
            printf(".");
            break;
        case MESSAGE_CODE_FILENAME:
            if( hErrorFile != INVALID_HANDLE_VALUE )
            {
                DWORD bytesReturned = 0;
                WriteFile(hErrorFile,
                    (LPVOID)para1,
                    (DWORD)wcslen( (PWCHAR)para1)*sizeof(WCHAR),
                    &bytesReturned,
                    0);
            }
            break;
        default:
            break;
    }
}

/*
PS > fsutil fsinfo ntfsinfo M:
NTFS 卷序列号:             0x94928eb9928e9f7c
NTFS 版本:                 3.1
LFS 版本:                  2.0
扇区数量:                  0x00000000000063ff
簇总数:                  0x00000000000063ff
可用簇:                  0x0000000000005c35
保留总数:                  0x0000000000000581
每个扇区字节数:            4096
每个物理扇区字节数:        4096
每个簇字节数:            4096
每个 FileRecord 段字节数:  1024
每个 FileRecord 段簇数:  0
Mft 有效数据长度:          0x0000000000040000
Mft 起始 Lcn:              0x0000000000002155
Mft2 起始 Lcn:             0x0000000000000002
Mft 区域起始:              0x0000000000002180
Mft 区域结尾:              0x0000000000002de0
最大设备剪裁盘区计数:     4096
最大设备剪裁字节计数:       0xffffffff
最大卷剪裁盘区计数:     62
最大卷剪裁字节计数:       0x40000000
Resource Manager 标识符:     63AEA7B1-66E1-11EB-A40E-B88198466C3D
PS > fsutil fsinfo sectorInfo M:
LogicalBytesPerSector :                                 4096
PhysicalBytesPerSectorForAtomicity :                    4096
PhysicalBytesPerSectorForPerformance :                  4096
FileSystemEffectivePhysicalBytesPerSectorForAtomicity : 4096
设备校准 :                                        已校准(0x000)
设备上的分区校准:                                  已校准(0x000)
无搜寻惩罚
支持剪裁
不支持 DAX
已精简预配，SlabSizeInBytes:                8388608

*/

int GetAllVolume()
{
	CHAR  DeviceName[MAX_PATH] = "";
	DWORD  Error = ERROR_SUCCESS;
	HANDLE FindHandle = INVALID_HANDLE_VALUE;
	BOOL   Found = FALSE;
	size_t Index = 0;
	BOOL   Success = FALSE;
	CHAR  VolumeName[MAX_PATH] = "";
	int nVolumeCnt = 0;
	//
	//  Enumerate all volumes in the system.
	FindHandle = FindFirstVolume(VolumeName, ARRAYSIZE(VolumeName));

	if (FindHandle == INVALID_HANDLE_VALUE)
	{
		Error = GetLastError();
		return 0;
	}

	for (;;)
	{
		//
		//  Skip the \\?\ prefix and remove the trailing backslash.
		if (VolumeName[0] != L'\\' ||
			VolumeName[1] != L'\\' ||
			VolumeName[2] != L'?' ||
			VolumeName[3] != L'\\' ||
			VolumeName[Index] != L'\\')
		{
			Error = ERROR_BAD_PATHNAME;
			break;
		}
		nVolumeCnt++;
		//vstrVolume.push_back(VolumeName);

		//  Move on to the next volume.
		Success = FindNextVolume(FindHandle, VolumeName, ARRAYSIZE(VolumeName));

		if (!Success)
		{
			Error = GetLastError();

			if (Error != ERROR_NO_MORE_FILES)
			{
				break;
			}

			//
			//  Finished iterating
			//  through all the volumes.
			Error = ERROR_SUCCESS;
			break;
		}
	}

	FindVolumeClose(FindHandle);
	FindHandle = INVALID_HANDLE_VALUE;

	return nVolumeCnt;
}


void ShowLogo()
{
    printf("                     分区坏簇标记工具 V%d.%d\n",MAINVERSION,SUBVERSION );
    char message[]="================================================================================\n\
注意：1 本软件仍在测试阶断，表现可能不稳定，请不要对存放重要数据的硬盘进行操作。\n\
      2 目前仅支持NTFS类型的分区！\n\n\
      3 对于由本软件造成的任何损失，作者不负任何法律责任！\n\n\
      4 每次操作均会清除原来的坏扇区日志，清注意备份！\n\
      5 初步支持GPT磁盘，可能有问题-lcq。\n\
      6 GPT下所有可见分区均假设为NTFS，所以务必保证操作分区为NTFS。\n\
      7 需要有盘符才能操作，原因不知道\n\
      8 初步支持4KN硬盘，本程序仅适用于HDD，SSD有FTL本程序无用\n\
联系作者：hackerlzc@126.com\n\
看雪ID：  hackerlzc\n\
================================================================================\n";
    printf("%s",message );
}

int _tmain(int argc, _TCHAR* argv[])
{
    //显示Logo
    ShowLogo();
    //初始化出错文件日志

    hErrorFile = CreateFile(
        "error_file_list.log",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if( hErrorFile == INVALID_HANDLE_VALUE )
    {
        printf("open error_file_list.log failed!\n");
    }
    DWORD bytesReturned = 0;
    BYTE buffer[2]={0xff,0xfe};
    WriteFile( hErrorFile,
                buffer,
                2,
                &bytesReturned,
                NULL);
    
    //初始化软件日志文件
    //;
    if(fopen_s(&hLogFile, "MarkBadClusTool.log", "a+") != 0)
    {
        printf("open log file failed!\n");
    }

    int id = 0;
    HANDLE hVolume = 0;
    CVolumeList *pVolumeList  = NULL;
    CRepairController *pController = NULL;
    PDISK_DEVICE    p = NULL;
    CDiskList       diskList;
    p = diskList.GetFirstDisk();
    if( p == NULL)
    {
        printf("未检测到磁盘设备，程序即将退出！\n");
        goto lab_exit;
    }

    printf("搜索到的硬盘设备:\n");
    printf("%-20s%-30s%-20s\n","设备ID","设备名称","容量");
    while( p )
    {
        printf("%-20d%-30s%lld GB\n",p->index,p->name,p->sizeInSectors.QuadPart * p->BytesPerSector /1024 /1024 /1024);
        p = diskList.GetNextDisk( p );
    }
    printf("\n请输入设备ID:");
    scanf_s("%d",&id);
    diskList.GetDiskByIndex( id,&p );
	//if (p->BytesPerSector != 512)
	//{
	//	printf("仅支持512扇区硬盘!\r\n");
	//	goto lab_exit;
	//}
    pVolumeList = new CVolumeList(p);
    PVOLUME_NODE    p2 = pVolumeList->GetFirstVolume();
    if(p2 == NULL)
    {
        printf("未搜索到支持的分区，程序即将退出！\n");
        goto lab_exit;
    }

    printf("\n搜索到的分区列表：\n");
    while( p2 )
    {
        printf("%-15s%-15s%-15s%-15s%-15s\n","分区ID","起始扇区(LBA)","扇区数(LBA)","盘符","文件系统");
        printf("%-15d%-15lld%-15lld%-15c%s\n",p2->Index,
            p2->StartSector.QuadPart,
            p2->TotalSectors.QuadPart,
            p2->VolumeLetter,
            p2->TypeName);
        p2 = pVolumeList->GetNextVolume( p2 );
    }

    printf("\n请输入分区ID：");
    scanf_s("%d",&id);
    pVolumeList->GetVolumeByIndex(id,&p2);
    if( p2 == NULL)
    {
        printf("获取分区失败！程序即将退出！\n");
        goto lab_exit;
    }
    
    
    if( p2->VolumeLetter != '-')
    {
		CHAR path[] = "\\\\.\\C:";
        path[4]=p2->VolumeLetter;
        printf("正在打开分区:%s\n",path+4 );
        hVolume = CreateFile( path,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
        if( hVolume == INVALID_HANDLE_VALUE )
        {
                printf("分区打开失败,程序即将退出！\n");
                goto lab_exit;
        }
        else
        {
            DWORD bytesReturned = 0;
            printf("正在尝试卸载分区...\n");
            BOOL bOk = DeviceIoControl(
                  hVolume,
                  FSCTL_DISMOUNT_VOLUME,
                  NULL,
                  0,         
                  NULL,
                  0,
                  &bytesReturned,
                  NULL
                );
            if(bOk)
                printf("分区成功卸载\n");
            else
            {
                printf("分区卸载失败，程序即将退出！\n");
                goto lab_exit;
            }
        }
    }
	else
	{
		printf_s("无盘符分区\n");
		CHAR path2[] = TEXT("\\\\?\\Harddisk%dPartition%d");
		CHAR* path = (CHAR*)malloc(100);
		sprintf_s(path, 100, path2, (int)p->index, p2->Index);

		printf("正在打开分区:%s\n", path);
		GetAllVolume();




		hVolume = CreateFile(path,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (hVolume == INVALID_HANDLE_VALUE)
		{
			printf("分区打开失败,程序即将退出！\n");
			goto lab_exit;
		}
		else
		{
			DWORD bytesReturned = 0;
			printf("正在尝试卸载分区...\n");
			BOOL bOk = DeviceIoControl(
				hVolume,
				FSCTL_DISMOUNT_VOLUME,
				NULL,
				0,
				NULL,
				0,
				&bytesReturned,
				NULL
			);
			if (bOk)
				printf("分区成功卸载\n");
			else
			{
				printf("分区卸载失败，程序即将退出！\n");
				goto lab_exit;
			}
		}
	}
    if( p2->Type == PARTITION_TYPE_NTFS || p2->Type == PARTITION_TYPE_NTFS_HIDDEN )
        pController = new CNtfsController( (LPSTR)p->path, p2->StartSector.QuadPart, p2->TotalSectors.QuadPart, p->BytesPerSector);
    else
    {
        printf("不支持此分区类型,程序即将退出！\n");
        goto lab_exit;
    }
    pController->RegisterMessageCallBack( (MESSAGE_CALLBACK_FUNC)ShowStateMessage );

    printf("当前文件系统已经标记的坏扇区列表:\n");
    printf("%-20s%-20s%-20s\n","起始扇区(LBA)","起始扇区(LCN)","扇区数");
    for( PBLOCK_DESCRIPTOR p = pController->GetFirstBadBlock();
        p != NULL;
        p = pController->GetNextBadBlock( p ))
    {
        printf("%-20lld%-20lld%-20lld\n", 
			p->StartSector.QuadPart + p2->StartSector.QuadPart 
			,p->StartSector.QuadPart
			,p->TotalSectors.QuadPart );
    }

    if(pController->ProbeForRepair())
    {
        printf("\n1=手工输入坏扇区数据 2=从文件读入 0=退出\n");
        scanf_s("%d",&id );
        getchar();
        if( id == 2 )
        {
            char filename[256] = {0};
            printf("请输入配置文件名:\n");

            gets_s( filename,256);
            FILE *fp = NULL;
            fopen_s(&fp,filename,"r");
            if( fp == NULL)
            {
                printf("配置文件打开失败，程序即将退出！\n");
                goto lab_exit;
            }

            pController->PrepareUpdateBadBlockList();
            LONGLONG start=-1,len =1000;
			//,p->sectorsPerCylinder.QuadPart/2
            printf("请输入坏扇区扩展量(这里为坏扇区前后扩展扇区大小,最小扇区单位为一个逻辑簇，比如4K簇512E的硬盘输入为8的整数)："); 
            scanf_s("%lld",&len );
            if( len <= 0 || len >= p2->TotalSectors.QuadPart/2 )
            {
                printf("输入值不合适，程序即将退出！\n");
                goto lab_exit;
            }
            fscanf_s(fp,"%lld",&start);
            while( !feof( fp ) && start != -1 )
            {
                LONGLONG left = 0,right = 0,tmp=0;
                if( start < p2->StartSector.QuadPart || start >=p2->StartSector.QuadPart + p2->TotalSectors.QuadPart)
                    continue;
                start -= p2->StartSector.QuadPart;
                left = max(start-len,36*8);
                right = min( start+len,p2->StartSector.QuadPart+p2->TotalSectors.QuadPart)-1;
                if( left>right)left=right;        
                pController->AddBadBlock( left,right-left+1 );
                fscanf_s(fp,"%lld",&start);
            }
            fclose( fp );
            printf("配置文件读入完成，即将进行更新！\n");
            system("PAUSE");
            pController->StartRepairProgress();
            printf("建议查看错误日志文件 error_file_list.log中是否有您感兴趣的文件，如果有，则先手工备份它们，然后再运行Chkdsk修复分区错误！\n");
        }
        else if(id== 1 )
        {
            
            pController->PrepareUpdateBadBlockList();
            LONGLONG start=-1,len =1000;
            printf("请输入坏扇区扩展量(这里为坏扇区前后扩展扇区大小,最小扇区单位为一个逻辑簇，比如4K簇512E的硬盘输入为8的整数)：");
            scanf_s("%lld",&len );
            if( len <= 0 || len >= p2->TotalSectors.QuadPart/2 )
            {
                printf("输入值不合适，程序即将退出！\n");
                goto lab_exit;
            }
			printf("请输入坏扇区表（-1表示结束,地址为磁盘LBA地址):\n");
			printf("选择的分区LBA地址范围为%lld-%lld\n",
				p2->StartSector.QuadPart, p2->StartSector.QuadPart + p2->TotalSectors.QuadPart);
            do
            {
				scanf_s("%lld", &start);
                LONGLONG left = 0,right = 0,tmp=0;
				if (start < p2->StartSector.QuadPart || start >= p2->StartSector.QuadPart + p2->TotalSectors.QuadPart)
				{
					printf("不合法地址跳过: %lld\n", start);
					continue;
				}
                    
                start -= p2->StartSector.QuadPart;
                left = max(start-len,36*8);
                right = min( start+len,p2->StartSector.QuadPart+p2->TotalSectors.QuadPart)-1;
                if( left>right)left=right;        
                pController->AddBadBlock( left,right-left+1 );
                //scanf_s("%lld",&start);
			} while (start != -1);
            printf("数据读入完成，即将进行更新！\n");
            system("PAUSE");
            pController->StartRepairProgress();
            printf("建议查看错误文件日志 error_file_list.log中是否有您感兴趣的文件，如果有，则先手工备份它们，然后再运行Chkdsk修复分区错误！\n");

        }
    }

lab_exit:
    if( pVolumeList != NULL)
        delete pVolumeList;
    if( pController != NULL)
        delete pController;
    if( hErrorFile != INVALID_HANDLE_VALUE )
        CloseHandle( hErrorFile );
    if( hLogFile != NULL )
        fclose( hLogFile );
    if( hVolume != INVALID_HANDLE_VALUE )
        CloseHandle( hVolume );
    DeleteFile("MarkBadClusTool.log");

    system("PAUSE");

#if MEM_LEAK_CHECK
    int tmpDbgFlag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
    tmpDbgFlag |= _CRTDBG_LEAK_CHECK_DF;
    _CrtSetDbgFlag( tmpDbgFlag );
#endif
	return 0;
}

