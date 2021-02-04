// main.cpp : �������̨Ӧ�ó������ڵ㡣
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

void ShowLogo()
{
    printf("                     �������ر�ǹ��� V%d.%d\n",MAINVERSION,SUBVERSION );
    char message[]="================================================================================\n\
ע�⣺1 ��������ڲ��Խ׶ϣ����ֿ��ܲ��ȶ����벻Ҫ�Դ����Ҫ���ݵ�Ӳ�̽��в�����\n\
      2 Ŀǰ��֧��NTFS���͵ķ�����\n\n\
      3 �����ɱ������ɵ��κ���ʧ�����߲����κη������Σ�\n\n\
      4 ÿ�β����������ԭ���Ļ�������־����ע�ⱸ�ݣ�\n\
      5 ����֧��GPT���̣�����������-lcq��\n\
      6 GPT�����пɼ�����������ΪNTFS��������ر�֤��������ΪNTFS��\n\
��ϵ���ߣ�hackerlzc@126.com\n\
��ѩID��  hackerlzc\n\
================================================================================\n";
    printf("%s",message );
}

int _tmain(int argc, _TCHAR* argv[])
{
    //��ʾLogo
    ShowLogo();
    //��ʼ�������ļ���־

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
    
    //��ʼ�������־�ļ�
    fopen_s( &hLogFile,"MarkBadClusTool.log","w");
    if( hLogFile == NULL )
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
        printf("δ��⵽�����豸�����򼴽��˳���\n");
        goto lab_exit;
    }

    printf("��������Ӳ���豸:\n");
    printf("%-20s%-30s%-20s\n","�豸ID","�豸����","����");
    while( p )
    {
        printf("%-20d%-30s%lld GB\n",p->index,p->name,p->sizeInSectors.QuadPart * p->BytesPerSector /1024 /1024 /1024);
        p = diskList.GetNextDisk( p );
    }
    printf("\n�������豸ID:");
    scanf_s("%d",&id);
    diskList.GetDiskByIndex( id,&p );
	if (p->BytesPerSector != 512)
	{
		printf("��֧��512����Ӳ��!\r\n");
		goto lab_exit;
	}
    pVolumeList = new CVolumeList( (LPSTR)p->path,p->index );
    PVOLUME_NODE    p2 = pVolumeList->GetFirstVolume();
    if(p2 == NULL)
    {
        printf("δ������֧�ֵķ��������򼴽��˳���\n");
        goto lab_exit;
    }

    printf("\n�������ķ����б�\n");
    while( p2 )
    {
        printf("%-15s%-15s%-15s%-15s%-15s\n","����ID","��ʼ����","������","�̷�","�ļ�ϵͳ");
        printf("%-15d%-15lld%-15lld%-15c%s\n",p2->Index,
            p2->StartSector.QuadPart,
            p2->TotalSectors.QuadPart,
            p2->VolumeLetter,
            p2->TypeName);
        p2 = pVolumeList->GetNextVolume( p2 );
    }

    printf("\n���������ID��");
    scanf_s("%d",&id);
    pVolumeList->GetVolumeByIndex(id,&p2);
    if( p2 == NULL)
    {
        printf("��ȡ����ʧ�ܣ����򼴽��˳���\n");
        goto lab_exit;
    }
    
    CHAR path[]="\\\\.\\C:";
    if( p2->VolumeLetter != '-')
    {
        path[4]=p2->VolumeLetter;
        printf("���ڴ򿪷���:%s\n",path+4 );
        hVolume = CreateFile( path,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
        if( hVolume == INVALID_HANDLE_VALUE )
        {
                printf("������ʧ��,���򼴽��˳���\n");
                goto lab_exit;
        }
        else
        {
            DWORD bytesReturned = 0;
            printf("���ڳ���ж�ط���...\n");
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
                printf("�����ɹ�ж��\n");
            else
            {
                printf("����ж��ʧ�ܣ����򼴽��˳���\n");
                goto lab_exit;
            }
        }
    }
    if( p2->Type == PARTITION_TYPE_NTFS || p2->Type == PARTITION_TYPE_NTFS_HIDDEN )
        pController = new CNtfsController( (LPSTR)p->path,p2->StartSector.QuadPart,p2->TotalSectors.QuadPart);
    else
    {
        printf("��֧�ִ˷�������,���򼴽��˳���\n");
        goto lab_exit;
    }
    pController->RegisterMessageCallBack( (MESSAGE_CALLBACK_FUNC)ShowStateMessage );

    printf("��ǰ�ļ�ϵͳ�Ѿ���ǵĻ������б�:\n");
    printf("%-20s%-20s\n","��ʼ����","������");
    for( PBLOCK_DESCRIPTOR p = pController->GetFirstBadBlock();
        p != NULL;
        p = pController->GetNextBadBlock( p ))
    {
        printf("%-20lld%-20lld\n",p->StartSector.QuadPart,p->TotalSectors.QuadPart );
    }

    if(pController->ProbeForRepair())
    {
        printf("\n1=�ֹ����뻵�������� 2=���ļ����� 0=�˳�\n");
        scanf_s("%d",&id );
        getchar();
        if( id == 2 )
        {
            char filename[256] = {0};
            printf("�����������ļ���:\n");

            gets_s( filename,256);
            FILE *fp = NULL;
            fopen_s(&fp,filename,"r");
            if( fp == NULL)
            {
                printf("�����ļ���ʧ�ܣ����򼴽��˳���\n");
                goto lab_exit;
            }

            pController->PrepareUpdateBadBlockList();
            LONGLONG start=-1,len =1000;
            printf("�����뻵������չ��(����ֵ��%lld,����Ϊ������ǰ����չ���ݣ���С��λΪһ����/512��С)��",p->sectorsPerCylinder.QuadPart/2);
            scanf_s("%lld",&len );
            if( len <= 0 || len >= p2->TotalSectors.QuadPart/2 )
            {
                printf("����ֵ�����ʣ����򼴽��˳���\n");
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
            printf("�����ļ�������ɣ��������и��£�\n");
            system("PAUSE");
            pController->StartRepairProgress();
            printf("����鿴������־�ļ� error_file_list.log���Ƿ���������Ȥ���ļ�������У������ֹ��������ǣ�Ȼ��������Chkdsk�޸���������\n");
        }
        else if(id== 1 )
        {
            
            pController->PrepareUpdateBadBlockList();
            LONGLONG start=-1,len =1000;
            printf("�����뻵������չ��(����ֵ��%lld,����Ϊ������ǰ����չ���ݣ���С��λΪһ����/512��С)��",p->sectorsPerCylinder.QuadPart/2);
            scanf_s("%lld",&len );
            if( len <= 0 || len >= p2->TotalSectors.QuadPart/2 )
            {
                printf("����ֵ�����ʣ����򼴽��˳���\n");
                goto lab_exit;
            }
            printf("�����뻵������-1��ʾ����,��ַΪ����LBA��ַ):\n");
            scanf_s("%lld",&start);
            while( start != -1 )
            {
                LONGLONG left = 0,right = 0,tmp=0;
                if( start < p2->StartSector.QuadPart || start >=p2->StartSector.QuadPart + p2->TotalSectors.QuadPart)
                    continue;
                start -= p2->StartSector.QuadPart;
                left = max(start-len,36*8);
                right = min( start+len,p2->StartSector.QuadPart+p2->TotalSectors.QuadPart)-1;
                if( left>right)left=right;        
                pController->AddBadBlock( left,right-left+1 );
                scanf_s("%lld",&start);
            }
            printf("���ݶ�����ɣ��������и��£�\n");
            system("PAUSE");
            pController->StartRepairProgress();
            printf("����鿴�����ļ���־ error_file_list.log���Ƿ���������Ȥ���ļ�������У������ֹ��������ǣ�Ȼ��������Chkdsk�޸���������\n");

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

