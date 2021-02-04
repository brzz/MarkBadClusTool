//disk_list.cpp for class CDiskList
//author:lzc
//date:2012/11/07
//e-mail:hackerlzc@126.com

#include"stdafx.h"
#include<windows.h>
#include<setupapi.h>
#pragma comment(lib,"setupapi.lib")
#include<guiddef.h>
#include<winioctl.h>
#include"disk_list.h"

//��ʵ��

CDiskList::CDiskList()
/*++
�������������캯��

��������

����ֵ����
--*/
{
    InitDiskList();
}

VOID CDiskList::InitDiskList()
/*++
��������������ϵͳ�еĴ����豸�����������豸����

��������

����ֵ����
--*/
{
    PDISK_DEVICE pDiskDevice = NULL;
    DWORD       cbData = 0,retBytes = 0;
    LSTATUS     status = 0;
    int         i = 0;
    GUID        dev_interface_guid = GUID_DEVINTERFACE_DISK;
    HDEVINFO    hDevInfo = NULL;

    InitializeListHead( &m_DiskListHead );
    m_DiskCount = 0;
    
    hDevInfo = SetupDiGetClassDevs(&dev_interface_guid,NULL,NULL, DIGCF_PRESENT |DIGCF_DEVICEINTERFACE);
    if( hDevInfo == INVALID_HANDLE_VALUE )
    {
        DbgPrint("get classdevs failed!");
        goto exit;
    }

    for( i = 0;TRUE;i++)
    {
        BOOL    bOk = FALSE;
        SP_DEVICE_INTERFACE_DATA  devInterfaceData;
        devInterfaceData.cbSize = sizeof( SP_DEVICE_INTERFACE_DATA );
        bOk = SetupDiEnumDeviceInterfaces(hDevInfo,NULL,&dev_interface_guid,i,&devInterfaceData);
        if( bOk == FALSE )
        {
            char message[256];
            sprintf_s(message,"i = %d,error_code = %d",i,GetLastError());
            DbgPrint( message );
            //ShowError();
            break;
        }

        //���������豸��Ϣ��㣬���򵥳�ʼ��
        pDiskDevice = (PDISK_DEVICE)malloc( sizeof(DISK_DEVICE));
        //pDiskDevice->index = i;
        pDiskDevice->reserved = 0;

        //��ȡ�����豸���·��
        bOk = SetupDiGetDeviceInterfaceDetail( hDevInfo,
                    &devInterfaceData,NULL,0,&retBytes,NULL);
        if( !bOk && GetLastError() != ERROR_INSUFFICIENT_BUFFER )
        {
            //��ȡ·��ʧ��
            pDiskDevice->path = NULL;
        }
        else
        {
            //��ȡ·���ɹ�

            char message[256];
            SP_DEVICE_INTERFACE_DETAIL_DATA *pInterfaceDetailData
                = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc( retBytes );
            pInterfaceDetailData->cbSize = sizeof( SP_DEVICE_INTERFACE_DETAIL_DATA);
            SP_DEVINFO_DATA  devInfoData;
            devInfoData.cbSize = sizeof( SP_DEVINFO_DATA );

            bOk = SetupDiGetDeviceInterfaceDetail( hDevInfo,
                    &devInterfaceData,pInterfaceDetailData,retBytes,NULL,&devInfoData);
            assert( bOk );

            sprintf_s(message,"i = %d,path = %s",i,pInterfaceDetailData->DevicePath);
            DbgPrint(message);

            //���豸����з���洢·���ִ��Ŀռ�
            pDiskDevice->path = (BYTE *)malloc( 
                        retBytes - FIELD_OFFSET(SP_DEVICE_INTERFACE_DETAIL_DATA, DevicePath) );
            assert( pDiskDevice->path != NULL );

            //�豸·�����Ƶ���Ϣ���
            memcpy_s( pDiskDevice->path,
                retBytes - FIELD_OFFSET(SP_DEVICE_INTERFACE_DETAIL_DATA, DevicePath),
                pInterfaceDetailData->DevicePath,
                retBytes - FIELD_OFFSET(SP_DEVICE_INTERFACE_DETAIL_DATA, DevicePath));
            free( pInterfaceDetailData );
            pInterfaceDetailData = NULL;

            //��ȡ�豸�Ѻ�����
            retBytes = 0;
            bOk = SetupDiGetDeviceRegistryProperty( hDevInfo,
                                &devInfoData,
                                SPDRP_FRIENDLYNAME ,
                                NULL,
                                NULL,
                                0,
                                &retBytes);
            assert( bOk == FALSE );
            if( retBytes == 0 )
            {
                bOk = SetupDiGetDeviceRegistryProperty( hDevInfo,
                                &devInfoData,
                                SPDRP_DEVICEDESC,
                                NULL,
                                NULL,
                                0,
                                &retBytes);
                assert( bOk == FALSE && retBytes != 0 );
            }
            pDiskDevice->name = (BYTE *)malloc( retBytes );
            assert( pDiskDevice->name != NULL );
            bOk = SetupDiGetDeviceRegistryProperty( hDevInfo,
                                &devInfoData,
                                SPDRP_FRIENDLYNAME ,
                                NULL,
                                pDiskDevice->name,
                                retBytes,
                                NULL) || 
                SetupDiGetDeviceRegistryProperty( hDevInfo,
                                &devInfoData,
                                SPDRP_DEVICEDESC,
                                NULL,
                                pDiskDevice->name,
                                retBytes,
                                NULL);
            assert( bOk );

            HANDLE hDisk = CreateFile( (LPSTR)pDiskDevice->path,
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    0);
            if( hDisk == INVALID_HANDLE_VALUE )
            {
                DbgPrint(" open disk device failed!\n");
                pDiskDevice->sizeInSectors.QuadPart = 0;
            }
            else
            {
                DISK_GEOMETRY   diskGeom = {0};
                DWORD           bytesReturned = 0;
                BOOL            bOk = FALSE;
                bOk = DeviceIoControl( hDisk,
                                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                NULL,
                                0,
                                &diskGeom,
                                sizeof( diskGeom ),
                                &bytesReturned,
                                0);
                if( !bOk )
                {
                    DbgPrint("control code execute failed!\n");
                    pDiskDevice->sizeInSectors.QuadPart = 0;
                }
                else
                {
                    pDiskDevice->sizeInSectors.QuadPart = diskGeom.Cylinders.QuadPart
                        * diskGeom.TracksPerCylinder
                        * diskGeom.SectorsPerTrack;
					pDiskDevice->BytesPerSector = diskGeom.BytesPerSector;
                    pDiskDevice->sectorsPerCylinder.QuadPart = 
                          diskGeom.TracksPerCylinder * diskGeom.SectorsPerTrack;
                }

                STORAGE_DEVICE_NUMBER storage_disk_number={0};
                bOk = DeviceIoControl( hDisk,
                                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                NULL,
                                0,
                                &storage_disk_number,
                                sizeof( storage_disk_number ),
                                &bytesReturned,
                                0);
                if( !bOk )
                {
                    DbgPrint("control code execute failed!\n");
                    pDiskDevice->index = 0xffff;
                }
                else
                {
                    assert( storage_disk_number.DeviceType == FILE_DEVICE_DISK);
                    pDiskDevice->index = (WORD)storage_disk_number.DeviceNumber;
                }

                CloseHandle( hDisk );
            }

            //����Ϣ�����ӵ������豸������
            InsertTailList( &m_DiskListHead,&pDiskDevice->list );
            m_DiskCount++;
        }// else end ��ȡ·���ɹ�
    }//end for
    
    SetupDiDestroyDeviceInfoList( hDevInfo );

exit:
    return;
}

CDiskList::~CDiskList()
/*++
�����������ع��������ͷű��ද̬������ڴ���Դ

��������

����ֵ����
--*/
{
    ReleaseAllResources();
    return;
}

WORD CDiskList::GetDiskCount()
/*++
��������������ϵͳ�д����豸������

��������

����ֵ��ϵͳ�д����豸����
--*/
{
    return m_DiskCount;
}

BOOL CDiskList::GetDiskByIndex(IN WORD index,OUT PDISK_DEVICE *result)
/*++
����������ͨ�������豸ʵ��ID������Ӧ���豸��Ϣ�ṹ

����
    index:�����豸���
    result:�������ṩ��ָ��ռ䣬���Դ�Ž���豸��Ϣ�ṹ��ָ��

����ֵ��
    TRUE:�����ɹ���*resultָ����ȷ�Ľ��
    FALSE:����ʧ�ܣ�*result��ΪNULL

--*/
{
    PLIST_ENTRY pEntry = NULL;

    for( pEntry = m_DiskListHead.Flink;
        pEntry != (PLIST_ENTRY)&m_DiskListHead;
        pEntry = pEntry->Flink)
    {
        PDISK_DEVICE    pDiskDevice = (PDISK_DEVICE)
            CONTAINING_RECORD(pEntry,DISK_DEVICE,list);
        if( pDiskDevice->index == index )
        {
            *result = pDiskDevice;
            break;
        }
    }
    if( pEntry != (PLIST_ENTRY)&m_DiskListHead )
        return TRUE;
    else
        return FALSE;
}

PDISK_DEVICE CDiskList::GetFirstDisk()
/*++
�������������ص�һ�������豸�ṹ

��������

����ֵ���ɹ��򷵻ص�һ�������豸�ṹָ��
        ʧ�ܷ���NULL
--*/
{
    if( IsListEmpty( &m_DiskListHead ))
        return NULL;

    return (PDISK_DEVICE)CONTAINING_RECORD( m_DiskListHead.Flink,
        DISK_DEVICE,list );
}

PDISK_DEVICE CDiskList::GetNextDisk( PDISK_DEVICE curDisk )
/*++
����������ͨ����ǰ���д����豸��Ϣ���ָ�룬������һ�������豸��Ϣ���ָ��

����    curDisk:��ǰ�����豸��Ϣ���ָ��

����ֵ����һ�������豸��Ϣ�ṹָ�룬ʧ�ܷ���NULL����ʾ�Ѿ������β��
--*/
{
    assert( curDisk != NULL );

    if( curDisk->list.Flink == &m_DiskListHead )
        return NULL;
    return (PDISK_DEVICE)CONTAINING_RECORD( curDisk->list.Flink,
                                            DISK_DEVICE,
                                            list );
}

VOID CDiskList::ReleaseAllResources()
/*
�����������ͷ��������ж�̬������ڴ���Դ

��������

����ֵ����
*/
{
    PLIST_ENTRY entry = NULL;
    for( entry = RemoveHeadList( &m_DiskListHead );
        entry != NULL;
        entry = RemoveHeadList( &m_DiskListHead))
    {
        PDISK_DEVICE diskDev = (PDISK_DEVICE)CONTAINING_RECORD(
            entry,
            DISK_DEVICE,
            list);
        if( diskDev->name != NULL)free( diskDev->name );
        if( diskDev->path != NULL)free( diskDev->path );
        free( diskDev );
        m_DiskCount--;
    }
    assert( m_DiskCount == 0 );
    assert( IsListEmpty( &m_DiskListHead ));
}

VOID CDiskList::UpdateDiskList()
/*
�������������´����豸��Ϣ

��������

����ֵ����
*/
{
    ReleaseAllResources();
    InitDiskList();
}