//utils.cpp for class-CUtils
//author:lzc
//date:2012/11/07
//e-mail:hackerlzc@126.com

//20210205 lcq

#include"stdafx.h"
#include<windows.h>
#include<winioctl.h>
#include<assert.h>
#include<crtdbg.h>
#include"layout_mbr.h"
#include"utils.h"
extern FILE *hLogFile;
CUtils::CUtils()
/*++
�����������������е�Ԫ��ʼ��
--*/
{
    
}
void CUtils::_DbgPrint(LPSTR file,LPSTR function,LPSTR message)
{
    CHAR buf[256]; 

    sprintf_s( buf,"%s=>%s:%s\n",file,function,message );
    OutputDebugString(buf);
    fprintf( hLogFile,"%s",buf );
}

void CUtils::ShowError( DWORD ErrorCode )
/*
������������MessageBox��ʾGetLastError�Ĵ������������Ϣ
*/
{
	LPVOID                 lpMsgBuf;

	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &lpMsgBuf,
		0,
		NULL 
	);
	// Process any inserts in lpMsgBuf.
	// ...
	// Display the string.
	MessageBox( NULL, (LPCTSTR)lpMsgBuf,_T("Error"), MB_OK | MB_ICONINFORMATION );
	// Free the buffer.
	LocalFree( lpMsgBuf );
}


VOID
CUtils::InitializeListHead(OUT PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}


VOID CUtils::InsertTailList(
    IN PLIST_ENTRY  ListHead,
    IN PLIST_ENTRY  Entry
    )
{
    ListHead->Blink->Flink = Entry;
    Entry->Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    ListHead->Blink = Entry;
}

VOID CUtils::InsertHeadList(
    IN PLIST_ENTRY  ListHead,
    IN PLIST_ENTRY  Entry
    )
{
    ListHead->Flink->Blink = Entry;
    Entry->Flink = ListHead->Flink;
    Entry->Blink = ListHead;
    ListHead->Flink = Entry;
}


BOOL CUtils::IsListEmpty( IN PLIST_ENTRY ListHead )
{
    return ListHead->Flink == ListHead ? TRUE:FALSE;
}

PLIST_ENTRY CUtils::RemoveHeadList(IN PLIST_ENTRY  ListHead )
{
    PLIST_ENTRY entry = NULL;

    if( IsListEmpty( ListHead))return NULL;

    entry = ListHead->Flink;
    ListHead->Flink = entry->Flink;
    entry->Flink->Blink = ListHead;
    entry->Flink = entry->Blink = NULL;

    return entry;
}


PLIST_ENTRY CUtils::RemoveTailList( IN PLIST_ENTRY  ListHead )
{
    PLIST_ENTRY entry = NULL;

    if( IsListEmpty( ListHead))return NULL;

    entry = ListHead->Blink;
    ListHead->Blink = entry->Blink;
    entry->Blink->Flink = ListHead;
    entry->Flink = entry->Blink = NULL;

    return entry;
}

VOID CUtils::RemoveEntryList( PLIST_ENTRY ListEntry )
/*++
--*/
{
    ListEntry->Flink->Blink = ListEntry->Blink;
    ListEntry->Blink->Flink = ListEntry->Flink;

}
PLIST_ENTRY CUtils::GetFirstListEntry( PLIST_ENTRY ListHead )
/*++
--*/
{
    assert( ListHead != NULL );
    return ListHead->Flink;
}

PLIST_ENTRY CUtils::GetNextListEntry( PLIST_ENTRY CurrEntry )
/*++
--*/
{
    assert( CurrEntry != NULL );
    return CurrEntry->Flink;
}

BYTE CUtils::CompressLongLong( LONGLONG x,BOOL bSigned )
/*++
��������������һ��LONGLONG���͵��������ٿ����ö����ֽڱ�ʾ

����:
    x:���ж�����
    bSigned:ѹ������Ƿ������з�������Ĭ�����з�����

����ֵ��
    �ֽڸ���
--*/
{
    BYTE result = 0;

    if( x >= 0 )
    {
        for( CHAR j = 7;j >= 0;j--)
        {
            if( x & (0xffull << j*8))
            {
                if( (x & (0x80ull << j*8)) && bSigned)
                    result = j + 2;
                else
                    result = j + 1;
                break;
            }
        }
    }
    else
    {
        for( CHAR j = 7;j >= 0;j--)
        {
            if( ~x & (0xffull << j*8))
            {
                if( (~x & (0x80ull << j*8)) && bSigned)
                    result = j+2;
                else
                    result = j+1;
                break;
            }
        }
    }

    return result;
}



BOOL CUtils::ReadSector(IN HANDLE hDisk,
	OUT LPVOID buffer, 
	IN DWORD bufferSize,
	IN DWORD SectorNumberLow, 
	IN DWORD SectorNumberHigh, 
	DWORD SectorSzie
)

	/*++
	������������ȡһ������������

	������
	hDisk:�����豸���
	buffer:�������������С����Ϊһ�����������򷵻�ʧ��
	bufferSize:ָ������������Ĵ�С
	SectorNumberLow:�����ŵĵ�32λ
	SectorNumberHigh:�����ŵĸ�32λ��Ĭ��ֵΪ0

	����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE

	--*/
{
	DWORD   bytesOffsetLow, bytesOffsetHigh, retBytes;
	ULONGLONG   bytesOffset;

	if (bufferSize < SectorSzie)
		return FALSE;
	
	//lcq: ���ﰴ��512�ֽ�һ���������ֽ�ƫ�ƣ���������ġ�
	//bytesOffsetHigh = (SectorNumberHigh << 9) | ((SectorNumberLow & 0xff800000) >> 23);
	//bytesOffsetLow = SectorNumberLow << 9;
	//�������ֽ�һ��������ģʽ
	bytesOffset = SectorNumberHigh << 32 | SectorNumberLow;
	bytesOffset = bytesOffset*SectorSzie;
	//(DWORD)(tmp & 0xffffffff), (DWORD)(tmp >> 32)
	bytesOffsetLow = (DWORD)(bytesOffset & 0xffffffff);
	bytesOffsetHigh = (DWORD)(bytesOffset >> 32);


	if (INVALID_SET_FILE_POINTER ==
		SetFilePointer(hDisk,
			bytesOffsetLow,
			(PLONG)&bytesOffsetHigh,
			FILE_BEGIN))
	{
		ShowError(GetLastError());
		return FALSE;
	}

	return ReadFile(hDisk, buffer, SectorSzie, &retBytes, NULL);

}


BOOL CUtils::WriteSector(HANDLE hDisk,
                        LPVOID buffer, 
                        DWORD bufferSize,
                        DWORD SectorNumberLow, 
                        DWORD SectorNumberHigh, /* = 0 */
	                    DWORD  SectorSzie)
/*++
����������д��һ������������

������
    hDisk:�����豸������������дȨ�ޣ�
    buffer:���뻺��������С����Ϊһ�����������򷵻�ʧ��
    bufferSize:ָ���뻺�����Ĵ�С������Ϊһ��������
    SectorNumberLow:�����ŵĵ�32λ
    SectorNumberHigh:�����ŵĸ�32λ��Ĭ��ֵΪ0

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE

--*/
{
    DWORD   bytesOffsetLow,bytesOffsetHigh,retBytes;
	ULONGLONG   bytesOffset;

    if( bufferSize < MBR_SECTOR_SIZE )
        return FALSE;
#if 0
    printf("WARNING:Write to sector:%d\n",SectorNumberLow);
    for( DWORD i = 0;i < MBR_SECTOR_SIZE;i++)
    {
        printf("%.2x ",((LPBYTE)buffer)[i] );
        if((i+1)%16==0)printf("\n");
    }
    system("PAUSE");
    return TRUE;
#endif
#if 1
    //bytesOffsetHigh = (SectorNumberHigh << 9 ) | ((SectorNumberLow & 0xff800000) >> 23);
    //bytesOffsetLow = SectorNumberLow << 9;

	//lcq: ���ﰴ��512�ֽ�һ���������ֽ�ƫ�ƣ���������ġ�
	//bytesOffsetHigh = (SectorNumberHigh << 9) | ((SectorNumberLow & 0xff800000) >> 23);
	//bytesOffsetLow = SectorNumberLow << 9;
	//�������ֽ�һ��������ģʽ
	bytesOffset = SectorNumberHigh << 32 | SectorNumberLow;
	bytesOffset = bytesOffset*SectorSzie;
	//(DWORD)(tmp & 0xffffffff), (DWORD)(tmp >> 32)
	bytesOffsetLow = (DWORD)(bytesOffset & 0xffffffff);
	bytesOffsetHigh = (DWORD)(bytesOffset >> 32);

    if( INVALID_SET_FILE_POINTER == 
           SetFilePointer( hDisk,
                            bytesOffsetLow,
                            //bytesOffsetHigh != 0?(PLONG)&bytesOffsetHigh:NULL,
                            (PLONG)&bytesOffsetHigh,
                            FILE_BEGIN ))
    {
        return FALSE;
    }

    return WriteFile( hDisk, buffer, SectorSzie, &retBytes, NULL);
#endif

}

BOOL CUtils::CopyBlock( HANDLE hDisk,ULONGLONG SourceSector,ULONGLONG DestinationSector,ULONGLONG NumberOfSectors)
/*++
�����������������ݿ飨��λ��������

������
    hDisk:�����豸�����������дȨ�ޣ�
    SourceSector:Դ����ʼ������
    DestinationSector:Ŀ�ĵ���ʼ������
    NumberOfSectors:�����ƿ����������

����ֵ���ɹ�����TRUE��ʧ�ܷ���FALSE
--*/
{
    BOOL bOk = TRUE;
    int max_sector_count = 10 * 2048;
    LPBYTE buffer = (LPBYTE)malloc( max_sector_count * MBR_SECTOR_SIZE );//10MB
    assert( buffer != NULL);
    DWORD   bytesOffsetLow,bytesOffsetHigh,retBytes;
    DWORD SectorNumberHigh,SectorNumberLow;
    while( NumberOfSectors > 10 * 2048 )
    {
        SectorNumberHigh = (DWORD)(SourceSector >> 32);
        SectorNumberLow = (DWORD)(SourceSector & 0xffffffffull);
        bytesOffsetHigh = (SectorNumberHigh << 9 ) | ((SectorNumberLow & 0xff800000) >> 23);
        bytesOffsetLow = SectorNumberLow << 9;
        if( INVALID_SET_FILE_POINTER == 
               SetFilePointer( hDisk,
                                bytesOffsetLow,
                                (PLONG)&bytesOffsetHigh,
                                FILE_BEGIN ))
        {
            bOk = FALSE;
            goto exit;
        }

        bOk = ReadFile( hDisk,
                        buffer,
                        max_sector_count * MBR_SECTOR_SIZE,
                        &retBytes,
                        NULL);
        if( !bOk)
            goto exit;

        SectorNumberHigh = (DWORD)(DestinationSector >> 32);
        SectorNumberLow = (DWORD)(DestinationSector & 0xffffffffull);
        bytesOffsetHigh = (SectorNumberHigh << 9 ) | ((SectorNumberLow & 0xff800000) >> 23);
        bytesOffsetLow = SectorNumberLow << 9;
        if( INVALID_SET_FILE_POINTER == 
               SetFilePointer( hDisk,
                                bytesOffsetLow,
                                (PLONG)&bytesOffsetHigh,
                                FILE_BEGIN ))
        {
            bOk = FALSE;
            goto exit;
        }
        bOk = WriteFile( hDisk,
            buffer,
            max_sector_count * MBR_SECTOR_SIZE,
            &retBytes,
            NULL);
        if( !bOk )
            goto exit;
        
        SourceSector += max_sector_count;
        DestinationSector += max_sector_count;
        NumberOfSectors -= max_sector_count;
    }
    
    if( NumberOfSectors > 0 )
    {
        SectorNumberHigh = (DWORD)(SourceSector >> 32);
        SectorNumberLow = (DWORD)(SourceSector & 0xffffffffull);
        bytesOffsetHigh = (SectorNumberHigh << 9 ) | ((SectorNumberLow & 0xff800000) >> 23);
        bytesOffsetLow = SectorNumberLow << 9;
        if( INVALID_SET_FILE_POINTER == 
               SetFilePointer( hDisk,
                                bytesOffsetLow,
                                (PLONG)&bytesOffsetHigh,
                                FILE_BEGIN ))
        {
            bOk = FALSE;
            goto exit;
        }

        bOk = ReadFile( hDisk,
                        buffer,
                        (DWORD)NumberOfSectors * MBR_SECTOR_SIZE,
                        &retBytes,
                        NULL);
        if( !bOk)
            goto exit;

        SectorNumberHigh = (DWORD)(DestinationSector >> 32);
        SectorNumberLow = (DWORD)(DestinationSector & 0xffffffffull);
        bytesOffsetHigh = (SectorNumberHigh << 9 ) | ((SectorNumberLow & 0xff800000) >> 23);
        bytesOffsetLow = SectorNumberLow << 9;
        if( INVALID_SET_FILE_POINTER == 
               SetFilePointer( hDisk,
                                bytesOffsetLow,
                                (PLONG)&bytesOffsetHigh,
                                FILE_BEGIN ))
        {
            bOk = FALSE;
            goto exit;
        }
        bOk = WriteFile( hDisk,
            buffer,
            (DWORD)NumberOfSectors * MBR_SECTOR_SIZE,
            &retBytes,
            NULL);
        if( !bOk )
            goto exit;
    }

exit:
    if( buffer != NULL)
        free(buffer);

    return bOk;
}