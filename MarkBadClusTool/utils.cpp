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
功能描述：公共运行单元初始化
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
功能描述：用MessageBox显示GetLastError的错误代码描述信息
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
功能描述：计算一个LONGLONG类型的数据至少可以用多少字节表示

参数:
    x:被判定的数
    bSigned:压缩结果是否用于有符号数，默认是有符号数

返回值：
    字节个数
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
	功能描述：读取一个扇区的数据

	参数：
	hDisk:磁盘设备句柄
	buffer:输出缓冲区，大小至少为一个扇区，否则返回失败
	bufferSize:指定输出缓冲区的大小
	SectorNumberLow:扇区号的低32位
	SectorNumberHigh:扇区号的高32位，默认值为0

	返回值：成功返回TRUE，失败返回FALSE

	--*/
{
	DWORD   bytesOffsetLow, bytesOffsetHigh, retBytes;
	ULONGLONG   bytesOffset;

	if (bufferSize < SectorSzie)
		return FALSE;
	
	//lcq: 这里按照512字节一扇区计算字节偏移，是有问题的。
	//bytesOffsetHigh = (SectorNumberHigh << 9) | ((SectorNumberLow & 0xff800000) >> 23);
	//bytesOffsetLow = SectorNumberLow << 9;
	//更正多字节一扇区兼容模式
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


BOOL CUtils::WriteSector(IN HANDLE hDisk,
	IN LPVOID buffer,
	IN DWORD bufferSize,
	IN DWORD SectorNumberLow,
	IN DWORD SectorNumberHigh,
	DWORD  SectorSzie
)
/*++
功能描述：写入一个扇区的数据

参数：
    hDisk:磁盘设备句柄（必须具有写权限）
    buffer:输入缓冲区，大小至少为一个扇区，否则返回失败
    bufferSize:指定入缓冲区的大小（至少为一个扇区）
    SectorNumberLow:扇区号的低32位
    SectorNumberHigh:扇区号的高32位，默认值为0

返回值：成功返回TRUE，失败返回FALSE

--*/
{
    DWORD   bytesOffsetLow,bytesOffsetHigh,retBytes;
	ULONGLONG   bytesOffset;

    if( bufferSize < SectorSzie)
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

	//lcq: 这里按照512字节一扇区计算字节偏移，是有问题的。
	//bytesOffsetHigh = (SectorNumberHigh << 9) | ((SectorNumberLow & 0xff800000) >> 23);
	//bytesOffsetLow = SectorNumberLow << 9;
	//更正多字节一扇区兼容模式
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

BOOL CUtils::CopyBlock(IN HANDLE hDisk,
	IN ULONGLONG SourceSector,
	IN ULONGLONG DestinationSector,
	IN ULONGLONG NumberOfSectors,
	DWORD  SectorSzie
)
/*++
功能描述：复制数据块（单位：扇区）

参数：
    hDisk:磁盘设备句柄（必须有写权限）
    SourceSector:源的起始扇区号
    DestinationSector:目的的起始扇区号
    NumberOfSectors:所复制块的扇区数量

返回值：成功返回TRUE，失败返回FALSE
--*/
{
    BOOL bOk = TRUE;
    int max_sector_count = 10 * 2048;
    LPBYTE buffer = (LPBYTE)malloc( max_sector_count * SectorSzie);//10MB
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
                        max_sector_count * SectorSzie,
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
            max_sector_count * SectorSzie,
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
                        (DWORD)NumberOfSectors * SectorSzie,
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
            (DWORD)NumberOfSectors * SectorSzie,
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