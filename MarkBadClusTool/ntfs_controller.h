//ntfs_controller.h for class ----  CNtfsController
//author:lzc
//date:2012/11/14
//e-mail:hackerlzc@126.com

#pragma once
#ifndef _NTFS_CONTROLLER_H
#define _NTFS_CONTROLLER_H
#pragma warning(push)
#pragma warning(disable:4200)

#include<windows.h>
#include"utils.h"
#include"repair_controller.h"
#include"layout_ntfs.h"

#ifdef _UNICODE
#error this class not support UNICODE!
#endif

//ע�⣺��֧�ֶ��߳�

typedef struct _FILE_ATTRIBUTE_NODE
{
    LIST_ENTRY      List;
    LONGLONG        OwnerRecordId;  //�������������ļ���¼ID
    WORD            AttrOffset;     //���������ļ���¼�е�ƫ��
    DWORD           AttributeType;  //��������
    LPVOID          AttributeData;  //ָ���������ݵ�ָ��(�����ݰ�������ͷ���ڣ�
    DWORD           Length;         //�������ݵĳ���
}FILE_ATTRIBUTE_NODE,*PFILE_ATTRIBUTE_NODE;

typedef struct _FILE_INFORMATION
{
    LIST_ENTRY      List;           //��������Ԫ��ΪFILE_ATTRIBUTE_NODE
    LONGLONG        FileSize;       //�ļ���С���ֽڣ�
    PWCHAR          FileName;       //ָ��UNICODE�ļ���
    DWORD           FileNameLength; //�ļ����ַ���
    LONGLONG        FileRecordId;   //�ļ���¼��
}FILE_INFORMATION,*PFILE_INFORMATION;

typedef PFILE_INFORMATION NTFS_FILE;

class CNtfsController:public CRepairController
{
private:

    NTFS_BOOT_SECTOR m_BootSect;                //NTFS��DBR
    DWORD           m_ClusterSizeInBytes;       //���ֽڴ�С
    DWORD           m_MftRecordLength;          //�ļ���¼��С����λ�ֽڣ�
    LPBYTE          m_MftDataRuns;              //ָ��$MFT�ļ�80���Ե�Datarns(�ڴ涯̬���룩
    DWORD           m_MftDataRunsLength;        //m_MftDataRunsָ��Ļ�������С
    LONGLONG        m_MftNumberOfRecord;        //$MFT�ļ����ļ���¼��
    LPBYTE          m_Bitmap;                   /*ָ������ӳ��Bitmap�Ļ�������InitBitmap�п����ڴ沢��ʼ��
                                                ReleaseAllResources���ͷ�*/
    LONGLONG        m_BitmapLength;             //Bitmapʵ�ʴ�С����λ���ֽڣ�
    LPBYTE          m_MftBitmap;                //$MFT��Bitmap�������ݣ�ReleaseAllResources���ͷ�
    LONGLONG        m_MftBitmapLength;          //m_MftBitmap�ĳ��ȣ��ֽڣ�
protected:
    //���Ա����

public:
    //�����ӿں���
    CNtfsController( LPSTR lpszDiskPath,LONGLONG StartSector,LONGLONG NumberOfSectors);
    virtual ~CNtfsController();
    virtual VOID PrepareUpdateBadBlockList();
    virtual VOID AddBadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors );
    virtual VOID AddDeadBlock( LONGLONG StartLsn,LONGLONG NumberOfSectors );
    virtual BOOL ProbeForRepair();
    virtual BOOL VerifyFileSystem();
    virtual BOOL StartRepairProgress();
    virtual BOOL StopRepairProgress();

protected:
    //�ɱ��̳е���˽�к���
    virtual BOOL InitController();
    virtual VOID ReleaseResources();
private:
    //���ɱ��̳е�˽�к���
    BOOL InitFreeAndUsedBlockList();
    VOID DestroyListNodes( PLIST_ENTRY ListHead);
    BOOL ReadLogicalCluster( OUT LPVOID Buffer,
                             IN DWORD BufferSize,
                             IN LONGLONG Lcn,
                             IN DWORD TryTime = 1,
                             IN BYTE BadByte = 0xbb);
    BOOL WriteLogicalCluster( IN LPVOID Buffer,
                             IN DWORD DataLen,
                             IN LONGLONG Lcn,
                             IN DWORD TryTime = 1);
    BOOL CopyLogicalClusterBlock( IN LONGLONG SourceLcn,
                           IN LONGLONG DestLcn,
                           IN LONGLONG NumberOfLcns );
    LONGLONG GetNumberOfVcnsInDataRuns( IN LPBYTE DataRuns,IN DWORD Length );
    LONGLONG GetLastStartLcnInDataruns( IN LPBYTE DataRuns,IN DWORD Length );
    DWORD    GetDataRunsLength( IN LPBYTE DataRuns,IN DWORD Length );
    LONGLONG GetDataRunsValue( IN LPBYTE DataRuns,IN DWORD Length,OUT LPVOID Buffer,IN LONGLONG BufferLength );
    LONGLONG VcnToLcn( LONGLONG Vcn,LPBYTE DataRuns,DWORD Length );
    LONG BlockListToDataRuns( IN PLIST_ENTRY BlockListHead,OUT LPBYTE Dataruns,IN LONGLONG DatarunsLength );
    LONG DataRunsToSpaceDataRuns(IN LPBYTE dataruns,IN LONGLONG len_dataruns,OUT LPBYTE bad_dataruns,IN LONGLONG len_bad_dataruns );
    BOOL InitMftFile( IN LPVOID MftRecordCluster,IN DWORD BufferLength );
    BOOL InitBitmap();
    BOOL InitMftBitmap();
    BOOL UpdateBitmap();
    BOOL UpdateMftBitmap();
    BOOL UpdateBadClus();
    BOOL UpdateMftMirr();
    BOOL InitBadBlockList();
    PFILE_INFORMATION InitNtfsFile( IN LPVOID MftRecordCluster,IN DWORD BufferLength,LONGLONG RecordId );
    PFILE_INFORMATION OpenNtfsFile( IN LONGLONG RecordId );
    BOOL ReadMftRecord( IN LONGLONG RecordId,OUT PVOID Buffer,IN DWORD BufferLength );
    BOOL WriteMftRecord( IN LONGLONG RecordId,IN PVOID Buffer,IN DWORD BufferLength );
    VOID CloseFile( IN PFILE_INFORMATION File );
    LONG GetAttributeListValue( IN PATTR_RECORD AttrRecord,
                                OUT PVOID Buffer,
                                IN DWORD BufferLength,
                                OUT PDWORD BytesReturned );
    LONG GetAttributeValue( IN NTFS_FILE File,
                             IN ATTR_TYPES Type,
                             OUT PVOID Buffer,
                             IN DWORD BufferLength,
                             OUT PBOOL IsDataruns = NULL,
                             IN PWCHAR AttrName = NULL,
                             IN WORD Instance = 0,
                             OUT PDWORD BytesReturned = NULL);
    VOID UpdateBitmapFromBlockList(PLIST_ENTRY ListHead);
    LONGLONG AllocateBlock( LONGLONG LengthInCluster );
    BOOL FreeBlock( LONGLONG StartCluster,LONGLONG LengthInCluster );
    BOOL FreeBlockInDataruns( IN LPBYTE Dataruns,DWORD Length);
    LONGLONG AllocateFileRecordId();
    VOID FreeFileRecordId( LONGLONG FileRecordId );
    VOID _ShowList();
    LONG CheckAndUpdateFile( IN LONGLONG FileId );
};

#pragma warning(pop)
#endif  //_NTFS_CONTROLLER_H