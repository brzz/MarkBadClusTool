//fat32_controller.h for class ----  CFat32Controller
//author:lzc
//date:2013/02/11
//e-mail:hackerlzc@126.com

#pragma once
#ifndef _FAT32_CONTROLLER_H
#define _FAT32_CONTROLLER_H
#pragma warning(push)
#pragma warning(disable:4200)

#include<windows.h>
#include"utils.h"
#include"repair_controller.h"

#ifdef _UNICODE
#error this class not support UNICODE!
#endif

//ע�⣺��֧�ֶ��߳�

class CFat32Controller:public CRepairController
{
private:

protected:
    //���Ա����

public:
    //�����ӿں���
    CFat32Controller( LPSTR lpszDiskPath,LONGLONG StartSector,LONGLONG NumberOfSectors);
    virtual ~CFat32Controller();
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
};

#pragma warning(pop)
#endif  //_FAT32_CONTROLLER_H