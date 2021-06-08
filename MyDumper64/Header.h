#pragma once

#include "windows.h"

#define uchar unsigned char
#define ushort unsigned short
#define ulong unsigned long
#define ulonglong unsigned long long


typedef struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaxLength;
	unsigned long Pad;
	wchar_t* Buffer;
}UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONGLONG           Length;
  HANDLE          RootDirectory;
  _UNICODE_STRING* ObjectName;
  ULONGLONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;


#define ProcessImageInformation 0x25
#define MemorySectionName 0x2
#define MemoryBasicVlmInformation 0x3


/*
struct PROCESS_IMAGE_INFORMATION
{
   unsigned long TransferAddress; //EntryPoint after relocation
   unsigned long ZeroBits;
   unsigned long SizeOfStackReserve;
   unsigned long SizeOfStackCommit;
 
   unsigned short subsystem;
   unsigned short unk2;
   unsigned short MinorSubSystemVersion;
   unsigned short MajorSubsystemVersion;
   unsigned long  GpValue;
   unsigned short characteristics;
   unsigned short dll_characteristics;
 
   unsigned short machine;
   unsigned short flags;  //0x0400--->FLAG_IMAGE_RELOCATED 0x1---->???
   unsigned long LoaderFlags;
   unsigned long FileSize;  //on disk
   unsigned long Checksum;
};
*/

struct _SECTION_IMAGE_INFORMATION
{
   ulonglong TransferAddress;	//EntryPoint after relocation
   ulong ZeroBits;
   ulong Pad;
   ulonglong MaximumStackSize;
   ulonglong CommittedStackSize;
   ulong SubSystemType;
   ushort SubSystemMinorVersion;
   ushort SubSystemMajorVersion;
   ulong GpValue;
   ushort ImageCharacteristics;
   ushort DllCharacteristics;
   ushort Machine;
   uchar ImageContainsCode;
   struct
   {
	uchar ComPlusNativeReady:1;
	uchar ComPlusILOnly:1;
	uchar ImageDynamicallyRelocated:1;
    uchar ImageMappedFlat:1;
	uchar Reserved:4;
   }ImageFlags;
   ulong LoaderFlags;
   ulong ImageFileSize;
   ulong CheckSum;
};



typedef struct _MEMORY_BASIC_VLM_INFORMATION
{
        ulonglong  ImageBase;
		ulonglong	Unk;
        unsigned long  SizeOfImage;
}MEMORY_BASIC_VLM_INFORMATION;



extern "C"
{
        int __stdcall ZwQueryInformationProcess(HANDLE,int,_SECTION_IMAGE_INFORMATION*,unsigned long,int*);
        int __stdcall ZwQueryVirtualMemory(HANDLE,void*,unsigned long,void*,unsigned long,unsigned long*);
}


extern "C"
{
        int __stdcall DebugActiveProcessStop(unsigned long);
        BOOL __stdcall DebugSetProcessKillOnExit(BOOL);
        int __stdcall ZwCreateDebugObject(void*,unsigned long,OBJECT_ATTRIBUTES*,BOOL);
        int __stdcall ZwClose(unsigned long);
        int __stdcall ZwDebugActiveProcess(unsigned long handle,unsigned long debugObject);
}

typedef BOOL(__stdcall *lpIsWow64Process)(HANDLE,BOOL*);
typedef void(__stdcall *lpGetNativeSystemInfo)(SYSTEM_INFO*);