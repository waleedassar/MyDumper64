// MyDumper64.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include "Header.h"



lpIsWow64Process pIsWow64Process;
lpGetNativeSystemInfo pGetNativeSystemInfo;
//------------------------------------------
unsigned long long g_lpMaximumApplicationAddress = 0x7ffeffff;
unsigned long long g_lpMinimumApplicationAddress = 0x0;
unsigned long long g_PageSize = 0x1000;
//------------------------------------------
void Resolve()
{
	HMODULE hKern = LoadLibrary(L"kernel32.dll");
	pIsWow64Process = (lpIsWow64Process) GetProcAddress(hKern,"IsWow64Process");
	pGetNativeSystemInfo = (lpGetNativeSystemInfo)GetProcAddress(hKern,"GetNativeSystemInfo");
}
//---------------------- Acquiring Debug Privilege --------------------------------------
BOOL Debug()
{
        LUID X;
        if(!LookupPrivilegeValue(0,L"SeDebugPrivilege",&X))
        {
               return FALSE;
        }
        HANDLE hToken;
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken) )
        {
                return FALSE;
        }
        TOKEN_PRIVILEGES T={0};
        T.PrivilegeCount=1;
        T.Privileges[0].Luid=X;
        T.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
 
        if(!AdjustTokenPrivileges(hToken,FALSE,&T,0,0,0) )
        {
                return FALSE;
        }
        return TRUE;
}
//-----------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------
void AppendBackSlash(wchar_t* pStr)
{
	unsigned long Length = wcslen((wchar_t*)pStr);
	if( (Length == 3) && (pStr[1]==L':') && (pStr[2]==L'\\')) return;
	if(pStr[Length-1]==L'\\') return;
	pStr[Length]=L'\\';
	pStr[Length+1]=0;
}
//----------------------------------------------------------------------------------------
//Method 0 to extract ImageBase on Windows XP
int GetImageBase_XP_1(unsigned long ProcessId,unsigned long* pImageBase)
{
		if(DebugActiveProcess(ProcessId))
		{
			 DEBUG_EVENT DE={0};
			 while( WaitForDebugEvent(&DE,0x32) )
			 {
				 switch(DE.dwDebugEventCode)
				 {
				 case CREATE_PROCESS_DEBUG_EVENT:
					 *pImageBase = (unsigned long) (DE.u.CreateProcessInfo.lpBaseOfImage);
				     ContinueDebugEvent(DE.dwProcessId,DE.dwThreadId,DBG_CONTINUE);
					 DebugActiveProcessStop(ProcessId);
					 break;
				 default:
					 ContinueDebugEvent(DE.dwProcessId,DE.dwThreadId,DBG_CONTINUE);
					 break;
				 }
			 }
		}
		else
		{
			return -1; //Process is being debugged.
		}

		if(! *pImageBase)
		{
			 printf("Zero ImageBase\r\n");
		     return -2;
		}
		printf("ImageBase is %x\r\n",*pImageBase);
		return 0;
}


//-------------------------------------------------------------------------------------
void GetGlobalMinMaxAddr()
{
	SYSTEM_INFO SysInfo={0};
	GetSystemInfo(&SysInfo);

	g_lpMaximumApplicationAddress = (unsigned long long) (SysInfo.lpMaximumApplicationAddress);
	g_lpMinimumApplicationAddress = (unsigned long long)  (SysInfo.lpMinimumApplicationAddress);
	g_PageSize = SysInfo.dwPageSize;
	if(!GetNativeSystemInfo)
	{
		Resolve();
	}
	memset(&SysInfo,0,sizeof(SysInfo));
	if(GetNativeSystemInfo)
	{
		GetNativeSystemInfo(&SysInfo);
		g_lpMaximumApplicationAddress = (unsigned long long)  (SysInfo.lpMaximumApplicationAddress);
	    g_lpMinimumApplicationAddress = (unsigned long long)  (SysInfo.lpMinimumApplicationAddress);
		g_PageSize = (unsigned long long)  (SysInfo.dwPageSize);
	}
	return;
}

bool IsRunPE(HANDLE hProcess,unsigned long lpMaximumApplicationAddress)
{
	unsigned long LastSize = 0;
	bool MainExecutableFound = false;
	for(unsigned long i=0;i<lpMaximumApplicationAddress;i+=g_PageSize)
	{
		MEMORY_BASIC_INFORMATION MBI={0};
		if( VirtualQueryEx(hProcess,(void*)i,&MBI,sizeof(MBI)) )
		{
			if(  (MBI.Type == MEM_IMAGE)  )
			{
					LastSize = MBI.RegionSize;

					IMAGE_DOS_HEADER DosHdr={0};
					IMAGE_NT_HEADERS* NtHdrs={0};
					
					unsigned long long BytesRead;
				    if(ReadProcessMemory(hProcess,(void*)i,&DosHdr,sizeof(DosHdr),&BytesRead) )
					{
						unsigned long e_lfanew = DosHdr.e_lfanew;
						if(DosHdr.e_magic==0x5A4D && e_lfanew<0x10000000)
						{
							 if(ReadProcessMemory(hProcess,(void*)(i+e_lfanew),&NtHdrs,sizeof(NtHdrs),&BytesRead) )
							 {
								// unsigned long Characteristics = 
							 }
						}
					}

					i+= (LastSize-g_PageSize);
			}
		}
	}
	return (!MainExecutableFound);
}

//returns the "SizeOfImage" value given the "ImageBase" value.  Using the "AllocationBase" and "AllocationProtect" values.
unsigned long GetSizeOfImage(HANDLE hProcess, unsigned long ImageBase)
{
	MEMORY_BASIC_INFORMATION MBI={0};

	if(!VirtualQueryEx(hProcess,(void*)(ImageBase+1),&MBI,sizeof(MBI))) return 0;

	unsigned long loc_ImageBase = (unsigned long) (MBI.AllocationBase);
	if(loc_ImageBase != ImageBase) return 0;
	unsigned long loc_AllocationProtect = (unsigned long)MBI.AllocationProtect;


	unsigned long i=g_PageSize;
	while(1)
	{
		memset(&MBI,0,sizeof(MBI));
		unsigned long len = VirtualQueryEx(hProcess,(void*)(loc_ImageBase+i),&MBI,sizeof(MBI));
		if(!len) break;

		if( ((unsigned long)(MBI.AllocationBase)!=loc_ImageBase) || ((unsigned long)(MBI.AllocationProtect)!=loc_AllocationProtect) ) break;
		i+=g_PageSize;
	}
	return i;
}

//Extracts the "ImageBase" and "SizeOfImage" values given the "EntryPoint" value. 
//Using the "AllocationBase" and "AllocationProtect" values of VirtualQueryEx
//returns SizeOfImage in return value.
unsigned long GetImageInfo(HANDLE hProcess, ulonglong EntryPoint,ulonglong* pImageBase)
{
	if(!EntryPoint) return 0;
	if(pImageBase) *pImageBase = 0;
	else return 0;

	MEMORY_BASIC_INFORMATION MBI={0};
	if(!VirtualQueryEx(hProcess,(void*)(EntryPoint),&MBI,sizeof(MBI))) return 0;

	ulonglong extracted_ImageBase         = (ulonglong) (MBI.AllocationBase);
	ulonglong extracted_AllocationProtect = (ulonglong) (MBI.AllocationProtect);
	if(extracted_AllocationProtect != PAGE_EXECUTE_READWRITE) //It maybe a RunPE memory
	{
		return 0;
	}

	ulonglong i=g_PageSize;
	while(1)
	{
		memset(&MBI,0,sizeof(MBI));
		ulonglong len = VirtualQueryEx(hProcess,(void*)(extracted_ImageBase+i),&MBI,sizeof(MBI));
		if(!len) break;
		if( ((ulonglong)(MBI.AllocationBase)!=extracted_ImageBase) || ((ulonglong)(MBI.AllocationProtect)!=extracted_AllocationProtect) ) break;
		i+=g_PageSize;
	}

	*pImageBase = extracted_ImageBase;
	return i;
}

//Detects if process can allocate memory at addresses higher than or equal to  0x80000000
//Process Handle must have PROCESS_VM_OPERATION access right.
bool IsProcessLargeAddressSpaceAware(HANDLE hProcess)
{
	bool ret = false;
	char* p=(char*)VirtualAllocEx(hProcess,0,0x1000,MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN,PAGE_READWRITE);
	if(!p)	return ret;

	if( (unsigned long) p >= 0x80000000) ret = true;
	
	VirtualFree(p,0,MEM_RELEASE);
	return ret;
}


//Upon failure the following error codes are returned
// -1  ==> OS Not Supported
// -2  ==> Error in Arguments/Argument Parsing
// -3  ==> Error Invalid Process Id e.g. PID = 0 or 4
// -4  ==> Error Opening Target process OpenProcess
// -5  ==> Unsupported archtiecture
// -6  ==> Error querying ProcessImageInformation
// -7  ==> Error Querying MemoryBasicVlmInformation:ImageBase & SizeOfImage (Win7/Vista)
// -8  ==> Error Querying ProcessImageInformation: ImageBase & SizeOfImage(XP/2003)
// -9  ==> Error: Value of ImageBase is zero
// -10 ==> Error: Value of SizeOfImage is zero
int _tmain(int argc, _TCHAR* argv[])
{
	Resolve();
	//----------------------------------------------------------------------------------
	unsigned long dwVersion      = GetVersion();
	unsigned long dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    unsigned long dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	printf("OS version, Major: %X, Minor: %X\r\n",dwMajorVersion,dwMinorVersion);
	//----------------------------------------------------------------------------------
	unsigned long PID = 0;
	wchar_t* pDllToInclude = 0;
	if(argc < 2)
	{
		printf("Usage: MyDumper.exe 1221\r\n       MyDumper.exe 0x4C5\r\n\r\n");
		return -2;
	}
	else
	{
		if( argc >= 2)
		{
			bool Hex = false;
			if( *(unsigned short*)(argv[1]) == 'x0' || *(unsigned short*)(argv[1]) == 'X0'  ) Hex = true;
			if(Hex) PID = wcstol(argv[1],0,0x10);
			else    PID = wcstol(argv[1],0,10);
		}

		if(argc >= 3)
		{
			pDllToInclude = argv[2];
		}


	}
    
	if( (PID == 0) || (PID == 4) )
	{
		   printf("Invalid Process Id\r\n");
		   return -3;
	}
	//---------------------------------------------------------------------------------
	if(!Debug())
	{
		printf("Warning: Can't acquire SE_DEBUG_PRIVILEGE\r\n");
	}

	//---------------------------------------------------------------------------------
	//---------------------------------------------------------------------------------
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,PID);
	if(!hProcess)
	{
		printf("Error: Can't open process %x ErrorCode:%x\r\n",PID,GetLastError());
		return -4;
	}
	printf("hProcess: %I64X\r\n",hProcess);
	//------------- Trying to determine the BitNess of Target Process 64Bit/32Bit -----
	bool Process_Is_64 = false;
	unsigned long Machine = 0x14C; //Assume 32-Bit
	_SECTION_IMAGE_INFORMATION Q_Machine={0};
    int ret_Machine = ZwQueryInformationProcess(hProcess,ProcessImageInformation,&Q_Machine,sizeof(Q_Machine),0);
	printf("ZwQueryInformationProcess, ret: %X\r\n",ret_Machine);
	if(ret_Machine >= 0)
	{
		Machine = Q_Machine.Machine;
		Process_Is_64= (Machine == 0x8664)?true:false;
	}
	else
	{
		if(ret_Machine == 0xC000010A)
		{
			printf("Dead process\r\n");
			return -5;
		}
		printf("Warning: Can't determine target process's platform. 32-Bit Assumed.\r\n");
	}

	if( (Machine != 0x14C) && (Process_Is_64 == false) ) //Not x86, Not x86-64
	{
		printf("Error: Unsupported architecture %x.\r\n",Machine);
		CloseHandle(hProcess);
		return -5;
	}
	//---------------------------------------------------------------------------------
	GetGlobalMinMaxAddr();
	//---------------------------------------------------------------------------------
	ulonglong PageSize = g_PageSize;
	ulonglong lpMinimumApplicationAddress = 0x0; //Not 0x10000 because we want to read from NullPage.
	ulonglong lpMaximumApplicationAddress = g_lpMaximumApplicationAddress;


	BOOL Wow64 = FALSE;
	if(IsWow64Process(hProcess,&Wow64) )
	{
		   if(Wow64)
		   {
			   HANDLE hProcess_LASA = OpenProcess(PROCESS_VM_OPERATION,FALSE,PID);

			   if( (hProcess_LASA) && (IsProcessLargeAddressSpaceAware(hProcess_LASA)) )
			   {
					   //To get the real value, you have to call ZwQuerySystemInformation (SystemBasicInformation or SystemEmulationBasicInformation) from the context of Target process.
					   //In Wow64 processes, calling ZwQuerySystemInformation from a LASA-capable process and non-LASA-capable process gives different results. Because the "lpMaximumApplicationAddress"
					   //is extracted from the process's _EPROCESS->HighestUserAddress

					   //Solution:
					   //1) Create remote thread into a LASA-capable process
					   //2) Use default = 0xFFFEffff
					   lpMaximumApplicationAddress = 0xFFFEffff;
			   }
			   else
			   {
				   //Drop the Non-LASA executale from RT_BIN
				   //Execute it
				   //Get Process Exit Code
				   lpMaximumApplicationAddress = 0x7ffeffff;
			   }

			   if(hProcess_LASA) CloseHandle(hProcess_LASA);
		   }
	}
	printf("Maximum Address is %I64X\r\n",lpMaximumApplicationAddress);
	//----------------------------------------------
    _SECTION_IMAGE_INFORMATION Q={0};
    int ret = ZwQueryInformationProcess(hProcess,ProcessImageInformation,&Q,sizeof(Q),0);
	if(ret < 0)
	{
		     printf("Error Extracting ProcessImageInformationEntryPoint\r\n");
		     CloseHandle(hProcess);
		     return -6;
	}

	ulonglong EP = (Q.TransferAddress);


	ulonglong ImageBase = 0;
	ulonglong SizeOfImage = 0;
	if( dwMajorVersion >= 6 ) //Vista/2008/7/8/others
	{
	         MEMORY_BASIC_VLM_INFORMATION MBVI = {0};
	         int retX = ZwQueryVirtualMemory(hProcess,(void*)EP,MemoryBasicVlmInformation,&MBVI,sizeof(MBVI),0);
			 printf("ZwQueryVirtualMemory, ret: %X\r\n",retX);
	         if(retX < 0)
			 {
		         printf("Error Querying MemoryBasicVlmInformation:ImageBase & SizeOfImage (Win7/Vista)\r\n");
		         CloseHandle(hProcess);
		         return -7;
			 }
			 ImageBase = MBVI.ImageBase;
	         SizeOfImage = MBVI.SizeOfImage;
	}
	else  //2003/XP
	{
			 SizeOfImage = GetImageInfo(hProcess,EP,&ImageBase);
			 if(!SizeOfImage)
			 {
				 printf("Error Querying ProcessImageInformation: ImageBase & SizeOfImage(XP/2003)\r\n");
				 CloseHandle(hProcess);
				 return -8;
			 }
	}


	if(!ImageBase)
	{
			 printf("Error: Value of ImageBase is zero\r\n");
			 CloseHandle(hProcess);
			 return -9;
	}

	if(!SizeOfImage)
	{
		     printf("Error: Value of SizeOfImage is zero\r\n");
			 CloseHandle(hProcess);
			 return -10;
	}


	printf("Entry Point is %I64X\r\n",EP);
	printf("ImageBase is %I64X\r\n",ImageBase);	 
	printf("SizeOfImage is %I64X\r\n",SizeOfImage);
	


	lpMaximumApplicationAddress -= 0xFFF;
	//-----------------------------------------------
	wchar_t CurrDir[MAX_PATH+1]={0};
	GetCurrentDirectory(MAX_PATH,(wchar_t*)CurrDir);
	AppendBackSlash(CurrDir);
	wcscat((wchar_t*)CurrDir,L"Dump.dmp");
	
	HANDLE hOut=CreateFile((wchar_t*)CurrDir,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
	if(hOut == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hProcess);
		return 0;
	}
	//-----------------------------------------------
	ulonglong LastSize = 0;
	
	for(ulonglong i=0;i<lpMaximumApplicationAddress;i+=PageSize)
	{
		bool bIncludeDll = false;
		MEMORY_BASIC_INFORMATION MBI={0};
		if( VirtualQueryEx(hProcess,(void*)i,&MBI,sizeof(MBI)) )
		{
			LastSize = MBI.RegionSize;

			if(pDllToInclude)
			{
				if(MBI.Type == MEM_IMAGE)
				{
					if(MBI.AllocationBase != (void*)ImageBase)
					{
						ulong szToAlloc = 
						sizeof(_UNICODE_STRING)+(MAX_PATH*2);

						_UNICODE_STRING* pSectionName = (_UNICODE_STRING*)LocalAlloc(LMEM_ZEROINIT,szToAlloc);
						if(!pSectionName)
						{
							printf("Fatal Error while allocating section name memory\r\n");
							ExitProcess(0);
						}
						else
						{
							ulong retLen = 0;
							int ret_dll = ZwQueryVirtualMemory(hProcess,
													(void*)i,
													MemorySectionName,
													pSectionName,
													szToAlloc,
													&retLen);

							printf("=> ZwQueryVirtualMemory, ret: %X\r\n",ret_dll);
							if(ret_dll >= 0)
							{
								//wprintf(L"%s\r\n",pSectionName->Buffer);

								if(wcsstr(pSectionName->Buffer,pDllToInclude) )
								{
									bIncludeDll = true;
									wprintf(L"Including %s (Addr: %I64X, Size: %I64X)\r\n",pSectionName->Buffer,i,LastSize);
								}

							}

							LocalFree(pSectionName);
						}
					}
				}
			}

			if( 
				  ( (MBI.Type == MEM_IMAGE) && (MBI.AllocationBase==(void*)ImageBase) ) 
				||( (MBI.Type == MEM_IMAGE) && (bIncludeDll == true) ) 
				||(MBI.Type==MEM_PRIVATE) 
			  )
			{
				if(MBI.State==MEM_COMMIT)
				{
					
					void* pNew = VirtualAlloc(0,LastSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
	                if(!pNew)
					{
						printf("Error dumping Region: %x Region Size: %x\r\n",i,LastSize);
		                CloseHandle(hProcess);
		                return 0;
					}
					
					
					ulonglong BytesRead;
				    ReadProcessMemory(hProcess,(void*)i,pNew,LastSize,&BytesRead);
					WriteFile(hOut,pNew,LastSize,(ulong*)(&BytesRead),0);
					
					FlushFileBuffers(hOut);
					printf("Dumped %I64X bytes from %I64X\r\n",LastSize,i);

					if(pNew) VirtualFree(pNew,0,MEM_RELEASE);
					
					i+= (LastSize-PageSize);
				}
				else
				{
					i+= (LastSize-PageSize);
				}
			}
			else
			{
				i+= (LastSize-PageSize);
			}
		}
	}

	CloseHandle(hProcess);
	return 1;
}