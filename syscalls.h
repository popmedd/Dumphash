#pragma once
#pragma once

typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(*NTOPENPROCESS)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

typedef NTSTATUS(*NTDUPLICATEOBJECT)(
	HANDLE      SourceProcessHandle,
	HANDLE      SourceHandle,
	HANDLE      TargetProcessHandle,
	PHANDLE     TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG       HandleAttributes,
	ULONG       Options
);

typedef  NTSTATUS(*NTQUERYOBJECT)(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
	);

typedef  NTSTATUS(*NTCLOSE)(
	HANDLE Handle
	);

typedef NTSTATUS (*NTADJUSTPRIVILEGESTOTEKEN)(
	HANDLE TokenHandle,              
	BOOLEAN DisableAllPrivileges,    
	PTOKEN_PRIVILEGES NewState,     
	ULONG BufferLength,             
	PTOKEN_PRIVILEGES PreviousState,  
	PULONG ReturnLength              
);

typedef NTSTATUS(*RTLADJUSTPRIVILEGE)(
	ULONG Privilege,       
	BOOL Enable,          
	BOOL CurrentThread,   
	PBOOLEAN Enabled       
	);

typedef NTSTATUS(*NTDUPLICATETOKEN) 
(
	HANDLE ExistingToken,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE NewToken
	);

typedef NTSTATUS(*NTSETINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength
);


typedef NTSTATUS(*NTADJUSYPRIVILEGESTOKEN)(
	HANDLE TokenHandle,
	BOOLEAN DisableAllPrivileges,
	PTOKEN_PRIVILEGES TokenPrivileges,
	ULONG PreviousPrivilegesLength,
	PTOKEN_PRIVILEGES PreviousPrivileges,
	PULONG RequiredLength
	);

typedef NTSTATUS(*NTOPENPROCESSTOKEN)(
	HANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	PHANDLE TokenHandle
	);

typedef NTSTATUS(*NTQUERYINFORMATIONTOKEN)(
	HANDLE TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID TokenInformation,
	ULONG TokenInformationLength,
	PULONG ReturnLength
	);

typedef BOOL(WINAPI* fMiniDumpWriteDump)(
	HANDLE hProcess,
	DWORD ProcessId,
	HANDLE hFile,
	MINIDUMP_TYPE DumpType,
	PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	PMINIDUMP_CALLBACK_INFORMATION CallbackParam
	);