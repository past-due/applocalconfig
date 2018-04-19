// AppLocalVerify.cpp
//
// Verify properties of app-local libraries.
//
// Copyright (c) 2018 past-due - https://github.com/past-due/
// License: MIT (see LICENSE file).
// 

#undef UNICODE
#define UNICODE

#include "stdafx.h"
#include <Shlobj.h>
#include "runtime_libs.h"
#include "codesignextract.hpp"
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <memory>
#include <iterator>

#pragma comment(lib, "Version.lib")

#define HELP_LINES_COUNT 11
static wchar_t helpLines[][250] = {
	L" applocalverify.exe -help\n",
	L" Copyright (c) 2018 past-due - MIT License (https://github.com/past-due/applocalconfig)\n\n",
	L" Command-line options:\n",
	L"  -getmoduledetails <filename>\n",
	L"\tDisplay details about the library that's required by the executable.\n",
	L"  -getcrtdetails\n",
	L"\tDisplay details about the CRT libraries required & loaded by the executable.\n",
	L"  -getlocaldetails\n",
	L"\tDisplay details about all local libraries in the application folder.\n",
	L"  -exit\n",
	L"\tExit with exit code 0.\n"
};

HANDLE hOutput = INVALID_HANDLE_VALUE;
bool isConsoleOutput = false;

static bool printOutString(LPCWSTR str)
{
	if (hOutput == INVALID_HANDLE_VALUE) return false;
	DWORD cWritten = 0;
	size_t stringLen = wcslen(str);
	if (isConsoleOutput) {
		if (WriteConsoleW(hOutput, str, stringLen, &cWritten, NULL) == 0) {
			// WriteConsole failed
			return false;
		}
	}
	else {
		if (!WriteFile(
			hOutput,                // output handle 
			str,					// prompt string 
			stringLen,				// string length 
			&cWritten,              // bytes written 
			NULL))                  // not overlapped 
		{
			return false;
		}
	}
	return true;
}

static bool printOutString(const std::wstring &str)
{
	return printOutString(str.c_str());
}

static bool printOutStrings(const std::vector<std::wstring> &strings)
{
	for (const std::wstring &str : strings)
	{
		if (!printOutString(str + L"\n"))
		{
			return false;
		}
	}
	return true;
}

static bool outputHelp()
{
	for (int i = 0; i < HELP_LINES_COUNT; ++i)
	{
		if (!printOutString(helpLines[i])) return false;
	}

	return true;
}

#define WIN_MAX_EXTENDED_PATH 32767

static std::shared_ptr<std::wstring> GetCurrentApplicationFullFilePath()
{
	wchar_t *pBuffer = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (WIN_MAX_EXTENDED_PATH + 1) * sizeof(wchar_t));
	if (NULL == pBuffer) return NULL;
	DWORD moduleFileNameLen = GetModuleFileNameW(NULL, pBuffer, WIN_MAX_EXTENDED_PATH);
	DWORD lastError = GetLastError();
	if ((moduleFileNameLen == 0) && (lastError != ERROR_SUCCESS))
	{
		// GetModuleFileName failed
		HeapFree(GetProcessHeap(), 0, pBuffer);
		return NULL;
	}

	if (moduleFileNameLen > WIN_MAX_EXTENDED_PATH)
	{
		HeapFree(GetProcessHeap(), 0, pBuffer);
		return NULL;
	}

	// Because Windows XP's GetModuleFileName does not guarantee null-termination,
	// always append a null-terminator
	pBuffer[moduleFileNameLen] = 0;

	std::shared_ptr<std::wstring> pathString = std::make_shared<std::wstring>(pBuffer);

	if (pBuffer) HeapFree(GetProcessHeap(), 0, pBuffer);

	return pathString;
}

static std::shared_ptr<std::wstring> GetCurrentApplicationPath()
{
	std::shared_ptr<std::wstring> pCurrentApplicationFullPath = GetCurrentApplicationFullFilePath();
	if (!pCurrentApplicationFullPath) { return pCurrentApplicationFullPath; }

	size_t lastSlash = pCurrentApplicationFullPath->find_last_of(L"\\/", std::wstring::npos);
	if (lastSlash != std::wstring::npos)
	{
		return std::make_shared<std::wstring>(pCurrentApplicationFullPath->substr(0, lastSlash));
	}
	else
	{
		return pCurrentApplicationFullPath;
	}
}

static std::wstring GetModuleFullPath(HMODULE hModule)
{
	std::vector<wchar_t> pathBuffer(WIN_MAX_EXTENDED_PATH + 1);
	DWORD moduleFileNameLen = GetModuleFileNameW(hModule, &pathBuffer[0], pathBuffer.size());
	DWORD lastError = GetLastError();
	if ((moduleFileNameLen == 0) && (lastError != ERROR_SUCCESS))
	{
		// GetModuleFileName failed
		return std::wstring();
	}
	assert(pathBuffer.size() >= moduleFileNameLen);

	// Because Windows XP's GetModuleFileName does not guarantee null-termination,
	// always append a null-terminator
	pathBuffer[moduleFileNameLen] = 0;

	return std::wstring(&pathBuffer[0]);
}

static std::wstring GetModuleFullPath(const std::wstring &lpModuleName)
{
	HMODULE hModule = GetModuleHandleW(lpModuleName.c_str());
	if (NULL == hModule)
	{
		// Failed to get module handle by filename
		return std::wstring();
	}
	return GetModuleFullPath(hModule);
}

static VS_FIXEDFILEINFO GetFileFixedVersionInfo(const std::wstring &filePath)
{
	VS_FIXEDFILEINFO retValue = {0};
	DWORD verHandle = 0;
	DWORD verSize = GetFileVersionInfoSizeW(filePath.c_str(), &verHandle);
	if (0 != verSize)
	{
		void *pVerData = malloc(verSize);
		if (NULL != pVerData)
		{
			if (GetFileVersionInfoW(filePath.c_str(), 0, verSize, pVerData))
			{
				VS_FIXEDFILEINFO *pFileInfo = NULL;
				UINT puLenFileInfo = 0;
				if (VerQueryValueW(pVerData, L"\\", (LPVOID*)&pFileInfo, &puLenFileInfo))
				{
					if (puLenFileInfo >= sizeof(VS_FIXEDFILEINFO))
					{
						retValue = *pFileInfo;
					}
				}
			}
			free(pVerData);
		}
	}
	return retValue;
}

bool GetFileCodeSignatureDetails(const std::wstring &filePath, std::wstring &detailsString)
{
	detailsString.clear();
	SignatureDetails details;
	EXTRACT_RESULT result = ExtractFileCodeSignatureDetails(filePath, details);
	if (result == EXTRACT_OK) {
		if (details.hasValidSignature)
		{
			detailsString = L"Digital Signature:";
			if (!details.certName.empty()) {
				detailsString += L" (" + details.certName + L")";
			}
			else {
				detailsString += L" Valid";
			}
			if (details.hasMicrosoftRoot) {
				detailsString += L" [Microsoft Root]";
			}
			return true;
		}
		else {
			detailsString = L"Digital Signature: Invalid / Not-Present";
			return false;
		}
	}
	detailsString = L"Digital Signature: Failed to verify / extract";
	return false;
}

struct ModuleDetails
{
	std::wstring fullPath;
	VS_FIXEDFILEINFO fileVersionInfo = {0};
};

static ModuleDetails GetModuleDetails(const std::wstring &lpModuleName)
{
	ModuleDetails details;
	details.fullPath = GetModuleFullPath(lpModuleName);
	if (!details.fullPath.empty())
	{
		details.fileVersionInfo = GetFileFixedVersionInfo(details.fullPath);
	}
	return details;
}

struct FixedFileInfoStrings
{
	std::wstring FileVersion;
	std::wstring ProductVersion;
};

static FixedFileInfoStrings FixedFileInfoToStrings(const VS_FIXEDFILEINFO &verInfo)
{
	FixedFileInfoStrings output;
	std::vector<wchar_t> strBuffer(1024);
	swprintf_s(&strBuffer[0], strBuffer.size(), L"%d.%d.%d.%d",
		(verInfo.dwFileVersionMS >> 16) & 0xffff,
		(verInfo.dwFileVersionMS >> 0) & 0xffff,
		(verInfo.dwFileVersionLS >> 16) & 0xffff,
		(verInfo.dwFileVersionLS >> 0) & 0xffff
	);
	output.FileVersion = std::wstring(&strBuffer[0]);
	swprintf_s(&strBuffer[0], strBuffer.size(), L"%d.%d.%d.%d",
		(verInfo.dwProductVersionMS >> 16) & 0xffff,
		(verInfo.dwProductVersionMS >> 0) & 0xffff,
		(verInfo.dwProductVersionLS >> 16) & 0xffff,
		(verInfo.dwProductVersionLS >> 0) & 0xffff
	);
	output.ProductVersion = std::wstring(&strBuffer[0]);
	return output;
}

static std::unordered_set<std::wstring> GetSystemFolderLocations()
{
	std::unordered_set<std::wstring> systemFolderPaths;
	WCHAR szPath[MAX_PATH];

	// CSIDL_SYSTEM
	if (SUCCEEDED(SHGetFolderPathW(NULL,
		CSIDL_SYSTEM,
		NULL,
		SHGFP_TYPE_CURRENT,
		szPath)))
	{
		systemFolderPaths.insert(std::wstring(szPath));
	}

	// CSIDL_SYSTEMX86
	if (SUCCEEDED(SHGetFolderPathW(NULL,
		CSIDL_SYSTEMX86,
		NULL,
		SHGFP_TYPE_CURRENT,
		szPath)))
	{
		systemFolderPaths.insert(std::wstring(szPath));
	}

	return systemFolderPaths;
}

inline bool
isWindowsVersionOrGreater(DWORD dwMajorVersion, DWORD dwMinorVersion, WORD wServicePackMajor = 0)
{
	OSVERSIONINFOEXW versionInfo;
	memset(&versionInfo, 0, sizeof(versionInfo));
	versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
	DWORDLONG        const dwlConditionMask = 
		VerSetConditionMask(
			VerSetConditionMask(
				VerSetConditionMask(
					0, VER_MAJORVERSION, VER_GREATER_EQUAL
				),
				VER_MINORVERSION, VER_GREATER_EQUAL
			),
			VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL
		);

	versionInfo.dwMajorVersion = dwMajorVersion;
	versionInfo.dwMinorVersion = dwMinorVersion;
	versionInfo.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&versionInfo, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != 0;
}

inline bool isWindows8OrGreater()
{
	return isWindowsVersionOrGreater(6, 2);
}

typedef enum _ENUM_FILE_INFO_BY_HANDLE_CLASS {
	_FileBasicInfo = 0,
	_FileStandardInfo = 1,
	_FileNameInfo = 2,
	_FileRenameInfo = 3,
	_FileDispositionInfo = 4,
	_FileAllocationInfo = 5,
	_FileEndOfFileInfo = 6,
	_FileStreamInfo = 7,
	_FileCompressionInfo = 8,
	_FileAttributeTagInfo = 9,
	_FileIdBothDirectoryInfo = 10, // 0xA
	_FileIdBothDirectoryRestartInfo = 11, // 0xB
	_FileIoPriorityHintInfo = 12, // 0xC
	_FileRemoteProtocolInfo = 13, // 0xD
	_FileFullDirectoryInfo = 14, // 0xE
	_FileFullDirectoryRestartInfo = 15, // 0xF
	_FileStorageInfo = 16, // 0x10
	_FileAlignmentInfo = 17, // 0x11
	_FileIdInfo = 18, // 0x12
	_FileIdExtdDirectoryInfo = 19, // 0x13
	_FileIdExtdDirectoryRestartInfo = 20, // 0x14
	_MaximumFileInfoByHandlesClass
} __FILE_INFO_BY_HANDLE_CLASS, *__PFILE_INFO_BY_HANDLE_CLASS;

typedef BOOL (WINAPI *PGetFileInformationByHandleEx)(
	HANDLE                    hFile,
	__FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	LPVOID                    lpFileInformation,
	DWORD                     dwBufferSize
);

typedef struct __FILE_ID_128 {
	BYTE  Identifier[16];
} ___FILE_ID_128, *___PFILE_ID_128;

typedef struct __FILE_ID_INFO {
	ULONGLONG VolumeSerialNumber;
	__FILE_ID_128 FileId;
} ___FILE_ID_INFO, *___PFILE_ID_INFO;

static bool doFSHandlesPointToSameTarget(HANDLE h1, HANDLE h2)
{
	HMODULE hKernel32 = GetModuleHandleW(L"Kernel32.dll");
	assert(NULL != hKernel32);

	PGetFileInformationByHandleEx Func_GetFileInformationByHandleEx = (PGetFileInformationByHandleEx) GetProcAddress(hKernel32, "GetFileInformationByHandleEx");
	if (Func_GetFileInformationByHandleEx && isWindows8OrGreater())
	{
		// If GetFileInformationByHandleEx is available, *always* attempt to use it
		// on Windows 8+ (as Windows 8+ supports FileIdInfo).

		___FILE_ID_INFO info_h1 = { 0 };
		___FILE_ID_INFO info_h2 = { 0 };
		if (Func_GetFileInformationByHandleEx(h1, _FileIdInfo, &info_h1, sizeof(___FILE_ID_INFO)) == 0)
		{
			DWORD lastError = GetLastError();
			printOutString(L"GetFileInformationByHandleEx failed with error: " + std::to_wstring(lastError) + L"\n");
			return false;
		}
		if (Func_GetFileInformationByHandleEx(h2, _FileIdInfo, &info_h2, sizeof(___FILE_ID_INFO)) == 0)
		{
			DWORD lastError = GetLastError();
			printOutString(L"GetFileInformationByHandleEx failed with error: " + std::to_wstring(lastError) + L"\n");
			return false;
		}

		if (info_h1.VolumeSerialNumber != info_h2.VolumeSerialNumber) return false;
		for (size_t i = 0; i < 16; ++i)
		{
			if (info_h1.FileId.Identifier[i] != info_h2.FileId.Identifier[i]) return false;
		}
		return true;
	}

OlderAPI:
	// Fall-back to the older GetFileInformationByHandle
	BY_HANDLE_FILE_INFORMATION info_h1 = { 0 };
	BY_HANDLE_FILE_INFORMATION info_h2 = { 0 };
	if (GetFileInformationByHandle(h1, &info_h1) == 0) return false;
	if (GetFileInformationByHandle(h2, &info_h2) == 0) return false;

	return ((info_h1.dwVolumeSerialNumber == info_h2.dwVolumeSerialNumber) &&
		(info_h1.nFileIndexHigh == info_h2.nFileIndexHigh) &&
		(info_h1.nFileIndexLow == info_h2.nFileIndexLow));
}

static std::vector<HANDLE> GetSystemFolderHandles()
{
	std::vector<HANDLE> sysFolderHandles;
	std::unordered_set<std::wstring> systemPaths = GetSystemFolderLocations();
	for (const std::wstring &systemPath : systemPaths)
	{
		std::wstring cpy = systemPath;
		HANDLE hFolder = CreateFileW(systemPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (INVALID_HANDLE_VALUE != hFolder)
		{
			// check if it's the same as any existing handle in the list
			if (std::find_if(sysFolderHandles.begin(), sysFolderHandles.end(), [&hFolder](const HANDLE &hSysFolder) {
				return doFSHandlesPointToSameTarget(hFolder, hSysFolder);
			}) != sysFolderHandles.end())
			{
				// a handle to the same folder already exists in the list
				continue;
			}

			sysFolderHandles.push_back(hFolder);
		}
	}
	return sysFolderHandles;
}

static bool FolderContainsFile(HANDLE hFolder, const std::wstring &fullFilePath)
{
	std::wstring currentPathToExamine = fullFilePath;
	size_t lastSlash = currentPathToExamine.find_last_of(L"\\/", std::wstring::npos);
	while (lastSlash != std::wstring::npos) {
		currentPathToExamine = currentPathToExamine.substr(0, lastSlash);
		HANDLE hFolderToCheck = CreateFileW(currentPathToExamine.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (INVALID_HANDLE_VALUE != hFolderToCheck)
		{
			if (doFSHandlesPointToSameTarget(hFolderToCheck, hFolder))
			{
				CloseHandle(hFolderToCheck);
				return true;
			}
			CloseHandle(hFolderToCheck);
		}
		lastSlash = currentPathToExamine.find_last_of(L"\\/", std::wstring::npos);
	}
	return false;
}

static std::wstring GetPathLocationDescription(const std::wstring &fullPath, const std::wstring &appDir, const std::vector<HANDLE> &systemFolderHandles)
{
	std::wstring moduleLocation = L"Specific";

	// check if the module was loaded from the application directory or not
	if (fullPath.compare(0, appDir.length(), appDir) == 0)
	{
		// loaded the app-local library
		moduleLocation = L"AppLocal";
	}
	else
	{
		// the loaded library is *not* the app-local version - try to determine where it is

		for (const HANDLE &hSysFolder : systemFolderHandles)
		{
			if (FolderContainsFile(hSysFolder, fullPath))
			{
				// module fullpath starts with a system path
				moduleLocation = L"System";
				break;
			}
		}
	}

	return moduleLocation;
}

static std::wstring GetPathLocationDescription(const std::wstring &fullPath)
{
	std::wstring locationDescription;
	std::shared_ptr<std::wstring> pAppDir = GetCurrentApplicationPath();
	if (!pAppDir) {
		printOutString(L"- Error: Failed to get current application path.\n");
		return locationDescription;
	}
	std::wstring appDir(*pAppDir);
	std::vector<HANDLE> systemFolderHandles = GetSystemFolderHandles();
	locationDescription = GetPathLocationDescription(fullPath, appDir, systemFolderHandles);

	for (const HANDLE &hSysFolder : systemFolderHandles) { CloseHandle(hSysFolder); }

	return locationDescription;
}

static std::vector<std::wstring> GetCRTModulesDetails()
{
	std::vector<std::wstring> crtModuleDetails;

	wchar_t *pPathBuffer = NULL;
	std::shared_ptr<std::wstring> pAppDir = GetCurrentApplicationPath();
	if (!pAppDir) {
		printOutString(L"- Error: Failed to get current application path.\n");
		return crtModuleDetails;
	}
	std::wstring appDir(*pAppDir);
	std::vector<HANDLE> systemFolderHandles = GetSystemFolderHandles();

	for (int i = 0; i < RUNTIME_LIBS_COUNT; ++i) {
		const wchar_t *pFile = runtimeLibs[i];
		assert(pFile != NULL);
		std::wstring moduleName(pFile);

		ModuleDetails details = GetModuleDetails(moduleName);
		if (details.fullPath.empty())
		{
			// This module isn't loaded, but that's expected - some CRT modules are loaded as-needed
			// Just skip to the next
			continue;
		}

		std::wstring moduleLocation = GetPathLocationDescription(details.fullPath, appDir, systemFolderHandles);

		crtModuleDetails.push_back(L"[" + moduleLocation + L"]: " + moduleName);
		FixedFileInfoStrings fileInfoStrings = FixedFileInfoToStrings(details.fileVersionInfo);
		crtModuleDetails.push_back(L"  - File Version: " + fileInfoStrings.FileVersion + L"");
		crtModuleDetails.push_back(L"  - Module Path:  \"" + details.fullPath + L"\"");

		// Digital signature status
		std::wstring digitalSignatureDetails;
		if (GetFileCodeSignatureDetails(details.fullPath, digitalSignatureDetails))
		{
			crtModuleDetails.push_back(L"  - " + digitalSignatureDetails);
		}
	}

	// Cleanup
	for (const HANDLE &hSysFolder : systemFolderHandles) { CloseHandle(hSysFolder); }

	return crtModuleDetails;
}

bool endsWith(const std::wstring& a, const std::wstring& b) {
	if (b.size() > a.size()) return false;
	return std::equal(a.begin() + a.size() - b.size(), a.end(), b.begin());
}

static bool printLocalDetails(std::vector<std::wstring> fileExtensions = std::vector<std::wstring>{L"dll", L"ocx", L"sys"})
{
	std::shared_ptr<std::wstring> pAppDir = GetCurrentApplicationPath();
	if (!pAppDir) {
		printOutString(L"- Error: Failed to get current application path.\n");
		return false;
	}

	std::vector<std::wstring> fileExtensionsWithPeriod;
	std::transform(fileExtensions.begin(), fileExtensions.end(), std::back_inserter(fileExtensionsWithPeriod),
		[] (std::wstring extension) -> std::wstring {
		if (extension.length() > 0 && extension.front() != L'.')
		{
			extension = L"." + extension;
		}
		return extension;
	});

	WIN32_FIND_DATAW findData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Copy of directory path with a guaranteed "\" at the end
	std::wstring appDirWithSlash = *pAppDir;
	if (appDirWithSlash.back() != L'\\')
	{
		appDirWithSlash += L"\\";
	}

	// Append "\*" to the end of the directory path
	size_t pathLength = pAppDir->length();
	if (pathLength + 3 > WIN_MAX_EXTENDED_PATH) {
		// Resulting path is too long
		printOutString(L"\tPath is too long\n");
		return false;
	}
	std::wstring pathSearch = *pAppDir;
	if (pathSearch.back() == L'\\') {
		pathSearch += L"*";
	}
	else {
		pathSearch += L"\\*";
	}

	hFind = FindFirstFileW(pathSearch.c_str(), &findData);
	if (INVALID_HANDLE_VALUE == hFind) {
		// FindFirstFile failed
		printOutString(L"\t +FindFirstFile failed\n");
		return false;
	}

	do {
		if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			bool endsWithIncludedExtension = false;
			for (const auto & fileExtension : fileExtensionsWithPeriod) {
				if (endsWith(findData.cFileName, fileExtension)) {
					endsWithIncludedExtension = true;
					break;
				}
			}
			
			if (endsWithIncludedExtension) {
				std::wstring fullFilePath = appDirWithSlash + findData.cFileName;
				printOutString(findData.cFileName + std::wstring(L"\n"));

				// Get version info
				VS_FIXEDFILEINFO fixedFileInfo = GetFileFixedVersionInfo(fullFilePath);
				FixedFileInfoStrings fileInfoStrings = FixedFileInfoToStrings(fixedFileInfo);
				printOutString(L"  - File Version: " + fileInfoStrings.FileVersion + L"\n");

				// Get digital signature info
				std::wstring digitalSignatureDetails;
				if (GetFileCodeSignatureDetails(fullFilePath, digitalSignatureDetails))
				{
					printOutString(L"  - " + digitalSignatureDetails + L"\n");
				}
			}
		}
	} while (FindNextFile(hFind, &findData) != 0);

	FindClose(hFind);

	return true;
}

int __wmain(int argc, wchar_t* argv[])
{
	if (argc <= 1) {
		outputHelp();
		return 0;
	}

	// process command-line options
	for (int i = 1; i < argc; ++i) {
		const wchar_t *pArg = argv[i];
		if (_wcsicmp(pArg, L"-help") == 0) {
			outputHelp();
			return 0;
		}
		else if (_wcsicmp(pArg, L"-exit") == 0) {
			return 0;
		}
		else if (_wcsicmp(pArg, L"-getmoduledetails") == 0) {
			// next command-line option should be the filename
			if (i + 1 < argc)
			{
				const wchar_t *pFilename = argv[++i];
				ModuleDetails details = GetModuleDetails(pFilename);
				if (!details.fullPath.empty())
				{
					printOutString(L"  - Loaded Location: " + GetPathLocationDescription(details.fullPath) + L"\n");
					printOutString(L"  - Module Path: " + details.fullPath + L"\n");
					FixedFileInfoStrings fileInfoStrings = FixedFileInfoToStrings(details.fileVersionInfo);
					printOutString(L"  - File Version: " + fileInfoStrings.FileVersion + L"\n");
					std::wstring digitalSignatureDetails;
					GetFileCodeSignatureDetails(details.fullPath, digitalSignatureDetails);
					printOutString(L"  - " + digitalSignatureDetails + L"\n");
					return 0;
				}
				else
				{
					// failed to get details
					printOutString(L"Failed to get module details for: \"");
					printOutString(pFilename);
					printOutString(L"\"\n");
					return EXIT_FAILURE;
				}

			}
			else
			{
				// missing required next parameter (filename)
				printOutString(L"Missing required filename for -getmoduledetails option. Command-line should be: -getmoduledetails <filename>\n");
				return EXIT_FAILURE;
			}
		}
		else if (_wcsicmp(pArg, L"-getcrtdetails") == 0) {
			// get module details for CRT
			std::vector<std::wstring> crtDetailsLines = GetCRTModulesDetails();
			printOutStrings(crtDetailsLines);
		}
		else if (_wcsicmp(pArg, L"-getlocaldetails") == 0) {
			if (!printLocalDetails()) {
				printOutString(L"Failed to getlocaldetails");
				return EXIT_FAILURE;
			}
		}
		else {
			printOutString(std::wstring(L"Unknown parameter: ") + pArg + L"\n");
			return EXIT_FAILURE;
		}
	}
	return 0;
}

int main()
{
	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOutput == INVALID_HANDLE_VALUE)
	{
		ExitProcess(EXIT_FAILURE);
		return EXIT_FAILURE;
	}
	DWORD _unusedMode = 0;
	isConsoleOutput = GetConsoleMode(hOutput, &_unusedMode) != 0;

	struct Args
	{
		int n;
		wchar_t** p;
	
		~Args() { if (p != 0) { LocalFree(p); } }
		Args()
			: p(NULL)
		{
			LPWSTR pCommandLine = GetCommandLineW();
			p = CommandLineToArgvW(pCommandLine, &n);
		}
	};

	Args args;
	if (args.p == 0) {
		ExitProcess(EXIT_FAILURE);
		return EXIT_FAILURE;
	}

	int result = __wmain(args.n, args.p);

	ExitProcess(result);
	return result;
}
