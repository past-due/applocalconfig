// AppLocalConfig.cpp : Defines the entry point for the console application.
//
// This executable must not explicitly require the CRT for the "enable" functionality.
//
// Copyright (c) 2018 past-due - https://github.com/past-due/
// License: MIT (see LICENSE file).
//

#define _WIN32_WINNT 0x0501 // Windows XP+

#undef UNICODE
#define UNICODE

#if defined(_MSC_VER)
	// Disable run-time checks for debug builds (they require the CRT)
	#pragma runtime_checks( "", off ) 
#endif

#include <windows.h>
#include <Shellapi.h>
#include <Strsafe.h>
#include <Shlwapi.h>
#include "runtime_libs.h"

#define HELP_LINES_COUNT 8
static wchar_t helpLines[][250] = {
	L"applocalconfig.exe -help\n\n",
	L" Command-line options:\n",
	L"  -disablecrt\n",
	L"\tDisable the applocal CRT runtime, moving it into a subdirectory.\n",
	L"  -enablecrt\n",
	L"\tEnable the applocal CRT runtime, moving it from the subdirectory back into the application directory.\n",
	L"  -status\n",
	L"\tOutput the current applocal CRT status information.\n"
};

HANDLE hOutput = INVALID_HANDLE_VALUE;
bool isConsoleOutput = false;

static bool printOutString(LPCWSTR str)
{
	if (hOutput == INVALID_HANDLE_VALUE) return false;
	DWORD cWritten = 0;
	size_t stringLen = lstrlenW(str);
	if (isConsoleOutput) {
		if (WriteConsoleW(hOutput, str, stringLen, &cWritten, NULL) == 0) {
			// WriteConsole failed
			return false;
		}
	}
	else {
		if (!WriteFile(
			hOutput,                 // output handle 
			str,               // prompt string 
			stringLen,				 // string length 
			&cWritten,               // bytes written 
			NULL))                   // not overlapped 
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

static LPWSTR GetCurrentApplicationPath()
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

	// Trim filename
	for (int i = moduleFileNameLen; i >= 0; --i)
	{
		// Find rightmost "\" or "/" character
		if ((pBuffer[i] == L'\\') || (pBuffer[i] == L'/'))
		{
			pBuffer[i] = 0;
			break;
		}
	}
	return pBuffer;
}

enum APPLOCAL_CRT_STATUS
{
	INVALID,
	ENABLED,
	DISABLED,
	PARTIAL,
	MISSING
};

#define RUNTIME_DISABLED_PREFIX L"disabled_applocal_runtime\\"

static APPLOCAL_CRT_STATUS isAppLocalCRTEnabled(bool outputMissing = true)
{
	APPLOCAL_CRT_STATUS retValue = INVALID;
	int numEnabledFiles = 0;
	int numDisabledFiles = 0;
	int numMissingFiles = 0;
	wchar_t *pPathBuffer = NULL;
	LPWSTR pAppDir = GetCurrentApplicationPath();
	if (NULL == pAppDir) {
		printOutString(L"- Error: Failed to get current application path.\n");
		goto Cleanup;
	}

	pPathBuffer = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, WIN_MAX_EXTENDED_PATH * sizeof(wchar_t));
	if (NULL == pPathBuffer) {
		printOutString(L"- Error: Failed to allocate memory.\n");
		goto Cleanup;
	}

	for (int i = 0; i < RUNTIME_LIBS_COUNT; ++i) {
		const wchar_t *pFile = runtimeLibs[i];

		// check if (enabled) pFile exists in application directory
		if (FAILED(StringCchCopyW(pPathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) goto Cleanup;
		if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) goto Cleanup;
		if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, pFile))) goto Cleanup;
		if (GetFileAttributesW(pPathBuffer) != INVALID_FILE_ATTRIBUTES)
		{
			// enabled pFile exists
			numEnabledFiles++;
			continue;
		}
		
		// check if (disabled) pFile exists in application directory
		if (FAILED(StringCchCopyW(pPathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) goto Cleanup;
		if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) goto Cleanup;
		if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, RUNTIME_DISABLED_PREFIX))) goto Cleanup;
		if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, pFile))) goto Cleanup;
		if (GetFileAttributesW(pPathBuffer) != INVALID_FILE_ATTRIBUTES)
		{
			// disabled pFile exists
			numDisabledFiles++;
			continue;
		}

		if (outputMissing) {
			printOutString(L"\t- Missing file: ");
			printOutString(pFile);
			printOutString(L"\n");
		}
		numMissingFiles++;
	}

	if (numMissingFiles > 0) {
		retValue = MISSING;
	}
	else if (numDisabledFiles > 0) {
		if (numEnabledFiles == 0) retValue = DISABLED;
		else retValue = PARTIAL;
	}
	else if (numEnabledFiles > 0) {
		retValue = ENABLED;
	}
	else {
		// shouldn't reach here
		retValue = INVALID;
	}

Cleanup:
	if (pPathBuffer) HeapFree(GetProcessHeap(), 0, pPathBuffer);
	if (pAppDir) HeapFree(GetProcessHeap(), 0, pAppDir);

	return retValue;
}

static LPWSTR CreateAppLocalPath(LPCWSTR pFilename)
{
	wchar_t *pPathBuffer = NULL;
	LPWSTR pAppDir = GetCurrentApplicationPath();
	if (NULL == pAppDir) {
		printOutString(L"- Error: Failed to get current application path.\n");
		goto Cleanup;
	}

	pPathBuffer = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, WIN_MAX_EXTENDED_PATH * sizeof(wchar_t));
	if (NULL == pPathBuffer) {
		printOutString(L"- Error: Failed to allocate memory.\n");
		goto Cleanup;
	}

	if (FAILED(StringCchCopyW(pPathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) {
		HeapFree(GetProcessHeap(), 0, pPathBuffer);
		pPathBuffer = NULL;
		goto Cleanup;
	}
	if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) {
		HeapFree(GetProcessHeap(), 0, pPathBuffer);
		pPathBuffer = NULL;
		goto Cleanup;
	}
	if (FAILED(StringCchCatW(pPathBuffer, WIN_MAX_EXTENDED_PATH, pFilename))) {
		HeapFree(GetProcessHeap(), 0, pPathBuffer);
		pPathBuffer = NULL;
		goto Cleanup;
	}

Cleanup:
	if (pAppDir) HeapFree(GetProcessHeap(), 0, pAppDir);

	return pPathBuffer;
}

static bool setAppLocalCRT(bool enabled)
{
	bool retValue = false;
	int numAlreadySet = 0;
	int numSet = 0;
	int numMoveFailed = 0;
	wchar_t *pDesiredPathBuffer = NULL;
	wchar_t *pSourcePathBuffer = NULL;
	LPWSTR pAppDir = GetCurrentApplicationPath();
	if (NULL == pAppDir) {
		printOutString(L"- Error: Failed to get current application path.\n");
		goto Cleanup;
	}

	pDesiredPathBuffer = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, WIN_MAX_EXTENDED_PATH * sizeof(wchar_t));
	if (NULL == pDesiredPathBuffer) {
		printOutString(L"- Error: Failed to allocate memory.\n");
		goto Cleanup;
	}
	pSourcePathBuffer = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, WIN_MAX_EXTENDED_PATH * sizeof(wchar_t));
	if (NULL == pSourcePathBuffer) {
		printOutString(L"- Error: Failed to allocate memory.\n");
		goto Cleanup;
	}

	if (!enabled) {
		// Create disabled applocal runtime directory path
		if (FAILED(StringCchCopyW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) goto Cleanup;
		if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) goto Cleanup;
		if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, RUNTIME_DISABLED_PREFIX))) goto Cleanup;

		// Create disabled applocal runtime directory
		if (CreateDirectory(pDesiredPathBuffer, NULL) == 0 &&
			ERROR_ALREADY_EXISTS != GetLastError())
		{
			// failed to create directory
			printOutString(L"- Error: Failed to create disabled files directory: ");
			printOutString(pDesiredPathBuffer);
			printOutString(L"\n");
			goto Cleanup;
		}
	}

	for (int i = 0; i < RUNTIME_LIBS_COUNT; ++i)
	{
		const wchar_t *pFile = runtimeLibs[i];

		// Build the desired library path+name in the application directory
		if (FAILED(StringCchCopyW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) goto Cleanup;
		if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) goto Cleanup;
		if (!enabled) {
			if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, RUNTIME_DISABLED_PREFIX))) goto Cleanup;
		}
		if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, pFile))) goto Cleanup;

		// Desired library doesn't exist - try to move / rename the opposite-state library
		if (FAILED(StringCchCopyW(pSourcePathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) goto Cleanup;
		if (FAILED(StringCchCatW(pSourcePathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) goto Cleanup;
		if (enabled) {
			if (FAILED(StringCchCatW(pSourcePathBuffer, WIN_MAX_EXTENDED_PATH, RUNTIME_DISABLED_PREFIX))) goto Cleanup;
		}
		if (FAILED(StringCchCatW(pSourcePathBuffer, WIN_MAX_EXTENDED_PATH, pFile))) goto Cleanup;
	
		// When disabling, always overwrite the "disabled" CRT libraries with the current enabled libraries
		if (MoveFileExW(pSourcePathBuffer, pDesiredPathBuffer, (!enabled) ? MOVEFILE_REPLACE_EXISTING : 0) == 0)
		{
			// MoveFile failed
			DWORD errMoveFile = GetLastError();

			if ((ERROR_ALREADY_EXISTS == errMoveFile) && enabled) {
				// Did not move the file to the destination because the destination file already exists
				// Handle this as a special case (since it only affects enabling)
				printOutString(L"- Skipped disabled file \"");
				printOutString(pFile);
				printOutString(L"\" because the application directory already contains a file with that name. (Preferring existing applocal runtime file.)\n");
				// deliberately do NOT increment numMoveFailed, because this case isn't treated as an error
				continue;
			}

			const size_t DebugStrBufferLen = 128;
			wchar_t buffer[DebugStrBufferLen];
			wnsprintfW(buffer, 128, L"%u", errMoveFile);
			buffer[DebugStrBufferLen - 1] = 0; // ensure null-termination
			printOutString(L"- Unable to move file \"");
			printOutString(pFile);
			if (enabled) {
				printOutString(L"\" to application directory, with error: ");
			}
			else {
				printOutString(L"\" to disabled_applocal_runtime\\ subdirectory, with error: ");
			}
			printOutString(buffer);
			printOutString(L"\n");
			numMoveFailed++;
			continue;
		}

		numSet++;
	}

	if (enabled) {
		// Create disabled applocal runtime directory path
		if (FAILED(StringCchCopyW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, pAppDir))) goto Cleanup;
		if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, L"\\"))) goto Cleanup;
		if (FAILED(StringCchCatW(pDesiredPathBuffer, WIN_MAX_EXTENDED_PATH, RUNTIME_DISABLED_PREFIX))) goto Cleanup;

		// Remove the disabled applocal runtime directory if it's now empty
		RemoveDirectoryW(pDesiredPathBuffer);
	}

	if (numMoveFailed == 0) {
		retValue = true;
	}

Cleanup:
	if (pDesiredPathBuffer) HeapFree(GetProcessHeap(), 0, pDesiredPathBuffer);
	if (pSourcePathBuffer) HeapFree(GetProcessHeap(), 0, pSourcePathBuffer);
	if (pAppDir) HeapFree(GetProcessHeap(), 0, pAppDir);

	return retValue;
}

static bool printAppLocalCRTStatus(APPLOCAL_CRT_STATUS status)
{
	switch (status)
	{
	case INVALID:
		return printOutString(L"Unable to determine AppLocal CRT state.\n");
		break;
	case ENABLED:
		return printOutString(L"AppLocal CRT is present in application directory.\n");
		break;
	case DISABLED:
		return printOutString(L"AppLocal CRT is disabled (renamed) in application directory.\n");
		break;
	case PARTIAL:
		return printOutString(L"AppLocal CRT is partially enabled / disabled in application directory.\n");
		break;
	case MISSING:
		return printOutString(L"One or more AppLocal CRT components is missing from the application directory.\n");
		break;
	}
	return false;
}

enum APPLOCALVERIFY_RESULT
{
	APPLOCALVERIFY_SUCCESS = 0,
	APPLOCALVERIFY_DLL_NOT_FOUND,
	APPLOCALVERIFY_OTHERFAILURE,
};

static APPLOCALVERIFY_RESULT appLocalVerify(LPCWSTR fullAppLocalVerifyPath, LPCWSTR commandLineOptions, bool hideOutput = false)
{
	APPLOCALVERIFY_RESULT result = APPLOCALVERIFY_OTHERFAILURE;
	STARTUPINFO *pSI = (STARTUPINFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(STARTUPINFO));
	if (NULL == pSI)
	{
		// Failed to allocate memory
		printOutString(L"  - Error: Failed to allocate memory\n");
		goto Cleanup;
	}
	pSI->cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION *pPI = (PROCESS_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PROCESS_INFORMATION));
	if (NULL == pPI)
	{
		// Failed to allocate memory
		printOutString(L"  - Error: Failed to allocate memory\n");
		goto Cleanup;
	}

	wchar_t * pCommandLine = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (WIN_MAX_EXTENDED_PATH + 1) * sizeof(wchar_t));
	if (FAILED(StringCchCopyW(pCommandLine, WIN_MAX_EXTENDED_PATH, L"applocalverify.exe "))) goto Cleanup;
	if (FAILED(StringCchCatW(pCommandLine, WIN_MAX_EXTENDED_PATH, commandLineOptions))) goto Cleanup;

	SetErrorMode(SetErrorMode(0) | SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
	if (CreateProcessW(fullAppLocalVerifyPath, pCommandLine, NULL, NULL, TRUE, (hideOutput) ? CREATE_NO_WINDOW : 0, NULL, NULL, pSI, pPI) != 0)
	{
		// CreateProcess succeeded - wait for the child process to exit
		WaitForSingleObject(pPI->hProcess, INFINITE);

		// Get the exit code
		DWORD exitCode = 1;
		if (GetExitCodeProcess(pPI->hProcess, &exitCode) != 0)
		{
			// check the exit code
			if (exitCode == 0)
			{
				// printOutString(L"Executable code relying on the CRT will run successfully on this machine.\n");
				result = APPLOCALVERIFY_SUCCESS;
			}
			else if (exitCode == STATUS_DLL_NOT_FOUND)
			{
				// printOutString(L"WARNING: *CANNOT* run executables in this directory that rely on the CRT.");
				result = APPLOCALVERIFY_DLL_NOT_FOUND;
			}
			else
			{
				printOutString(L"  - Error: Failed to get details on loading CRT.\n");
				result = APPLOCALVERIFY_OTHERFAILURE;
			}
		}
		else
		{
			// GetExitCodeProcess failed
			printOutString(L"  - Error: GetExitCodeProcess failed.\n");
			result = APPLOCALVERIFY_OTHERFAILURE;
		}

		// Close process and thread handles. 
		CloseHandle(pPI->hProcess);
		CloseHandle(pPI->hThread);
	}
	else
	{
		const size_t DebugStrBufferLen = 128;
		wchar_t buffer[DebugStrBufferLen];
		wnsprintfW(buffer, 128, L"%u", GetLastError());
		buffer[DebugStrBufferLen - 1] = 0; // ensure null-termination
		printOutString(L"  - Error: CreateProcess failed: ");
		printOutString(buffer);
		printOutString(L"\n");
		result = APPLOCALVERIFY_OTHERFAILURE;
	}

Cleanup:
	if (pSI) HeapFree(GetProcessHeap(), 0, pSI);
	if (pPI) HeapFree(GetProcessHeap(), 0, pPI);
	if (pCommandLine) HeapFree(GetProcessHeap(), 0, pCommandLine);

	return result;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc <= 1) {
		outputHelp();
		return 0;
	}

	// process command-line options
	for (int i = 1; i < argc; ++i) {
		wchar_t *pArg = argv[i];
		if (lstrcmpiW(pArg, L"-help") == 0) {
			outputHelp();
			return 0;
		}
		else if (lstrcmpiW(pArg, L"-togglecrt") == 0) {
			APPLOCAL_CRT_STATUS currentStatus = isAppLocalCRTEnabled();
			switch (currentStatus)
			{
			case ENABLED:
				if (setAppLocalCRT(false)) {
					printOutString(L"SUCCESS: AppLocal CRT disabled (moved to subdirectory: \"disabled_applocal_runtime\\\").\n");
					return 0;
				}
				else {
					printOutString(L"Failed to disable applocal CRT.\n");
					return EXIT_FAILURE;
				}
				break;
			case DISABLED:
				if (setAppLocalCRT(true)) {
					printOutString(L"SUCCESS: AppLocal CRT enabled.\n");
					return 0;
				}
				else {
					printOutString(L"Failed to enable applocal CRT.\n");
					return EXIT_FAILURE;
				}
				break;
			case PARTIAL:
				// state is partially enabled, partially disabled - can't know which to toggle to - message user
				printOutString(L"Unable to toggle applocal CRT state - current state is mixed (partially enabled / disabled).\n");
				printOutString(L"Use -disablecrt or -enablecrt to set the desired state.\n");
				return EXIT_FAILURE;
			case MISSING:
				// required applocal crt files aren't present (either in enabled or disabled state) in the application dir
				// nothing much we can do
				printOutString(L"Required applocal CRT files are missing from the application directory. Re-install applocalconfig.\n");
				return EXIT_FAILURE;
			case INVALID:
				// fatal error determining status
				printOutString(L"Fatal error determining status.\n");
				return EXIT_FAILURE;
			}
		}
		else if (lstrcmpiW(pArg, L"-disablecrt") == 0) {
			APPLOCAL_CRT_STATUS currentStatus = isAppLocalCRTEnabled();
			if ((currentStatus == ENABLED) || (currentStatus == PARTIAL)) {
				if (setAppLocalCRT(false)) {
					printOutString(L"SUCCESS: AppLocal CRT disabled (renamed).\n");
					return 0;
				}
				else {
					printOutString(L"Failed to disable applocal CRT.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				printAppLocalCRTStatus(currentStatus);
				return 0;
			}
		}
		else if (lstrcmpiW(pArg, L"-enablecrt") == 0) {
			APPLOCAL_CRT_STATUS currentStatus = isAppLocalCRTEnabled();
			if ((currentStatus == DISABLED) || (currentStatus == PARTIAL)) {
				if (setAppLocalCRT(true)) {
					printOutString(L"SUCCESS: AppLocal CRT enabled.\n");
					return 0;
				}
				else {
					printOutString(L"Failed to enable applocal CRT.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				printAppLocalCRTStatus(currentStatus);
				return 0;
			}
		}
		else if (lstrcmpiW(pArg, L"-status") == 0) {
			// Get current applocal CRT state in the current application directory
			APPLOCAL_CRT_STATUS currentStatus = isAppLocalCRTEnabled();
			printAppLocalCRTStatus(currentStatus);

			// Attempt to run accompanying applocalverify.exe which links to and uses the CRT
			// and outputs the details of the applocal CRT configuration being used by executables in this dir
			// (Such as: the location + version of the CRT that's loaded - both the VCRT and the UCRT)

			wchar_t * pAppLocalVerifyPath = CreateAppLocalPath(L"applocalverify.exe");
			if (NULL != pAppLocalVerifyPath)
			{
				#if _MSC_VER >= 1900 && _MSC_VER <= 1920

					// For MSVC 14-15, independently output details on the two key libraries:
					//	# ucrtbase.dll
					//	# vcruntime140.dll

					bool ucrtbase_success = false;
					bool vcruntime140_success = false;

					printOutString(L"\n[ucrtbase.dll]\n");

					APPLOCALVERIFY_RESULT result = appLocalVerify(pAppLocalVerifyPath, L"-getmoduledetails ucrtbase.dll");
					switch (result)
					{
					case APPLOCALVERIFY_SUCCESS:
						ucrtbase_success = true;
						break;
					case APPLOCALVERIFY_DLL_NOT_FOUND:
						ucrtbase_success = false;
						printOutString(L"  - Unable to load\n");
						break;
					default:
						// other errors should have already output details
						break;
					}

					printOutString(L"\n[vcruntime140.dll]\n");

					result = appLocalVerify(pAppLocalVerifyPath, L"-getmoduledetails vcruntime140.dll");
					switch (result)
					{
					case APPLOCALVERIFY_SUCCESS:
						vcruntime140_success = true;
						break;
					case APPLOCALVERIFY_DLL_NOT_FOUND:
						vcruntime140_success = false;
						printOutString(L"  - Unable to load\n");
						break;
					default:
						// other errors should have already output details
						break;
					}

					if (ucrtbase_success && vcruntime140_success)
					{
						printOutString(L"\nLocal executables that load the CRT run successfully on this machine.\n");
					}
					else
					{
						printOutString(L"\nWARNING: Local executables that load the CRT do *NOT* run on this machine.\n");
					}

				#else
					// Need to evaluate for explicit support for newer MSVC versions
					// In the interim, since applocalverify is linked to the appropriate CRT, attempt to run it with -exit.
					APPLOCALVERIFY_RESULT result = appLocalVerify(pAppLocalVerifyPath, L"-exit", true);
					switch (result)
					{
					case APPLOCALVERIFY_SUCCESS:
						printOutString(L"\nLocal executables that load the CRT run successfully on this machine.\n");
						break;
					case APPLOCALVERIFY_DLL_NOT_FOUND:
						printOutString(L"\nWARNING: Local executables that load the CRT do *NOT* run on this machine.\n");
						break;
					default:
						// other errors should have already output details
						break;
					}
				#endif

				return 0;
			}
			
		}
		else {
			printOutString(L"Unknown parameter: ");
			printOutString(pArg);
			printOutString(L"\n");
			return EXIT_FAILURE;
		}
	}
	return 0;
}

int main()
{
	UINT inheritedErrorMode = SetErrorMode(0);
	SetErrorMode(inheritedErrorMode | SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

	hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOutput == INVALID_HANDLE_VALUE)
	{
		if ((inheritedErrorMode & SEM_FAILCRITICALERRORS) != SEM_FAILCRITICALERRORS)
		{
			MessageBoxW(NULL, L"No output handle detected. Cannot continue.", NULL, MB_ICONEXCLAMATION | MB_OK);
		}
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

	int result = wmain(args.n, args.p);

	ExitProcess(result);
	return result;
}
