//
//	codesignextract.cpp
//
//	Validate + extract the Authenticode signature from a file (ex. EXE or DLL)
//
//	The MIT License
//
//	Copyright (c) 2018 pastdue  https://github.com/past-due/
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in
//	all copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//	THE SOFTWARE.
//
//

#include "stdafx.h"
#include "codesignextract.hpp"
#include <windows.h>
#include <Softpub.h>
#include <Strsafe.h>
#include <Wincrypt.h>


#if !defined(LOAD_LIBRARY_SEARCH_SYSTEM32)
#define LOAD_LIBRARY_SEARCH_SYSTEM32        0x00000800
#endif

// Safely load a system library
// Expectation: lpFileName is a filename
extern "C" HMODULE SafeLoadSystemLibrary(LPCTSTR lpFileName)
{
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32"));
	if (hKernel32 == NULL)
	{
		return NULL;
	}

	// Check for the presence of AddDllDirectory as a proxy for checking whether
	// the LoadLibraryEx LOAD_LIBARY_SEARCH_SYSTEM32 flag is supported.
	// On Windows 8+, support is built-in.
	// On Windows 7, Windows Server 2008 R2, Windows Vista and Windows Server 2008,
	// support is available if KB2533623 is installed.
	if (GetProcAddress(hKernel32, "AddDllDirectory") != NULL)
	{
		// LOAD_LIBARY_SEARCH_SYSTEM32 is available
		return LoadLibraryEx(lpFileName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	}
	else
	{
		// LOAD_LIBARY_SEARCH_SYSTEM32 is unavailable - attempt to create full path to system folder
		int fileNameLen = lstrlen(lpFileName);
		UINT sysDirLen = GetSystemDirectory(NULL, 0);
		if (sysDirLen == 0)
		{
			return NULL;
		}
		int totalStringLen = (sysDirLen + 1 + fileNameLen);
		TCHAR *sysDirStr = (TCHAR*)LocalAlloc(LPTR, totalStringLen * sizeof(TCHAR));
		if (sysDirStr == NULL)
		{
			return NULL;
		}
		if (GetSystemDirectory(sysDirStr, sysDirLen) == 0)
		{
			return NULL;
		}
		if (FAILED(StringCchCopy(sysDirStr + sysDirLen, totalStringLen - sysDirLen, _T("\\"))))
		{
			return NULL;
		}
		if (FAILED(StringCchCopy(sysDirStr + sysDirLen + 1, totalStringLen - sysDirLen - 1, lpFileName)))
		{
			return NULL;
		}
		HMODULE hModule = LoadLibraryEx(sysDirStr, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
		LocalFree(sysDirStr);
		return hModule;
	}
}


// TypeDefs for required WinAPI functions

// Wintrust.dll

typedef CRYPT_PROVIDER_DATA* (WINAPI *PWTHelperProvDataFromStateData)(
	HANDLE hStateData
	);

typedef CRYPT_PROVIDER_SGNR* (WINAPI *PWTHelperGetProvSignerFromChain)(
	CRYPT_PROVIDER_DATA *pProvData,
	DWORD idxSigner,
	BOOL fCounterSigner,
	DWORD idxCounterSigner
	);

typedef CRYPT_PROVIDER_CERT* (WINAPI *PWTHelperGetProvCertFromChain)(
	CRYPT_PROVIDER_SGNR *pSgnr,
	DWORD idxCert
	);

typedef LONG(WINAPI *PWinVerifyTrust)(
	HWND hWnd,
	GUID *pgActionID,
	LPVOID pWVTData
	);

// Crypt32.dll

typedef BOOL(WINAPI *PCertVerifyCertificateChainPolicy)(
	LPCSTR                    pszPolicyOID,
	PCCERT_CHAIN_CONTEXT      pChainContext,
	PCERT_CHAIN_POLICY_PARA   pPolicyPara,
	PCERT_CHAIN_POLICY_STATUS pPolicyStatus
	);

typedef DWORD(WINAPI *PCertGetNameString)(
	PCCERT_CONTEXT pCertContext,
	DWORD          dwType,
	DWORD          dwFlags,
	void           *pvTypePara,
	LPTSTR         pszNameString,
	DWORD          cchNameString
	);

// Verifies that a certificate chain ends in a Microsoft Root
static bool CertChainMicrosoftRootVerify(HMODULE hCrypt32Module,
	PCCERT_CHAIN_CONTEXT pChainContext)
{
	PCertVerifyCertificateChainPolicy Func_CertVerifyCertificateChainPolicy = (PCertVerifyCertificateChainPolicy)GetProcAddress(hCrypt32Module, "CertVerifyCertificateChainPolicy");
	if (Func_CertVerifyCertificateChainPolicy == NULL) return false;

	CERT_CHAIN_POLICY_PARA ChainPolicyPara;
	memset(&ChainPolicyPara, 0, sizeof(CERT_CHAIN_POLICY_PARA));
	ChainPolicyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
	ChainPolicyPara.dwFlags = 0;
	CERT_CHAIN_POLICY_STATUS ChainPolicyStatus;
	memset(&ChainPolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));

	if (Func_CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, pChainContext, &ChainPolicyPara, &ChainPolicyStatus) == TRUE)
	{
		// CertVerifyCertificateChainPolicy was able to check the policy
		// *Must* check ChainPolicyStatus.dwError to determine if the policy check was actually satisfied
		return ChainPolicyStatus.dwError == 0;
	}
	else
	{
		// CertVerifyCertificateChainPolicy failed to check the policy
		return false;
	}
}

// Calls CertGetNameString with the specified parameters, allocating an appropriately-sized buffer
// for the result. This buffer is then returned (if the calls were successful). NULL is returned on failure.
// The caller is responsible for calling LocalFree() on the return value (if non-NULL) once finished
static LPTSTR CertGetNameStringWrapper(PCertGetNameString Func_CertGetNameString,
	PCCERT_CONTEXT pCertContext,
	DWORD dwType,
	DWORD dwFlags,
	void *pvTypePara)
{
	int nLength = Func_CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);
	if (nLength <= 0)
	{
		// Unable to get the length of the issuer-name string
		return NULL;
	}

	TCHAR *strBuffer = (TCHAR*)LocalAlloc(LPTR, nLength * sizeof(TCHAR));
	if (strBuffer == NULL)
	{
		// LocalAlloc failed
		return NULL;
	}

	if (!Func_CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, strBuffer, nLength))
	{
		LocalFree(strBuffer);
		return NULL;
	}

	return strBuffer;
}

#ifdef UNICODE
#define _CertGetNameStringFunc "CertGetNameStringW"
#else
#define _CertGetNameStringFunc "CertGetNameStringA"
#endif

static EXTRACT_RESULT ExtractStateDetails(HMODULE hWinTrustModule,
	HMODULE hCrypt32Module,
	HANDLE hWVTStateData,
	SignatureDetails &output)
{
	PWTHelperProvDataFromStateData Func_WTHelperProvDataFromStateData = (PWTHelperProvDataFromStateData)GetProcAddress(hWinTrustModule, "WTHelperProvDataFromStateData");
	PWTHelperGetProvSignerFromChain Func_WTHelperGetProvSignerFromChain = (PWTHelperGetProvSignerFromChain)GetProcAddress(hWinTrustModule, "WTHelperGetProvSignerFromChain");
	PWTHelperGetProvCertFromChain Func_WTHelperGetProvCertFromChain = (PWTHelperGetProvCertFromChain)GetProcAddress(hWinTrustModule, "WTHelperGetProvCertFromChain");
	if (Func_WTHelperProvDataFromStateData == NULL) return ERROR_GETPROCADDRESSFAILURE;
	if (Func_WTHelperGetProvSignerFromChain == NULL) return ERROR_GETPROCADDRESSFAILURE;
	if (Func_WTHelperGetProvCertFromChain == NULL) return ERROR_GETPROCADDRESSFAILURE;

	PCertGetNameString Func_CertGetNameString = (PCertGetNameString)GetProcAddress(hCrypt32Module, _CertGetNameStringFunc);
	if (Func_CertGetNameString == NULL) return ERROR_GETPROCADDRESSFAILURE;

	CRYPT_PROVIDER_DATA *pCryptProvData = Func_WTHelperProvDataFromStateData(hWVTStateData);
	if (pCryptProvData == NULL) return ERROR_WTHELPERFAILED;
	CRYPT_PROVIDER_SGNR *pSigner = Func_WTHelperGetProvSignerFromChain(pCryptProvData, 0, FALSE, 0);
	if (pSigner == NULL) return ERROR_WTHELPERFAILED;

	// Check for Microsoft root
	output.hasMicrosoftRoot = CertChainMicrosoftRootVerify(hCrypt32Module, pSigner->pChainContext);

	CRYPT_PROVIDER_CERT *pCert = Func_WTHelperGetProvCertFromChain(pSigner, 0);
	if (pCert == NULL) return ERROR_WTHELPERFAILED;

	// Get Cert name
	LPTSTR retrieved_CertName = CertGetNameStringWrapper(Func_CertGetNameString, pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL);
	if (retrieved_CertName != NULL)
	{
		output.certName = retrieved_CertName;
		LocalFree(retrieved_CertName);
	}

	// Get Cert issuer name
	LPTSTR retrieved_IssuerName = CertGetNameStringWrapper(Func_CertGetNameString, pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL);
	if (retrieved_IssuerName != NULL)
	{
		output.certIssuerName = retrieved_IssuerName;
		LocalFree(retrieved_IssuerName);
	}

	return EXTRACT_OK;
}

EXTRACT_RESULT ExtractFileCodeSignatureDetails(const std::wstring &filePath,
	SignatureDetails &output)
{
	output.reset();

	if (filePath.empty()) return EXTRACT_OK;

	HMODULE hWinTrustModule = SafeLoadSystemLibrary(_T("wintrust.dll"));
	if (hWinTrustModule == NULL)
	{
		// Can't load wintrust.dll - bail!
		return ERROR_LOADLIBRARYFAILURE;
	}
	HMODULE hCrypt32Module = SafeLoadSystemLibrary(_T("Crypt32.dll"));
	if (hCrypt32Module == NULL)
	{
		// Can't load Crypt32.dll - bail!
		FreeLibrary(hWinTrustModule);
		return ERROR_LOADLIBRARYFAILURE;
	}

	PWinVerifyTrust Func_WinVerifyTrust = (PWinVerifyTrust)GetProcAddress(hWinTrustModule, "WinVerifyTrust");
	if (Func_WinVerifyTrust == NULL) return ERROR_GETPROCADDRESSFAILURE;

	GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WintrustData;
	WINTRUST_FILE_INFO FileInfo;

	memset(&WintrustData, 0, sizeof(WINTRUST_DATA));
	WintrustData.cbStruct = sizeof(WINTRUST_DATA);
	WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustData.dwUIChoice = WTD_UI_NONE;
	WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

	memset(&FileInfo, 0, sizeof(WINTRUST_FILE_INFO));
	FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileInfo.pcwszFilePath = filePath.c_str();
	WintrustData.pFile = &FileInfo;

	EXTRACT_RESULT extractResult = EXTRACT_OK;

	LONG trustResult = Func_WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	if (trustResult == 0)
	{
		// Verification succeeded
		output.hasValidSignature = true;

		// NOTES:
		// ExtractStateDetails retrieves information about the "current" signature - i.e. 
		// the signature that WinVerifyTrust validated - using the WTHelper* APIs.
		//
		// This works with multiple signatures. If, for example, a file has two code signatures:
		//	1.) 1st signature - invalid / untrusted
		//	2.) 2nd signature - valid & trusted
		// A single call to WinVerifyTrust will return "true" (since one of the signatures - the 2nd - is valid)
		// and the WintrustData.hWVTStateData will refer to the 2nd (valid) signature.
		//
		// Thus, the following will extract additional details of the signature that WinVerifyTrust verified.

		extractResult = ExtractStateDetails(hWinTrustModule, hCrypt32Module, WintrustData.hWVTStateData, output);
	}
	else
	{
		// WinVerifyTrust returned a failure code
		output.hasValidSignature = false;
		extractResult = ERROR_VERIFYTRUSTFAILURE;
	}

	FreeLibrary(hCrypt32Module);
	FreeLibrary(hWinTrustModule);

	return extractResult;
}
