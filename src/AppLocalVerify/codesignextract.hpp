#pragma once
#ifndef ___CODE_SIGN_EXTRACT__HPP___
#define ___CODE_SIGN_EXTRACT__HPP___

#include <string>

enum EXTRACT_RESULT {
	EXTRACT_OK = 0,
	ERROR_LOADLIBRARYFAILURE,
	ERROR_VERIFYTRUSTFAILURE,
	ERROR_GETPROCADDRESSFAILURE,
	ERROR_WTHELPERFAILED,
	ERROR_CERTDETAILFETCHFAILED
};

struct SignatureDetails {
	std::wstring certName;
	std::wstring certIssuerName;
	bool hasMicrosoftRoot = false;
	bool hasValidSignature = false;

	inline void reset() {
		certName.clear();
		certIssuerName.clear();
		hasMicrosoftRoot = false;
		hasValidSignature = false;
	}
};

EXTRACT_RESULT ExtractFileCodeSignatureDetails(const std::wstring &filePath,
	SignatureDetails &output);

#endif//!___CODE_SIGN_EXTRACT__HPP___
