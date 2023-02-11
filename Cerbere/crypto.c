#include "crypto.h"
#include "time.h"
#include "asn1.h"

void loadCryptoFunctions() {
	HMODULE crypt = LoadLibraryA("CRYPTDLL");
	if (!crypt) {
		printf("[x] Failed to load CRYPTDLL module\n");
		exit(-1);
	}

	CDLocateCSystem = GetProcAddress(crypt, "CDLocateCSystem");
	if (!CDLocateCSystem) {
		printf("[x] Failed to load CDLocateCSystem\n");
		exit(-1);
	}

	HMODULE ntdll = GetModuleHandleA("NTDLL");
	if (!ntdll) {
		printf("[x] Failed to load NTDLL module\n");
		exit(-1);
	}

	RtlInitUnicodeString = GetProcAddress(ntdll, "RtlInitUnicodeString");
	if (!RtlInitUnicodeString) {
		printf("[x] Failed to load RtlInitUnicodeString\n");
		exit(-1);
	}

	RtlInitAnsiString = GetProcAddress(ntdll, "RtlInitAnsiString");
	if (!RtlInitAnsiString) {
		printf("[x] Failed to load RtlInitAnsiString\n");
		exit(-1);
	}

	RtlAnsiStringToUnicodeString = GetProcAddress(ntdll, "RtlAnsiStringToUnicodeString");
	if (!RtlAnsiStringToUnicodeString) {
		printf("[x] Failed to load RtlAnsiStringToUnicodeString\n");
		exit(-1);
	}
}

void char2unicode(char* source, UNICODE_STRING* result) {
	STRING ansiPassword;
	UNICODE_STRING unicodePassword;

	RtlInitAnsiString(&ansiPassword, source);
	RtlAnsiStringToUnicodeString(result, &ansiPassword, 1);
}

void get_key_rc4(char* password, PBYTE* hash, size_t* size) {
	NTSTATUS status;
	PKERB_ECRYPT pCSystem;
	PVOID pContext;

	status = CDLocateCSystem(RC4_HMAC, &pCSystem);
	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to call CDLocateCSystem\n");
		exit(-1);
	}
	*size = pCSystem->KeySize;

	STRING ansiPassword;
	UNICODE_STRING unicodePassword;
	UNICODE_STRING Salt;

	char2unicode(password, &unicodePassword);
	//RtlInitAnsiString(&ansiPassword, password);
	//RtlAnsiStringToUnicodeString(&unicodePassword, &ansiPassword, 1);
	RtlInitUnicodeString(&Salt, L"");

	*hash = calloc(pCSystem->KeySize, sizeof(char));
	pCSystem->HashPassword_NT6(&unicodePassword, &Salt, 4096, *hash);
	pCSystem->Finish(&pContext);
}

void get_key_aes256(char* domain, char* username, char* password, PBYTE* hash, size_t* size) {
	NTSTATUS status;
	PKERB_ECRYPT pCSystem;
	PVOID pContext;

	status = CDLocateCSystem(AES256_CTS_HMAC_SHA1, &pCSystem);
	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to call CDLocateCSystem\n");
		exit(-1);
	}
	*size = pCSystem->KeySize;

	char* salt = calloc(strlen(domain) + strlen(username), sizeof(char));
	if (!salt) {
		printf("[x] Failed to allocate salt buffer\n");
		exit(-1);
	}
	for (int i = 0; i < strlen(domain); i++) {
		salt[i] = toupper(domain[i]);
	}
	strcpy(&salt[strlen(domain)], username);

	STRING ansiPassword;
	STRING ansiSalt;
	UNICODE_STRING unicodePassword;
	UNICODE_STRING unicodeSalt;

	//RtlInitAnsiString(&ansiPassword, password);
	//RtlAnsiStringToUnicodeString(&unicodePassword, &ansiPassword, 1);
	char2unicode(password, &unicodePassword);

	//RtlInitAnsiString(&ansiSalt, salt);
	//RtlAnsiStringToUnicodeString(&unicodeSalt, &ansiSalt, 1);
	char2unicode(salt, &unicodeSalt);

	*hash = calloc(pCSystem->KeySize, sizeof(char));
	pCSystem->HashPassword_NT6(&unicodePassword, &unicodeSalt, 4096, *hash);

}

void decrypt(PBYTE key, DWORD eType, DWORD keyUsage, PBYTE data, size_t dataSize, PBYTE* result, size_t* size) {
	PKERB_ECRYPT pCSystem;
	PVOID pContext;
	NTSTATUS status;

	status = CDLocateCSystem(eType, &pCSystem);
	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to call CDLocateCSystem\n");
		exit(-1);
	}

	status = pCSystem->Initialize(key, pCSystem->KeySize, keyUsage, &pContext);
	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to initialize crypto system\n");
		exit(-1);
	}
	*result = calloc(dataSize, sizeof(unsigned char));
	*size = dataSize;
	status = pCSystem->Decrypt(pContext, data, dataSize, *result, size);
}

void get_enc_timestamp(PBYTE key, DWORD eType, PBYTE* result, size_t* size) {
	PKERB_ECRYPT pCSystem;
	PVOID pContext;
	NTSTATUS status;

	status = CDLocateCSystem(eType, &pCSystem);
	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to call CDLocateCSystem\n");
		exit(-1);
	}

	status = pCSystem->Initialize(key, pCSystem->KeySize, KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pContext);
	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to initialize crypto system\n");
		exit(-1);
	}

	char data[16];
	time_t timestamp = time(NULL);
	struct tm* pTime = gmtime(&timestamp);
	strftime(data, 16, "%Y%m%d%H%M%SZ", pTime);

	ASN encTimeSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN encTimeElement = {
		.tag = LIST | 0,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	encTimeSequence.asnContent[0] = encTimeElement;

	ASN encTime = {
		.tag = GENERALIZED_TIME,
		.isAsnContent = 0,
		.content = data,
		.contentSize = strlen(data)
	};

	encTimeElement.asnContent[0] = encTime;

	size_t nil = 0;
	PBYTE plainData = NULL;
	asn2byte(&encTimeSequence, &plainData, size, &nil);

	DWORD dataSize = *size;
	DWORD modulo = *size % pCSystem->BlockSize;
	if (modulo) {
		*size += pCSystem->BlockSize - modulo;
	}
	*size += pCSystem->HeaderSize;
	*result = calloc(*size, sizeof(char));
	status = pCSystem->Encrypt(pContext, plainData, dataSize, *result, size);


	if (!NT_SUCCESS(status)) {
		printf("[x] Failed to encrypt data\n");
		exit(-1);
	}

	pCSystem->Finish(&pContext);
	return 0;
}