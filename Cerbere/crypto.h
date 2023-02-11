#pragma once
#include <windows.h>
#include "NtSecAPI.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define DES_CBC_CRC  1
#define DES_CBC_MD4  2
#define DES_CBC_MD5  3
#define DES3_CBC_MD5  5
#define DES3_CBC_SHA1 7
#define DSA_WITH_SHA1_CMSOID 9
#define MD5_WITH_RSA_ENCRYPTION_CMSOID 10
#define SHA1_WITH_RSA_ENCRYTPTION_CMSOID 11
#define RC2_CBC_ENVOID 12
#define RSA_ENCRYPTION_ENVOID 13
#define tRSAES_OAEP_ENV_OID 14
#define DES_EDE3_CBC_ENV_OID 15
#define DES3_CBC_SHA1_KD 16
#define AES128_CTS_HMAC_SHA1 17
#define AES256_CTS_HMAC_SHA1 18
#define RC4_HMAC 23
#define RC4_HMAC_EXP 24
#define SUBKEY_KEYMATERIAL 65
#define OLD_EXP -135

#define KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP       1
#define KRB_KEY_USAGE_AS_REP_TGS_REP				2
#define KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY			3
#define KRB_KEY_USAGE_AS_REQ_AUTHORIZATION_SESSION	4
#define KRB_KEY_USAGE_AS_DATA_ENCRYPTED_NO_SPEC		16

typedef CONST UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);


typedef NTSTATUS(WINAPI* pRtlInitAnsiString)(STRING* DestinationString, char* SourceString);
typedef NTSTATUS(WINAPI* pRtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, STRING* SourceString, BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

pRtlInitAnsiString RtlInitAnsiString;
pRtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString;
pRtlInitUnicodeString RtlInitUnicodeString;



typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, * PKERB_ECRYPT;


typedef NTSTATUS(WINAPI* pCDLocateCSystem)(ULONG Type, PKERB_ECRYPT* ppCSystem);
pCDLocateCSystem CDLocateCSystem;

void char2unicode(char* source, UNICODE_STRING* result);

void loadCryptoFunctions();
void get_key_rc4(char* password, PBYTE* hash, size_t* size);
void get_key_aes256(char* domain, char* username, char* password, PBYTE* hash, size_t* size);
void get_enc_timestamp(PBYTE key, DWORD eType, PBYTE* result, size_t* size);

void decrypt(PBYTE key, DWORD eType, DWORD keyUsage, PBYTE data, size_t dataSize, PBYTE* result, size_t* size);	