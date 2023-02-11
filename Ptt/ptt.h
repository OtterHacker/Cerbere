#pragma once
#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//typedef NTSTATUS(NTAPI *pLsaConnectUntrusted)(PHANDLE LsaHandle);
//pLsaConnectUntrusted LsaConnectUntrusted;
