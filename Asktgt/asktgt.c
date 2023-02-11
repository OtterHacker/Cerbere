#define _CRT_SECURE_NO_WARNINGS
#include "asktgt.h"
#include "handleArgs.h"
#include "windows.h"
#include "asn1.h"
#include "tgt.h"
#include "time.h"
#include "crypto.h"
#include "network.h"

void buildASREQ() {
	ASN asn;
	ASREQ asreq = {
		.pvno = 5,
		.messageType = 10,
		.password = "Password@123!",
		.kdcoptions = FORWARDABLE | RENEWABLE | RENEWABLEOK,
		.cname = "chen",
		.realm = "KANTO.LAB",
		.service = "krbtgt",
		.resource = "KANTO.LAB",
		.till = 4*3600, //valid for 4h
		.dcIp = "10.253.1.2",
		.etype = RC4_HMAC,
	};
	initASREQ(&asn);
	addPvno(&asreq, &asn);
	addMsgType(&asreq, &asn);

	//KDC-REQ
	initPadata(&asn, 2);
	addEncTimestamp(&asreq, &asn);
	addPacRequest(&asreq, &asn);


	//KDC-BODY
	initKdcReqBody(&asn);
	addKdcOptions(&asreq, &asn);
	addCname(&asreq, &asn);
	addRealm(&asreq, &asn);
	addPrincipalName(&asreq, &asn);
	addExpirationDate(&asreq, &asn);
	addNonce(&asreq, &asn);
	addEtype(&asreq, &asn);

	printf("[+] ASREQ request : ");
	printAsn(&asn);

	size_t pointer = 0;
	size_t size = 0;
	char* result = NULL;
	PBYTE response = NULL;
	int responseSize = 0;
	asn2byte(&asn, &result, &size, &pointer);
	sendBytes(asreq.dcIp, "88", result, size, &response, &responseSize);
	
	printf("[+] KDC response : ");
	for (int i = 0; i < responseSize; i++) {
		printf("%02x", response[i]);
	}
	printf("\n");
	handleASREP(&asreq, &asn, response, responseSize);
	return;
}

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
int main(int argc, char** argv) {
	loadCryptoFunctions();
	buildASREQ();
	return 0;

	ASN asn = {
		.tag = APPLICATION | 10,
		.isAsnContent = 1,
		.asnContent = calloc(100, sizeof(ASN)),
	};
	ASN asnContent = {
		.tag = INTEGER,
		.content = "\x06",
		.isAsnContent = 0,
		.contentSize = 1,
	};
	addChild(&asn, &asnContent);

	size_t pointer = 0;
	size_t size = 0;
	char* result = NULL;
	PBYTE response = NULL;
	int responseSize = 0;
	asn2byte(&asn, &result, &size, &pointer);
	printAsn(&asn);
	ASN resultAsn;
	byte2asn(result, &resultAsn, size);
	printAsn(&resultAsn);

	return 0;
	//Args* args;
	//handleArgs(argc, argv, &args);
	//
	//ASN asn = {
	//.tag = APPLICATION | 10,
	//.isAsnContent = 1,
	//.asnContent = calloc(100, sizeof(ASN)),
	//};
	//
	//ASN asnContent = {
	//	.tag = INTEGER,
	//	.content = "\x06",
	//	.isAsnContent = 0,
	//	.contentSize = 1,
	//};
	//
	//ASN asnContent1 = {
	//.tag = INTEGER,
	//.content = "\x10",
	//.isAsnContent = 0,
	//.contentSize = 1,
	//};
	//
	//for (int i = 0; i < 65; i++) {
	//	asn.asnContent[i] = asnContent;
	//}
	//
	//unsigned char* asnByte = NULL;
	//size_t size = 0;
	//size_t pointer = 0;
	//asn2byte(&asn, &asnByte, &size, &pointer);
	//for (int i = 0; i < size; i++) {
	//	printf("%02x", asnByte[i]);
	//}

	return 0;
}
