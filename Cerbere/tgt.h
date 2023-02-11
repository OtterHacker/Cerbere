#pragma once
#include <windows.h>
#include "asn1.h"

#define VALIDATE  0x00000001
#define RENEW  0x00000002
#define UNUSED29  0x00000004
#define ENCTKTINSKEY  0x00000008
#define RENEWABLEOK  0x00000010
#define DISABLETRANSITEDCHECK  0x00000020
#define UNUSED16  0x0000FFC0
#define CONSTRAINED_DELEGATION  0x00020000
#define CANONICALIZE  0x00010000
#define CNAMEINADDLTKT  0x00004000
#define OK_AS_DELEGATE  0x00040000
#define REQUEST_ANONYMOUS  0x00008000
#define UNUSED12  0x00080000
#define OPTHARDWAREAUTH  0x00100000
#define PREAUTHENT  0x00200000
#define INITIAL  0x00400000
#define RENEWABLE  0x00800000
#define UNUSED7  0x01000000
#define POSTDATED  0x02000000
#define ALLOWPOSTDATE  0x04000000
#define PROXY  0x08000000
#define PROXIABLE  0x10000000
#define FORWARDED  0x20000000
#define FORWARDABLE  0x40000000
#define RESERVED  0x80000000


#define AS_REQ 10
#define AS_REP 11
#define TGS_REQ 12
#define TGS_REP 13
#define AP_REQ 14
#define AP_REP 15
#define TGT_REQ 16 // KRB-TGT-REQUEST for U2U
#define TGT_REP 17 // KRB-TGT-REPLY for U2U
#define SAFE 20
#define PRIV 21
#define CRED 22
#define ERROR 30


typedef struct _ASREQ {
	int pvno;
	int messageType;
	char* cname;
	char* realm;
	char* sname;
	time_t from;
	size_t till; // offset
	time_t rtime;
	int nonce;
	int etype;
	unsigned char* hostAddress;
	int kdcoptions;
	char* username;
	char* domain;
	char* password;
	char* service;
	char* resource;
	char* dcIp;
} ASREQ;

void initASREQ(ASN* asn);
void addPvno(ASREQ* asreq, ASN* asn);
void addMsgType(ASREQ* asreq, ASN* asn);
void initPadata(ASN* asn, int size);
void addEncTimestamp(ASREQ* asreq, ASN* asn);
void addPacRequest(ASREQ* asreq, ASN* asn);
void initKdcReqBody(ASN *asn);
void addKdcOptions(ASREQ *asreq, ASN *asn);
void addCname(ASREQ* asreq, ASN* asn);
void addRealm(ASREQ* asreq, ASN* asn);
void addPrincipalName(ASREQ* asreq, ASN* asn);
void addExpirationDate(ASREQ* asreq, ASN* asn);
void addNonce(ASREQ* asreq, ASN* asn);
void addEtype(ASREQ* asreq, ASN* asn);
void handleASREP(ASREQ* asreq, ASN* asreqAsn, PBYTE response, int responseSize);
char* lookupKrbErrorCode(int errorCode);

