#pragma once
#include <windows.h>

#define ASN_BOOLEAN 0x01
#define INTEGER 0x02
#define BIT_STRING 0x03
#define OCTET_STRING 0x04
#define GENERALIZED_TIME 0x18
#define GENERAL_STRING 0x1B
#define SEQUENCE 0x30
#define APPLICATION 0x60
#define LIST 0xA0

typedef struct _ASN {
	int tag;
	int isAsnContent;
	union {
		struct _ASN* asnContent;
		unsigned char* content;
	};
	size_t contentSize;
}ASN;

size_t getAsnSize(ASN* asn, int includeLengthByte);
void asn2byte(ASN* asn, unsigned char** result, size_t* size, size_t* pointer);
void printAsn(ASN* asn);
void addChild(ASN* parent, ASN* child);
void newInteger(ASN* asn, int value);
int isAsnContent(PBYTE pointer, int parentSize);
PBYTE byte2asn(PBYTE asnByte, ASN* asn, int parentSize);
int getListElementByIndex(ASN* asn, int element, ASN* result);