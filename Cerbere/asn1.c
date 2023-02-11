#include "asn1.h"
#include <windows.h>
#include "math.h"

size_t getAsnSize(ASN* asn, int includeLengthByte) {
	size_t result = 0;
	if (!asn->isAsnContent) {
		result += asn->contentSize;
	}
	else {
		ASN* currentAsn = asn->asnContent;
		while (currentAsn->tag != 0) {
			result += getAsnSize(currentAsn, 1);
			currentAsn += 1;
		}
	}

	if (includeLengthByte) {
		if (result > 127) {
			result += (((int)log2(result) + 1) / 8 + (((int)log2(result) + 1) % 8 != 0)) & 0b01111111;
		}
		result += 2;
	}

	return result;

}

void asn2byte(ASN* asn, unsigned char** result, size_t* size, size_t* pointer) {
	if (!asn || asn->tag == 0) { return; }
	if (!(*result)) {
		*pointer = 0;
		size_t asn_size = getAsnSize(asn, 1);
		*result = calloc(asn_size, sizeof(unsigned char));
		if (!(*result)) {
			printf("[x] Failed to allocate ASN byte array\n");
			exit(-1);
		}

		if (size) {
			*size = asn_size;
		}
	}

	(*result)[*pointer] = asn->tag;
	*pointer += 1;
	size_t asn_size = getAsnSize(asn, 0);

	if (asn_size < 128) {
		(*result)[*pointer] = asn_size;
		*pointer += 1;
	}
	else {
		int overflow = (((int)log2(asn_size) + 1) / 8 + (((int)log2(asn_size) + 1) % 8 != 0)) & 0b01111111;
		(*result)[*pointer] = 0b10000000 | overflow;
		*pointer += 1;
		int size = htonl(asn_size);
		int i = 0;
		while (i < 4 && *((char*)(&size) + i) == 0) { i += 1; }
		for (int j = 0; j < 4 - i; j++) {
			CopyMemory(&(*result)[*pointer+j], (char*)(&size) + i + j, sizeof(char));
		}
		//CopyMemory(&(*result)[*pointer], &asn_size, overflow * sizeof(unsigned char));
		*pointer += overflow;
	}
	if (!asn->isAsnContent) {
		CopyMemory(&(*result)[*pointer], asn->content, asn->contentSize * sizeof(unsigned char));
		*pointer += asn->contentSize;
		asn = NULL;
	}
	else {
		ASN* currentAsn = asn->asnContent;
		while (currentAsn->tag) {
			asn2byte(currentAsn, result, NULL, pointer);
			currentAsn += 1;
		}

	}

	// add a recursive call on asn->next here if multiple Application needed
}

void printAsn(ASN* asn) {
	unsigned char* asnByte = NULL;
	size_t size = 0;
	size_t pointer = 0;
	asn2byte(asn, &asnByte, &size, &pointer);
	for (int i = 0; i < size; i++) {
		printf("%02x", asnByte[i]);
	}
	printf("\n");
}

void addChild(ASN* parent, ASN* child) {
	ASN* currentAsn = parent->asnContent;
	int i = 0;
	while (currentAsn->tag) {
		currentAsn += 1;
		i += 1;
	}
	*currentAsn = *child;
}

void newInteger(ASN* asn, int value) {

	int networkValue = htonl(value);
	int i = 0;
	while (i < 4 && *((char*)(&networkValue) + i) == 0) { i += 1; }

	asn->tag = INTEGER;
	asn->isAsnContent = 0;
	if (value == 0) {
		asn->content = calloc(1, sizeof(char));
		asn->contentSize = 1;
		return;
	}
	asn->content = calloc(4 - i, sizeof(char));
	if (!asn->content) {
		printf("[x] Failed to allocate new integer ASN buffer\n");
		exit(-1);
	}
	asn->contentSize = 4 - i;

	for (int j = 0; j < 4 - i; j++) {
		CopyMemory(asn->content + j, (char*)(&networkValue) + i + j, sizeof(char));
	}
}

int getInteger(ASN* asn) {
	int result = 0;
	for (int i = 0; i < asn->contentSize; i++) {
		result = (result >> 8) + asn->content[i];
	}
	return result;
}

int isAsnContent(PBYTE asnByte, int parentSize) {
	PBYTE pointer = asnByte;
	pointer++;
	int length = *pointer;
	pointer++;
	int headerSize = 2;

	if (length > 0x80) {
		int additionalLengthByte = length - 0x80;
		headerSize += additionalLengthByte;
		if (additionalLengthByte + 2 >= parentSize) {
			return 0;
		}

		length = 0;
		for (int i = 0; i < additionalLengthByte; i++) {
			length = length << 8;
			length += *pointer;
			pointer++;
		}
	}

	if (length + headerSize > parentSize || length <= 0) {
		return 0;
	}
	if (length + headerSize == parentSize) {
		return 1;
	}

	int childSize = 0;

	while (childSize < length) {
		headerSize = 2;
		pointer++;
		int lengthChild = *pointer;
		pointer++;

		if (length > 0x80) {
			int additionalLengthByte = lengthChild - 0x80;
			headerSize += additionalLengthByte;
			if (additionalLengthByte + 2 >= length) {
				return 0;
			}

			lengthChild = 0;
			for (int i = 0; i < additionalLengthByte; i++) {
				lengthChild = lengthChild << 8;
				lengthChild += *pointer;
				pointer++;
			}
		}
		childSize += lengthChild + headerSize;
		pointer += lengthChild;
	}

	if (childSize != length) {
		return 0;
	}

	return 1;
}

PBYTE byte2asn(PBYTE asnByte, ASN* asn, int parentSize) {
	PBYTE pointer = asnByte;

	int tag = *pointer;
	pointer++;
	int length = *pointer;
	pointer++;

	if (length > 0x80) {
		int additionalLengthByte = length - 0x80;
		length = 0;
		for (int i = 0; i < additionalLengthByte; i++) {
			length = length << 8;
			length += *pointer;
			pointer++;
		}
	}

	asn->tag = tag;
	asn->isAsnContent = isAsnContent(pointer, length);
	//printf("Tag : %02x  -  isAsnContent : %d\n", asn->tag, asn->isAsnContent);

	if (asn->isAsnContent) {
		asn->asnContent = calloc(1, sizeof(ASN));
		if (!asn->asnContent) {
			printf("[x] Cannot allocate ASN ASN content element\n");
			exit(-1);
		}

		int i = 2;
		PBYTE endAddress = pointer + length;
		while (pointer != endAddress) {
			ASN* tmp = calloc(i, sizeof(ASN));
			if (!tmp) {
				printf("[x] Failed to reallocate ASN ASN content buffer");
				exit(-1);
			}
			for (int j = 0; j < i-1; j++) {
				tmp[j] = asn->asnContent[j];
			}
			free(asn->asnContent);
			asn->asnContent = tmp;
			
			ZeroMemory(asn->asnContent + i - 1, sizeof(ASN));
			PBYTE childPointer = pointer;
			pointer = byte2asn(childPointer, &asn->asnContent[i-2], length);
			i++;
		}
	}
	else {
		asn->content = calloc(length, sizeof(unsigned char));
		if (!asn->content) {
			printf("[x] Failed to allocate ASN content element\n");
			exit(-1);
		}
		CopyMemory(asn->content, pointer, length * sizeof(unsigned char));
		asn->contentSize = length;
		pointer += length;
	}
	
	return pointer;
}

int getListElementByIndex(ASN* asn, int element, ASN* result) {
	ASN* asnContent = asn->asnContent;
	while (asnContent->tag != 0) {
		if (asnContent->tag == (LIST | element)) {
			*result = *asnContent;
			return 1;
		}
		asnContent++;
	}
	result = NULL;
	return 0;
}


