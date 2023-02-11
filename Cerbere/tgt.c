#include "tgt.h"
#include "crypto.h"
#include "time.h"

void initASREQ(ASN* asn) {
	ASN application = {
		.tag = APPLICATION | AS_REQ ,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN)),
	};

	ASN kdcreq = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(5, sizeof(ASN)),
	};
	addChild(&application, &kdcreq);
	*asn = application;
}

void addPvno(ASREQ* asreq, ASN* asn) {
	ASN pvnoElement = {
		.tag = LIST | 1,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN)),
	};

	ASN pvno;
	newInteger(&pvno, asreq->pvno);

	addChild(&pvnoElement, &pvno);
	addChild(&asn->asnContent[0], &pvnoElement);
}

void addMsgType(ASREQ* asreq, ASN* asn) {
	ASN messageTypeElement = {
		.tag = LIST | 2,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN)),
	};
	ASN messageType;
	newInteger(&messageType, asreq->messageType);
	addChild(&messageTypeElement, &messageType);
	addChild(&asn->asnContent[0], &messageTypeElement);
}

void initPadata(ASN* asn, int size) {
	ASN padataElement = {
		.tag = LIST | 3,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN)),
	};

	ASN wrapperSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(size+1, sizeof(ASN))
	};
	addChild(&padataElement, &wrapperSequence);
	addChild(&asn->asnContent[0], &padataElement);
}

void addEncTimestamp(ASREQ* asreq, ASN* asn) {
	ASN padataSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(3, sizeof(ASN))
	};

	ASN typeElement = {
		.tag = LIST | 1,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	
	ASN valueElement = {
		.tag = LIST | 2,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	
	addChild(&padataSequence, &typeElement);
	addChild(&padataSequence, &valueElement);
	
	ASN type;
	newInteger(&type, 0x02);
	addChild(&typeElement, &type);
	
	ASN value = {
		.tag = OCTET_STRING,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&valueElement, &value);
	
	ASN encTimestampSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(3, sizeof(ASN))
	};
	addChild(&value, &encTimestampSequence);

	ASN encTypeElement = {
		.tag = LIST | 0,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&encTimestampSequence, &encTypeElement);
	
	ASN encType;
	newInteger(&encType, asreq->etype);
	addChild(&encTypeElement, &encType);
	
	ASN encValueElement = {
		.tag = LIST | 2,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&encTimestampSequence, &encValueElement);

	// a modifier
	ASN encValue = {
		.tag = OCTET_STRING,
		.isAsnContent = 0,
	};
	

	PBYTE key = NULL;
	size_t keySize;
	get_key_rc4(asreq->password, &key, &keySize);
	get_enc_timestamp(key, RC4_HMAC, &encValue.content, &encValue.contentSize);

	addChild(&encValueElement, &encValue);

	// Get the padata storage unit in the global ASREQ ASN
	addChild(&asn->asnContent[0].asnContent[2].asnContent[0], &padataSequence);
}


void addPacRequest(ASREQ* asreq, ASN* asn) {
	ASN padataSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(3, sizeof(ASN))
	};

	ASN typeElement = {
		.tag = LIST | 1,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN valueElement = {
		.tag = LIST | 2,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	addChild(&padataSequence, &typeElement);
	addChild(&padataSequence, &valueElement);

	ASN type;
	newInteger(&type, 0x8000);
	addChild(&typeElement, &type);

	ASN value = {
		.tag = OCTET_STRING,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&valueElement, &value);

	ASN pacRequestSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&value, &pacRequestSequence);

	ASN pacRequestElement = {
		.tag = LIST | 0,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&pacRequestSequence, &pacRequestElement);

	ASN pacRequest = {
		.tag = ASN_BOOLEAN,
		.isAsnContent = 0,
		.content = "\x01",
		.contentSize = 1
	};
	addChild(&pacRequestElement, &pacRequest);
	
	// Get the padata storage unit in the global ASREQ ASN
	addChild(&asn->asnContent[0].asnContent[2].asnContent[0], &padataSequence);

}

void initKdcReqBody(ASN* asn) {
	ASN bodyElement = {
		.tag = LIST | 4,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN bodySequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(8, sizeof(ASN))
	};
	
	addChild(&bodyElement, &bodySequence);
	addChild(&asn->asnContent[0], &bodyElement);
}

void addKdcOptions(ASREQ* asreq, ASN* asn) {
	ASN optionsElement = {
		.tag = LIST | 0,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN option = {
		.tag = BIT_STRING,
		.isAsnContent = 0,
		.content = calloc(6, sizeof(char)),
		.contentSize = 6
	};

	int kdcOptionsValue = htonl(asreq->kdcoptions);
	CopyMemory(option.content+1, &kdcOptionsValue, sizeof(int));

	addChild(&optionsElement, &option);
	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &optionsElement);
}

void addCname(ASREQ* asreq, ASN* asn) {
	ASN cnameElement = {
		.tag = LIST | 1,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN cnameSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(3, sizeof(ASN))
	};
	addChild(&cnameElement, &cnameSequence);

	ASN typeElement = {
		.tag = LIST | 0,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&cnameSequence, &typeElement);

	ASN type;
	newInteger(&type, 0x01);
	addChild(&typeElement, &type);

	ASN valueElement = {
		.tag = LIST | 1,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&cnameSequence, &valueElement);
	
	ASN valueSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&valueElement, &valueSequence);

	ASN value = {
		.tag = GENERAL_STRING,
		.isAsnContent = 0,
		.content = asreq->cname,
		.contentSize = strlen(asreq->cname)
	};
	addChild(&valueSequence, &value);

	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &cnameElement);
}

void addRealm(ASREQ* asreq, ASN* asn) {
	ASN realmElement = {
		.tag = LIST | 2,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN realm = {
		.tag = GENERAL_STRING,
		.isAsnContent = 0,
		.content = asreq->realm,
		.contentSize = strlen(asreq->realm),
	};
	addChild(&realmElement, &realm);

	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &realmElement);
}

void addPrincipalName(ASREQ* asreq, ASN* asn) {
	ASN principalElement = {
		.tag = LIST | 3,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN principalSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(3, sizeof(ASN))
	};
	addChild(&principalElement, &principalSequence);
	
	ASN typeElement = {
		.tag = LIST | 0,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&principalSequence, &typeElement);

	ASN type;
	newInteger(&type, 0x02);
	addChild(&typeElement, &type);

	ASN valueElement = {
		.tag = LIST | 1,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN)),
	};
	addChild(&principalSequence, &valueElement);

	ASN valueSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(3, sizeof(ASN))
	};
	addChild(&valueElement, &valueSequence);

	ASN valueService = {
		.tag = GENERAL_STRING,
		.isAsnContent = 0,
		.content = asreq->service,
		.contentSize = strlen(asreq->service)
	};
	addChild(&valueSequence, &valueService);

	ASN valueResource = {
		.tag = GENERAL_STRING,
		.isAsnContent = 0,
		.content = asreq->resource,
		.contentSize = strlen(asreq->resource)
	};
	addChild(&valueSequence, &valueResource);

	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &principalElement);
}

void addExpirationDate(ASREQ* asreq, ASN* asn) {
	ASN expirationElement = {
		.tag = LIST | 5,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN)),
	};

	char data[17];
	time_t timestamp = time(NULL) + asreq->till;
	struct tm* pTime = gmtime(&timestamp);
	strftime(data, 16, "%Y%m%d%H%M%SZ", pTime);

	ASN expirationValue = {
		.tag = GENERALIZED_TIME,
		.isAsnContent = 0,
		.content = calloc(strlen(data), sizeof(char)),
		.contentSize = strlen(data)
	};

	CopyMemory(expirationValue.content, data, strlen(data));
	addChild(&expirationElement, &expirationValue);

	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &expirationElement);

}

void addNonce(ASREQ* asreq, ASN* asn) {
	ASN nonceElement = {
		.tag = LIST | 7,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN nonce;
	newInteger(&nonce, 0x04030201);

	addChild(&nonceElement, &nonce);
	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &nonceElement);
}

void addEtype(ASREQ* asreq, ASN* asn) {
	ASN etypeElement = {
		.tag = LIST | 8,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};

	ASN etypeSequence = {
		.tag = SEQUENCE,
		.isAsnContent = 1,
		.asnContent = calloc(2, sizeof(ASN))
	};
	addChild(&etypeElement, &etypeSequence);

	ASN etype;
	newInteger(&etype, asreq->etype);
	addChild(&etypeSequence, &etype);
	addChild(&asn->asnContent[0].asnContent[3].asnContent[0], &etypeElement);
}


int getKerberosErrorCode(ASN* asn) {
	ASN* elements = asn->asnContent[0].asnContent;
	while (elements->tag != 0) {
		if (elements->tag == (LIST | 6)) {
			return getInteger(elements->asnContent[0]);
		}
		elements++;
	}
}

char* lookupKrbErrorCode(int errorCode) {
	char* KERBEROS_ERROR[0x5E] = {
		"KDC_ERR_NONE (0x0) - No error",
		"KDC_ERR_NAME_EXP (0x1) - Client's entry in KDC database has expired",
		"KDC_ERR_SERVICE_EXP (0x2) - Server's entry in KDC database has expired",
		"KDC_ERR_BAD_PVNO (0x3) - Requested Kerberos version number not supported",
		"KDC_ERR_C_OLD_MAST_KVNO (0x4) - Client's key encrypted in old master key",
		"KDC_ERR_S_OLD_MAST_KVNO (0x5) - Server's key encrypted in old master key",
		"KDC_ERR_C_PRINCIPAL_UNKNOWN (0x6) - Client not found in Kerberos database",
		"KDC_ERR_S_PRINCIPAL_UNKNOWN (0x7) - Server not found in Kerberos database",
		"KDC_ERR_PRINCIPAL_NOT_UNIQUE (0x8) - Multiple principal entries in KDC database",
		"KDC_ERR_NULL_KEY (0x9) - The client or server has a null key (master key)",
		"KDC_ERR_CANNOT_POSTDATE (0xA) - Ticket (TGT) not eligible for postdating",
		"KDC_ERR_NEVER_VALID (0xB) - Requested start time is later than end time",
		"KDC_ERR_POLICY (0xC) - Requested start time is later than end time",
		"KDC_ERR_BADOPTION (0xD) - KDC cannot accommodate requested option",
		"KDC_ERR_ETYPE_NOTSUPP (0xE) - KDC has no support for encryption type",
		"KDC_ERR_SUMTYPE_NOSUPP (0xF) - KDC has no support for checksum type",
		"KDC_ERR_PADATA_TYPE_NOSUPP (0x10) - KDC has no support for PADATA type (pre-authentication data)",
		"KDC_ERR_TRTYPE_NO_SUPP (0x11) - KDC has no support for transited type",
		"KDC_ERR_CLIENT_REVOKED (0x12) - Client's credentials have been revoked",
		"KDC_ERR_SERVICE_REVOKED (0x13) -Credentials for server have been revoked",
		"KDC_ERR_TGT_REVOKED (0x14) - TGT has been revoked",
		"KDC_ERR_CLIENT_NOTYET (0x15) - Client not yet valid—try again later",
		"KDC_ERR_SERVICE_NOTYET (0x16) -Server not yet valid—try again later",
		"KDC_ERR_KEY_EXPIRED (0x17) - Password has expired—change password to reset",
		"KDC_ERR_PREAUTH_FAILED (0x18) - Pre-authentication information was invalid",
		"KDC_ERR_PREAUTH_REQUIRED (0x19) - Additional preauthentication required",
		"KDC_ERR_SERVER_NOMATCH (0x1A) - KDC does not know about the requested server",
		"KDC_ERR_MUST_USE_USER2USER (0x1B) - Server principal valid for user2user only",
		"KDC_ERR_PATH_NOT_ACCEPTED (0x1C) - KDC Policy rejects transited path",
		"KDC_ERR_SVC_UNAVAILABLE (0x1D) - KDC is unavailable",
		"KRB_UNKNOWN (0x1E) - Code unknown",
		"KRB_AP_ERR_BAD_INTEGRITY (0x1F) - Integrity check on decrypted field failed",
		"KRB_AP_ERR_TKT_EXPIRED (0x20) - The ticket has expired",
		"KRB_AP_ERR_TKT_NYV (0x21) - The ticket is not yet valid",
		"KRB_AP_ERR_REPEAT (0x22) - The request is a replay",
		"KRB_AP_ERR_NOT_US (0x23) - The ticket is not for us",
		"KRB_AP_ERR_BADMATCH (0x24) -The ticket and authenticator do not match",
		"KRB_AP_ERR_SKEW (0x25) - The clock skew is too great",
		"KRB_AP_ERR_BADADDR (0x26) - Network address in network layer header doesn't match address inside ticket",
		"KRB_AP_ERR_BADVERSION (0x27) - Protocol version numbers don't match (PVNO)",
		"KRB_AP_ERR_MSG_TYPE (0x28) - Message type is unsupported",
		"KRB_AP_ERR_MODIFIED (0x29) - Message stream modified and checksum didn't match",
		"KRB_AP_ERR_BADORDER (0x2A) - Message out of order (possible tampering)",
		"KRB_UNKNOWN (0x2B) - Code unknown",
		"KRB_AP_ERR_BADKEYVER (0x2C) - Specified version of key is not available",
		"KRB_AP_ERR_NOKEY (0x2D) - Service key not available",
		"KRB_AP_ERR_MUT_FAIL (0x2E) - Mutual authentication failed",
		"KRB_AP_ERR_BADDIRECTION (0x2F) - Incorrect message direction",
		"KRB_AP_ERR_METHOD (0x30) - Alternative authentication method required",
		"KRB_AP_ERR_BADSEQ (0x31) - Incorrect sequence number in message",
		"KRB_AP_ERR_INAPP_CKSUM (0x32) - Inappropriate type of checksum in message (checksum may be unsupported)",
		"KRB_AP_PATH_NOT_ACCEPTED (0x33) - Desired path is unreachable",
		"KRB_ERR_RESPONSE_TOO_BIG (0x34) - Too much data",
		"KRB_UNKNOWN (0x15) - Code unknown",
		"KRB_UNKNOWN (0x16) - Code unknown",
		"KRB_UNKNOWN (0x17) - Code unknown",
		"KRB_UNKNOWN (0x18) - Code unknown",
		"KRB_UNKNOWN (0x19) - Code unknown",
		"KRB_UNKNOWN (0x1A) - Code unknown",
		"KRB_UNKNOWN (0x1B) - Code unknown",
		"KRB_ERR_GENERIC (0x3C) - Generic error; the description is in the e-data field",
		"KRB_ERR_FIELD_TOOLONG (0x3D) - Field is too long for this implementation",
		"KDC_ERR_CLIENT_NOT_TRUSTED (0x3E) - The client trust failed or is not implemented",
		"KDC_ERR_KDC_NOT_TRUSTED (0x3F) - The KDC server trust failed or could not be verified",
		"KDC_ERR_INVALID_SIG (0x40) - The signature is invalid",
		"KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED (0x41) - KDC policy has determined the provided Diffie-Hellman key parameters are not acceptable",
		"KDC_ERR_CERTIFICATE_MISMATCH (0x42) - certificate doesn't match client user",
		"KRB_AP_ERR_NO_TGT (0x43) - No TGT was presented or available",
		"KDC_ERR_WRONG_REALM (0x44) -Incorrect domain or principal",
		"KRB_AP_ERR_USER_TO_USER_REQUIRED (0x45) - Ticket must be for USER-TO-USER",
		"KDC_ERR_CANT_VERIFY_CERTIFICATE (0x46)",
		"KDC_ERR_INVALID_CERTIFICATE (0x47)",
		"KDC_ERR_REVOKED_CERTIFICATE (0x48)",
		"KDC_ERR_REVOCATION_STATUS_UNKNOWN (0x49)",
		"KRB_UNKNOWN (0x4A) - Code unknown",
		"KDC_ERR_CLIENT_NAME_MISMATCH (0x4B)",
		"KDC_ERR_KDC_NAME_MISMATCH (0x4C)",
		"KDC_ERR_INCONSISTENT_KEY_PURPOSE (0x4D) - The client certificate does not contain the KeyPurposeId EKU and is required",
		"KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED (0x4E) - The signature algorithm used to sign the CA certificate is not accepted",
		"KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED (0x4F) - The client did not include the required paChecksum parameter",
		"KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED (0x50) - The signature algorithm used to sign the request is not accepted",
		"KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED (0x51) - The KDC does not support public key encryption for PKINIT",
		"KRB_AP_ERR_PRINCIPAL_UNKNOWN (0x52) - A well-known Kerberos principal name is used but not supported",
		"KRB_AP_ERR_REALM_UNKNOWN (0x53) - A well-known Kerberos realm name is used but not supported",
		"KRB_AP_ERR_PRINCIPAL_RESERVED (0x54) - A reserved Kerberos principal name is used but not supported",
		"KRB_UNKNOWN (0x55) - Code unknown",
		"KRB_UNKNOWN (0x56) - Code unknown",
		"KRB_UNKNOWN (0x57) - Code unknown",
		"KRB_UNKNOWN (0x58) - Code unknown",
		"KRB_UNKNOWN (0x59) - Code unknown",
		"KDC_ERR_PREAUTH_EXPIRED (0x5A) - The provided pre-auth data has expired",
		"KDC_ERR_MORE_PREAUTH_DATA_REQUIRED (0x5B) - The KDC found the presented pre-auth data incomplete and requires additional information",
		"KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET (0x5C) - The client sent an authentication set that the KDC was not expecting",
		"KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS (0x5D) - The provided FAST options that were marked as critical are unknown to the KDC and cannot be processed"
	};
	return KERBEROS_ERROR[errorCode];
}

void buildKrbCredInfo(ASN* KDCRep, ASN* asreq, ASN* credInfo) {
	ASN* asn = &KDCRep->asnContent[0];
	ASN kdcReqBody;
	getListElementByIndex(&asreq->asnContent[0], 4, &kdcReqBody);
	kdcReqBody = kdcReqBody.asnContent[0];

	credInfo->tag = SEQUENCE;
	credInfo->isAsnContent = 1;
	credInfo->asnContent = calloc(12, sizeof(ASN));
	if (!credInfo->asnContent) {
		printf("[x] Failed to allocate cred info content\n");
		exit(-1);
	}

	ASN key;
	getListElementByIndex(asn, 0, &key);
	key.tag = LIST | 0;
	addChild(credInfo, &key);

	ASN realm;
	getListElementByIndex(&kdcReqBody, 2, &realm);
	realm.tag = LIST | 1;
	addChild(credInfo, &realm);
	
	ASN principal;
	getListElementByIndex(&kdcReqBody, 1, &principal);
	principal.tag = LIST | 2;
	addChild(credInfo, &principal);
	
	for (int i = 4; i < 12; i++) {
		ASN elt;
		int found = getListElementByIndex(asn, i, &elt);
		if (found) {
			elt.tag = LIST | (i - 1);
			addChild(credInfo, &elt);
		}

	}
}

void handleASREP(ASREQ* asreq, ASN* asreqAsn, PBYTE response, int responseSize) {
	ASN asn;
	byte2asn(response, &asn, responseSize);
	printf("[-] Inspecting response\n");
	int responseTag = asn.tag ^ APPLICATION;
	printf("\t[+] Response tag : %02x\n", responseTag);
	if (responseTag == ERROR) {
		printf("\t[x] Kerberos error : %s\n", lookupKrbErrorCode(getKerberosErrorCode(&asn)));
	}
	else if (responseTag == AS_REP) {
		printf("\t[+] ASREP response retrieved\n");
		ASN* asrepSequence = asn.asnContent[0].asnContent;
		int keyType = -1;
		char* encData = NULL;
		size_t encDataSize = -1;

		ASN encryptedPart;
		ASN keyTypeAsn;
		ASN cipherAsn;
		getListElementByIndex(&asn.asnContent[0], 6, &encryptedPart);
		if (!(&encryptedPart)) {
			printf("\t[x] Failed to extract encrypted element\n");
			exit(-1);
		}
		getListElementByIndex(&encryptedPart.asnContent[0], 0, &keyTypeAsn);
		getListElementByIndex(&encryptedPart.asnContent[0], 2, &cipherAsn);
		if (!(&keyTypeAsn) || !(&cipherAsn)) {
			printf("\t[x] Failed to extract encryption option for KDCRepPart\n");
			exit(-1);
		}
		keyType = getInteger(keyTypeAsn.asnContent[0]);
		encData = cipherAsn.asnContent[0].content;
		encDataSize = cipherAsn.asnContent[0].contentSize;

		if (keyType == -1) {
			printf("\t[x] Failed to retrieve encryption info\n");
			exit(-1);
		}
		PBYTE result;
		size_t resultSize;
		PBYTE key;
		size_t keySize;
		get_key_rc4(asreq->password, &key, &keySize);
		decrypt(key, keyType, 8, encData, encDataSize, &result, &resultSize);
		printf("\t[+] EncKDCRepPart : ");
		for (int i = 0; i < resultSize; i++) {
			printf("%02x", result[i]);
		}
		printf("\n");

		ASN KDCRep;
		byte2asn(result, &KDCRep, resultSize);

		printf("\t[-] Inspecting KDCRep\n");
		printf("\t[+] KDCRep tag : %d\n", KDCRep.tag ^ APPLICATION);
		if (KDCRep.tag != (APPLICATION | 25)) {
			printf("\t[x] Bad content for KDCRep\n");
			exit(-1);
		}

		printf("\t[+] Building KDC-CRED-INFO\n");
		ASN credInfo;
		buildKrbCredInfo(&KDCRep, asreqAsn, &credInfo);
		printf("\t[+] Building TGT\n");
		ASN creds = {
			.tag = APPLICATION | 22,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN)),
		};

		ASN sequenceCred = {
			.tag = SEQUENCE,
			.isAsnContent = 1,
			.asnContent = calloc(5, sizeof(ASN))
		};
		addChild(&creds, &sequenceCred);

		ASN pvnoElement = {
			.tag = LIST | 0,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&sequenceCred, &pvnoElement);

		ASN pvno;
		newInteger(&pvno, 5);
		addChild(&pvnoElement, &pvno);

		ASN typeElement = {
			.tag = LIST | 1,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&sequenceCred, &typeElement);
		
		ASN type;
		newInteger(&type, 0x16);
		addChild(&typeElement, &type);

		ASN tickets;
		getListElementByIndex(&asn.asnContent[0], 5, &tickets);
		tickets.tag = SEQUENCE;
		ASN ticketsElement = {
			.tag = LIST | 2,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&ticketsElement, &tickets);
		addChild(&sequenceCred, &ticketsElement);


		ASN infoElement = {
			.tag = LIST | 3,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&sequenceCred, &infoElement);

		ASN infoSequence = {
			.tag = SEQUENCE,
			.isAsnContent = 1,
			.asnContent = calloc(3, sizeof(ASN)),
		};
		addChild(&infoElement, &infoSequence);

		ASN encTypeElement = {
			.tag = LIST | 0,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN)),
		};
		addChild(&infoSequence, &encTypeElement);
		
		ASN encType;
		newInteger(&encType, 0);
		addChild(&encTypeElement, &encType);
		
		ASN encValueElement = {
			.tag = LIST | 2,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&infoSequence, &encValueElement);
		
		ASN encValueOctetString = {
			.tag = OCTET_STRING,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN)),
		};
		addChild(&encValueElement, &encValueOctetString);
		
		ASN encValueApplication = {
			.tag = APPLICATION | 29,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&encValueOctetString, &encValueApplication);
		
		ASN encValueAppSequence = {
			.tag = SEQUENCE,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN)),
		};
		addChild(&encValueApplication, &encValueAppSequence);
		
		ASN encValueAppSeqElement = {
			.tag = LIST | 0,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&encValueAppSequence, &encValueAppSeqElement);
		
		ASN dataSequence = {
			.tag = SEQUENCE,
			.isAsnContent = 1,
			.asnContent = calloc(2, sizeof(ASN))
		};
		addChild(&encValueAppSeqElement, &dataSequence);
		
		addChild(&dataSequence, &credInfo);
		printf("[+] TGT : ");
		printAsn(&creds);
		printf("\n");
	}
}