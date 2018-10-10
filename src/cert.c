#include "cert.h"

/* ------------------------------------------------------------------------ */

#define CERTIFICATE_DATABASE_HASH_TABLE_START_SIZE 20

/* ------------------------------------------------------------------------ */

static PLHashTable* certificateDatabaseHashTable;
static PRLock* certificateDatabaseLock;

/* ------------------------------------------------------------------------ */

static SECStatus certcr_initializeStaticCertificateDatabase() {
	DEBUGLOG("[>] entering certcr_initializeStaticCertificateDatabase\n");
	
	// ---
	
	DEBUGLOG("[+] creating certificate database\n");
	
	certificateDatabaseHashTable = PL_NewHashTable(CERTIFICATE_DATABASE_HASH_TABLE_START_SIZE, PL_HashString, PL_CompareStrings, PL_CompareValues, NULL, NULL);
	
	if (certificateDatabaseHashTable == NULL) {
		DEBUGLOG("[-] cannot create certificate database hash table\n");
		
		goto certcr_initializeStaticCertificateDatabase01;
	}
	
	// ---
	
	DEBUGLOG("[+] creating certificate database lock\n");
	
	certificateDatabaseLock = PR_NewLock();
	
	if (certificateDatabaseLock == NULL) {
		DEBUGLOG("[-] cannot create certificate database lock\n");
		
		goto certcr_initializeStaticCertificateDatabase02;
	}
	
	// ---
	
	return SECSuccess;
	
certcr_initializeStaticCertificateDatabase02:
	// TODO: deinitialize lock
	//
	// TODO: deinitialize the hash table
	//
	
certcr_initializeStaticCertificateDatabase01:
	return SECFailure;
}


/* ------------------------------------------------------------------------ */

SECStatus startupCertcr(char* directory) {
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[>] entering startupCertcr\n");
	
	// ---
	
	if (directory == NULL) {
		DEBUGLOG("[+] initializing nss without database\n");
		
		secStatus = NSS_NoDB_Init(".");
	} else {
		DEBUGLOG("[+] initializing nss with database\n");
		
		secStatus = NSS_Init(directory);
	}
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot initialize nss\n");
		
		return SECFailure;
	}
	
	// ---
	
	secStatus = setDomesticPolicies();
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot set domestic policies\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] initializing static certificate database\n");
	
	secStatus = certcr_initializeStaticCertificateDatabase();
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot initialize static certificate database\n");
		
		return SECFailure;
	}
	
	// ---
	
	return SECSuccess;
}

SECStatus shutdownCertcr(char* directory) {
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[>] entering shutdownCertcr\n");
	
	// ---
	
	DEBUGLOG("[+] deinitializing nss\n");
	
	secStatus = NSS_Shutdown();
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot deinitialize nss\n");
		
		return SECFailure;
	}
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

SECStatus setDomesticPolicies() {
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[+] setting domestic policy\n");
	
	secStatus = NSS_SetDomesticPolicy();
	
	if (secStatus == SECFailure) {
		RUNLOG("[-] cannot set domestic policy\n");
		
		return SECFailure;
	}
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

#define DEFAULT_RSA_KEY_SIZE_IN_BITS 1024
#define DEFAULT_RSA_PE 0x10001

/* ------------------------------------------------------------------------ */

int ssl2CipherSuites[] = {
	SSL_EN_RC4_128_WITH_MD5,              /* A */
	SSL_EN_RC4_128_EXPORT40_WITH_MD5,     /* B */
	SSL_EN_RC2_128_CBC_WITH_MD5,          /* C */
	SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5, /* D */
	SSL_EN_DES_64_CBC_WITH_MD5,           /* E */
	SSL_EN_DES_192_EDE3_CBC_WITH_MD5,     /* F */
	0
};

int ssl3CipherSuites[] = {
	-1, /*SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,*/ /* a */
	-1, /*SSL_FORTEZZA_DMS_WITH_RC4_128_SHA,*/      /* b */
	SSL_RSA_WITH_RC4_128_MD5,               /* c */
	SSL_RSA_WITH_3DES_EDE_CBC_SHA,          /* d */
	SSL_RSA_WITH_DES_CBC_SHA,               /* e */
	SSL_RSA_EXPORT_WITH_RC4_40_MD5,         /* f */
	SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,     /* g */
	-1, /*SSL_FORTEZZA_DMS_WITH_NULL_SHA,*/         /* h */
	SSL_RSA_WITH_NULL_MD5,                  /* i */
	SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,     /* j */
	SSL_RSA_FIPS_WITH_DES_CBC_SHA,          /* k */
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,    /* l */
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,     /* m */
	0
};

/* ------------------------------------------------------------------------ */

SECStatus enableNullCiphers(PRBool isEnabled) {
	#ifdef DEBUG
		if (isEnabled) {
			DEBUGLOG("[+] null ciphers enabled\n");
		} else {
			DEBUGLOG("[+] null ciphers disabled\n");
		}
	#endif
	
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[>] entering disableNullCiphers\n");
	
	// ---
	
	DEBUGLOG("[+] enable null md5\n");
	
	secStatus = SSL_CipherPrefSetDefault(SSL_RSA_WITH_NULL_MD5, isEnabled);
	
	if (secStatus == SECFailure) {
		return SECFailure;
	}
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

SECStatus enableSsl2(PRBool isEnabled) {
	#ifdef DEBUG
		if (isEnabled) {
			DEBUGLOG("[+] ssl2 enabled\n");
		} else {
			DEBUGLOG("[+] ssl2 disabled\n");
		}
	#endif
	
	// ---
	
	// TODO: add code here
	return SECSuccess;
	//
}

SECStatus enableSsl3(PRBool isEnabled) {
	#ifdef DEBUG
		if (isEnabled) {
			DEBUGLOG("[+] ssl3 enabled\n");
		} else {
			DEBUGLOG("[+] ssl3 disabled\n");
		}
	#endif
	
	// ---
	
	// TODO: add code here
	return SECSuccess;
	//
}

/* ------------------------------------------------------------------------ */

PRStatus disableAllSslCiphers() {
	int i;
	PRUint16 suite;
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[>] entering disableAllSslCiphers\n");
	
	// ---
	
	i = SSL_NumImplementedCiphers;
	
	while (--i >= 0) {
		suite = SSL_ImplementedCiphers[i];
		
		// +++
		
		DEBUGLOG("[+] disabling cipher suite %d\n", suite);
		
		secStatus = SSL_CipherPrefSetDefault(suite, PR_FALSE);
		
		if (secStatus == SECFailure) {
			DEBUGLOG("[-] cannot disable cipher suite %d\n", suite);
			
			return PR_FAILURE;
		}
	}
	
	// ---
	
	return PR_SUCCESS;
}

PRStatus enableSomeSslCiphers(char* ciphers) {
	int i;
	int* p;
	int cipher;
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[>] entering enableOnlySslCiphers\n");
	
	// ---
	
	while (0 != (i = *ciphers++)) {
		if (!isalpha(i)) {
			continue;
		}
		
		// +++
		
		p = islower(i) ? ssl3CipherSuites : ssl2CipherSuites;
		
		for (i &= 0x1f; (cipher = *p++) != 0 && --i > 0;) {
			// pass
		}
		
		// +++
		
		if (cipher) {
			DEBUGLOG("[+] turning on cipher %d\n", cipher);
			
			secStatus = SSL_CipherPrefSetDefault(cipher, PR_TRUE);
			
			if (secStatus == SECFailure) {
				DEBUGLOG("[-] cannot turn on cipher %d\n", cipher);
				
				return PR_FAILURE;
			}
		}
	}
	
	// ---
	
	return PR_SUCCESS;
}

/* ------------------------------------------------------------------------ */

CERTValidity* createCertificateValidityFromNow(PRUint8 months) {
	PRTime before;
	PRTime after;
	PRExplodedTime printableTime;
	
	// ---
	
	DEBUGLOG("[>] entering createCertificateValidityFromNow\n");
	
	// ---
	
	before = PR_Now();
	
	PR_ExplodeTime(before, PR_GMTParameters, &printableTime);
	
	printableTime.tm_month += months;
	
	after = PR_ImplodeTime(&printableTime);
	
	// ---
	
	return CERT_CreateValidity(before, after);
}

/* ------------------------------------------------------------------------ */

SECKEYPrivateKey* createEncryptionKeyPair(SECKEYPublicKey** publicKey) {
	SECStatus secStatus;
	PK11SlotInfo* slot;
	PK11RSAGenParams params;
	SECKEYPrivateKey* privateKey;
	
	// ---
	
	DEBUGLOG("[>] entering createEncryptionKeyPair\n");
	
	// ---
	
	DEBUGLOG("[+] creating slot\n");
	
	slot = PK11_GetBestSlot(CKM_RSA_PKCS_KEY_PAIR_GEN, NULL);
	
	if (slot == NULL) {
		DEBUGLOG("[-] cannot create slot\n");
		
		goto createEncryptionKeyPair01;
	}
	
	// ---
	
	DEBUGLOG("[+] authnticating slot\n");
	
	secStatus = PK11_Authenticate(slot, PR_FALSE, NULL);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot authenticate slot\n");
		
		goto createEncryptionKeyPair02;
	}
	
	// ---
	
	DEBUGLOG("[+] generating key pair\n");
	
	params.keySizeInBits = DEFAULT_RSA_KEY_SIZE_IN_BITS;
	params.pe = DEFAULT_RSA_PE;
	
	privateKey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &params, &(*publicKey), PR_FALSE, PR_FALSE, NULL);
	
	// ---
	
	if (privateKey == NULL) {
		DEBUGLOG("[-] private key is NULL\n");
		
		goto createEncryptionKeyPair03;
	}
	
	if (publicKey == NULL) {
		DEBUGLOG("[-] public key is NULL\n");
		
		goto createEncryptionKeyPair03;
	}
	
	// ---
	
	PK11_FreeSlot(slot);
	
	// ---
	
	return privateKey;
	
createEncryptionKeyPair03:
	if (privateKey != NULL) {
		SECKEY_DestroyPrivateKey(privateKey);
	}
	
	if (publicKey != NULL) {
		SECKEY_DestroyPublicKey(*publicKey);
	}
	
createEncryptionKeyPair02:
	PK11_FreeSlot(slot);
	
createEncryptionKeyPair01:
	return NULL;
}

/* ------------------------------------------------------------------------ */

SECStatus setCertificateType(CERTCertificate* certificate, unsigned int type) {
	SECStatus secStatus;
	void* extensionHandler;
	SECItem certType;
	
	// ---
	
	DEBUGLOG("[>] entering setCertificateType\n");
	
	// ---
	
	DEBUGLOG("[+] starting cert extensions\n");
	
	extensionHandler = CERT_StartCertExtensions(certificate);
	
	if (extensionHandler == NULL) {
		DEBUGLOG("[-] cannot star cert extension\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] encoding bits\n");
	
	certType.type = siBuffer;
	certType.data = (unsigned char*)&type;
	certType.len = 1;
	
	secStatus = CERT_EncodeAndAddBitStrExtension(extensionHandler, SEC_OID_NS_CERT_EXT_CERT_TYPE, &certType, PR_FALSE);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot encode bits\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] finishing extensions\n");
	
	secStatus = CERT_FinishExtensions(extensionHandler);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot finish extensions\n");
		
		return SECFailure;
	}
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

SECStatus signCertificate(CERTCertificate* certificate, SECKEYPrivateKey* privateKey) {
	SECStatus secStatus;
	SECOidTag alg;
	SECItem derItem;
	SECItem* derCert;
	SECItem* dummyEncodedItem;
	
	// ---
	
	DEBUGLOG("[>] entering signCertificate\n");
	
	// ---
	
	DEBUGLOG("[+] finding private key type\n");
	
	switch (privateKey->keyType) {
		case rsaKey: alg = SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION; break;
		case dsaKey: alg = SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST; break;
		
		default:
			DEBUGLOG("[-] cannot find private key type\n");
			
			return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] setting certificate algorithm id\n");
	
	secStatus = SECOID_SetAlgorithmID(certificate->arena, &certificate->signature, alg, 0);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot set certificate algorithm id\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] encoding certificate\n");
	
	derItem.len = 0;
	derItem.data = NULL;
	
	dummyEncodedItem = SEC_ASN1EncodeItem(certificate->arena, &derItem, certificate, SEC_ASN1_GET(CERT_CertificateTemplate));
	
	if (dummyEncodedItem == NULL) {
		DEBUGLOG("[-] cannot encode certificate\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] allocating arena\n");
	
	derCert = (SECItem*)PORT_ArenaZAlloc(certificate->arena, sizeof(SECItem));
	
	if (derCert == NULL) {
		DEBUGLOG("[-] cannot allocate arena\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] der signing data\n");
	
	secStatus = SEC_DerSignData(certificate->arena, derCert, derItem.data, derItem.len, privateKey, alg);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot der sign data\n");
		
		// NOTE: may not be the right way to do this
		SECITEM_FreeItem(derCert, PR_FALSE);
		//
		
		return SECFailure;
	}
	
	// ---
	
	certificate->derCert = *derCert;
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

CERTCertificateRequest* createCertificateRequest(CERTName* name, SECKEYPublicKey* publicKey) {
	CERTSubjectPublicKeyInfo* spki;
	CERTCertificateRequest* certificateRequest;
	
	// ---
	
	DEBUGLOG("[>] entering createCertificateRequest\n");
	
	// ---
	
	DEBUGLOG("[+] creating subject public key info\n");
	
	spki = SECKEY_CreateSubjectPublicKeyInfo(publicKey);
	
	if (spki == NULL) {
		DEBUGLOG("[-] cannot create subject public key info\n");
		
	    return NULL;
	}
	
	// ---
	
	DEBUGLOG("[+] generating certificate request\n");
	
	certificateRequest = CERT_CreateCertificateRequest(name, spki, NULL);
	
	if (certificateRequest == NULL) {
		DEBUGLOG("[-] cannot generate certificate request\n");
		
		SECKEY_DestroySubjectPublicKeyInfo(spki);
		
		return NULL;
	}
	
	// ---
	
	SECKEY_DestroySubjectPublicKeyInfo(spki);
	
	// ---
	
	return certificateRequest;
}

CERTCertificate* createCertificate(int serialNumber, CERTCertificateRequest* certificateRequest, CERTCertificate *issuerCertificate, CERTValidity* certificateValidity, unsigned int type) {
	SECStatus secStatus;
	CERTCertificate* certificiate;
	
	// ---
	
	DEBUGLOG("[>] entering createCertificate\n");
	
	// ---
	
	DEBUGLOG("[+] generating certificate\n");
	
	if (issuerCertificate == NULL) {
		certificiate = CERT_CreateCertificate(serialNumber, &(certificateRequest->subject), certificateValidity, certificateRequest);
	} else {
		certificiate = CERT_CreateCertificate(serialNumber, &(issuerCertificate->subject), certificateValidity, certificateRequest);
	}
	
	if (certificateRequest == NULL) {
		DEBUGLOG("[-] cannot generate certificate\n");
		
		return NULL;
	}
	
	// ---
	
	DEBUGLOG("[+] setting certificate type\n");
	
	secStatus = setCertificateType(certificiate, type);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot set certificate type\n");
		
		CERT_DestroyCertificate(certificiate);
		
		return NULL;
	}
	
	// ---
	
	return certificiate;
}

/* ------------------------------------------------------------------------ */

SECStatus defaultSslAuthCertificate(void* argument, PRFileDesc* socket, PRBool checksig, PRBool isServer) {
	DEBUGLOG("[>] entering defaultSslAuthCertificate\n");
	
	// ---
	
	return SECSuccess;
}

SECStatus defaultSslHandshakeCallback(PRFileDesc* socket, void* argument) {
	DEBUGLOG("[>] entering defaultSslHandshakeCallback\n");
	
	// ---
	
	return SECSuccess;
}

SECStatus defaultSslBadCertHandler(void* argument, PRFileDesc* socket) {
	DEBUGLOG("[>] entering defaultSslBadCertHandler\n");
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

SECStatus installDefaultSslHooks(PRFileDesc* socket) {
	SECStatus secStatus;
	
	// ---
	
	DEBUGLOG("[>] entering installDefaultSslHooks\n");
	
	// ---
	
	DEBUGLOG("[+] setting up authentication hook\n");
	
	secStatus = SSL_AuthCertificateHook(socket, (SSLAuthCertificate)defaultSslAuthCertificate, NULL);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot set up authentication hook\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] setting up bad cert hook\n");
	
	secStatus = SSL_BadCertHook(socket, (SSLBadCertHandler)defaultSslBadCertHandler, NULL);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot set up bad cert hook\n");
		
		return SECFailure;
	}
	
	// ---
	
	DEBUGLOG("[+] setting up handshake hook\n");
	
	secStatus = SSL_HandshakeCallback(socket, (SSLHandshakeCallback)defaultSslHandshakeCallback, NULL);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot set up handshake hook\n");
		
		return SECFailure;
	}
	
	// ---
	
	return SECSuccess;
}

/* ------------------------------------------------------------------------ */

PRFileDesc* prepareSslSocket(PRFileDesc* tcpSocket, PRBool isServer) {
	PRStatus prStatus;
	SECStatus secStatus;
	PRFileDesc* sslSocket;
	
	// ---
	
	DEBUGLOG("[>] entering prepareSslSocket\n");
	
	// ---
	
	DEBUGLOG("[+] creating ssl socket from tcp socket\n");
	
	sslSocket = SSL_ImportFD(NULL, tcpSocket);
	
	if (sslSocket == NULL) {
		DEBUGLOG("[-] cannot create ssl socket from tcp socket\n");
		
		goto prepareSslSocketFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] turning on security options on ssl socket\n");
	
	secStatus = SSL_OptionSet(sslSocket, SSL_SECURITY, PR_TRUE);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot turn on security options on ssl socket\n");
		
		goto prepareSslSocketFailure2;
	}
	
	if (isServer == PR_TRUE) {
		DEBUGLOG("[+] setting ssl socket to be a server\n");

		secStatus = SSL_OptionSet(sslSocket, SSL_HANDSHAKE_AS_SERVER, PR_TRUE);

		if (secStatus == SECFailure) {
			DEBUGLOG("[-] cannot set ssl socket to be a server\n");

			goto prepareSslSocketFailure2;
		}
	} else {
		DEBUGLOG("[+] setting ssl socket to be a client\n");
	
		secStatus = SSL_OptionSet(sslSocket, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
	
		if (secStatus == SECFailure) {
			DEBUGLOG("[-] setting ssl socket to be a client\n");
			
			goto prepareSslSocketFailure2;
		}
	}
	
	// ---
	
	secStatus = installDefaultSslHooks(sslSocket);
	
	if (secStatus == SECFailure) {
		goto prepareSslSocketFailure2;
	}
	
	/// ---
	
	return sslSocket;
	
prepareSslSocketFailure2:
	// NOTE: we need to ensure that PR_Close only closes the ssl socket and not the tcp one
	DEBUGLOG("[+] closing ssl socket\n");
	
	prStatus = PR_Close(sslSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot close ssl socket\n");
	}
	//
	
prepareSslSocketFailure1:
	return NULL;
}

/* ------------------------------------------------------------------------ */

PRFileDesc* makeClientSslSocket(PRFileDesc* tcpSocket) {
	PRFileDesc* sslSocket;
	
	// ---
	
	DEBUGLOG("[>] entering makeClientSslSocket\n");
	
	// ---
	
	DEBUGLOG("[+] preparing client ssl socket\n");
	
	sslSocket =  prepareSslSocket(tcpSocket, PR_FALSE);
	
	if (sslSocket == NULL) {
		DEBUGLOG("[-] cannot prepare client ssl socket\n");
		
		return NULL;
	}
	
	// ---
	
	return sslSocket;
}

PRFileDesc* makeServerSslSocket(PRFileDesc* tcpSocket, CERTCertificate* certificate, SECKEYPrivateKey* privateKey) {
	SECStatus secStatus;
	PRFileDesc* sslSocket;
	SSLKEAType certKEA;
	
	// ---
	
	DEBUGLOG("[>] entering makeServerSslSocket\n");
	
	// ---
	
	DEBUGLOG("[+] preparing server ssl socket\n");
	
	sslSocket = prepareSslSocket(tcpSocket, PR_TRUE);
	
	if (sslSocket == NULL) {
		DEBUGLOG("[-] cannot prepare server ssl socket\n");
		
		return NULL;
	}
	
	// ---
	
	DEBUGLOG("[+] finding the certificate kea type\n");
	
	certKEA = NSS_FindCertKEAType(certificate);
	
	if (certKEA == 0) {
		DEBUGLOG("[-] cannot find the certificate kea type\n");
		
		return NULL;
	}
	
	// ---
	
	DEBUGLOG("[+] configuring ssl server\n");
	
	secStatus = SSL_ConfigSecureServer(sslSocket, certificate, privateKey, certKEA);
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot configure ssl server\n");
		
		return NULL;
	}
	
	// ---
	
	return sslSocket;
}

/* ------------------------------------------------------------------------ */

CERTCertificate* obtainRemoteCertificate(char* host, PRUint16 port) {
	PRStatus prStatus;
	PRFileDesc* sslSocket;
	PRInt32 bytesSent;
	CERTCertificate* certificate;
	
	// ---
	
	DEBUGLOG("[>] entering obtainRemoteCertificate\n");
	
	// ---
	
	DEBUGLOG("[+] connecting to remote\n");
	
	sslSocket = connectToRemote(host, port, PR_TRUE, PR_TRUE);
	
	if (sslSocket == NULL) {
		DEBUGLOG("[-] cannot connect to remote\n");
		
		goto obtainRemoteCertificateCleanup1;
	}
	
	// ---
	
	DEBUGLOG("[+] sending dummy request\n");
	
	bytesSent = PR_Send(sslSocket, "GET / HTTP/1.0\r\n\r\n", 18, 0, DEFAULT_SEND_TIMEOUT);
	
	if (bytesSent <= 0) {
		DEBUGLOG("[-] cannot send dummy request\n");
		ERRORLOG();
		
		goto obtainRemoteCertificateCleanup2;
	}
	
	// ---
	
	DEBUGLOG("[+] revealing certificate\n");
	
	certificate = SSL_RevealCert(sslSocket);
	
	if (certificate == NULL) {
		DEBUGLOG("[-] cannot reveal certificate\n");
		
		goto obtainRemoteCertificateCleanup2;
	}
	
	// ---
	
	DEBUGLOG("[+] closing tcp socket\n");
	
	prStatus = PR_Close(sslSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot close tcp socket\n");
	}
	
	// ---
	
	return certificate;
	
obtainRemoteCertificateCleanup2:
	DEBUGLOG("[+] closing ssl socket\n");
	
	prStatus = PR_Close(sslSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot close ssl socket\n");
	}
	
obtainRemoteCertificateCleanup1:
	return NULL;
}

CERTName* obtainRemoteCertificateName(char* host, PRUint16 port) {
	SECStatus secStatus;
	CERTCertificate* certificate;
	PLArenaPool* arena;
	CERTName* name;
	
	// ---
	
	DEBUGLOG("[>] entering obtainRemoteCertificateName\n");
	
	// ---
	
	DEBUGLOG("[+] obtaining remote certificate\n");
	
	certificate = obtainRemoteCertificate(host, port);
	
	if (certificate == NULL) {
		DEBUGLOG("[-] cannot obtain remote certificate\n");
		
		goto obtainRemoteCertificateNameCleanup1;
	}
	
	// ---
	
	DEBUGLOG("[+] creating arena\n");
	
	// NOTE: this used to be PRArenaPool
	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	//
	
	if (arena == NULL) {
		DEBUGLOG("[-] cannot create arena\n");
		
		goto obtainRemoteCertificateNameCleanup2;
	}
	
	// ---
	
	// NOTE: for some reason this technique happens to work but it is not sure if it leaks
	DEBUGLOG("[+] allocating name\n");
	
	name = (CERTName*)PORT_ArenaZNew(arena, CERTName);
	
	if (name == NULL) {
		DEBUGLOG("[-] cannot allocate name\n");
		
		goto obtainRemoteCertificateNameCleanup3;
	}
	//
	
	// ---
	
	DEBUGLOG("[+] copying name\n");
	
	secStatus = CERT_CopyName(arena, name, &(certificate->subject));
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot copy name\n");
		
		// NOTE: the reason we do this here is because otherwise freeing the arena and destroying the name will trigger double free
		CERT_DestroyName(name);
		
		goto obtainRemoteCertificateNameCleanup2;
		//
	}
	
	// ---
	
	// NOTE: see notes above why we are not doing this
	//PORT_FreeArena(arena, PR_FALSE);
	//
	
	// ---
	
	CERT_DestroyCertificate(certificate);
	
	// ---
	
	return name;
	
obtainRemoteCertificateNameCleanup3:
	PORT_FreeArena(arena, PR_FALSE);
	
obtainRemoteCertificateNameCleanup2:
	CERT_DestroyCertificate(certificate);
	
obtainRemoteCertificateNameCleanup1:
	return NULL;
}

/* ------------------------------------------------------------------------ */

const char* builtinCaSubject = "c=US,st=California,l=Mountain View,o=Proxify Inc,ou=QA,cn=";

/* ------------------------------------------------------------------------ */

static CERTName* certcr_obtainCertificateName(char* host, PRUint16 port, char* defaultSubject) {
	CERTName* name;
	char* subject;
	
	// ---
	
	DEBUGLOG("[>] entering certcr_obtainCertificateName\n");
	
	// ---
	
	DEBUGLOG("[+] checking default subject\n");
	
	if (defaultSubject == NULL) {
		DEBUGLOG("[-] default subject is null\n");
		
		return NULL;
	}
	
	// ---
	
	DEBUGLOG("[+] creating subject\n");
	
	subject = (char*)PR_MALLOC(PL_strlen(defaultSubject) + PL_strlen(host) + 1);
	
	if (subject == NULL) {
		DEBUGLOG("[-] cannot create subject\n");
		
		return NULL;
	}
	
	// ---
	
	DEBUGLOG("[+] reconstructing subject\n");
	
	strcpy(subject, defaultSubject);
	strcat(subject, host);
	
	// ---
	
	DEBUGLOG("[+] creating certificate name from subject %s\n", subject);
	
	name = CERT_AsciiToName(subject);
	
	if (name == NULL) {
		DEBUGLOG("[-] cannot create certificate name from subject %s\n", subject);
		
		PR_DELETE(subject);
		
		return NULL;
	}
	
	// ---
	
	PR_DELETE(subject);
	
	// ---
	
	return name;
}

static CERTName* certcr_obtainRemoteCertificateName(char* host, PRUint16 port, char* defaultSubject) {
	CERTName* name;
	
	// ---
	
	DEBUGLOG("[>] entering certcr_obtainRemoteCertificateName\n");
	
	// ---
	
	DEBUGLOG("[+] obtaining remote certificate name\n");
	
	name = obtainRemoteCertificateName(host, port);
	
	if (name == NULL) {
		DEBUGLOG("[+] cannot obtain remote certificate name\n");
		
		// +++
		
		DEBUGLOG("[+] creating certificate name from host, port and provided subject\n");
		
		name = certcr_obtainCertificateName(host, port, defaultSubject);
		
		if (name == NULL) {
			DEBUGLOG("[-] cannot create certificate name from host, port and provided subject\n");
			
			return NULL;
		}
	}
	
	// ---
	
	return name;
}

static CertificateDatabaseEntry* certcr_createCertificateDatabaseEntry(char* host, PRUint16 port, char* defaultSubject, unsigned int type) {
	SECStatus secStatus;
	CertificateDatabaseEntry* certificateDatabaseEntry;
	CERTName* name;
	SECKEYPublicKey* publicKey;
	SECKEYPrivateKey* privateKey;
	CERTCertificateRequest* certificateRequest;
	CERTValidity* certificateValidity;
	unsigned long serial;
	CERTCertificate* certificate;
	
	// ---
	
	DEBUGLOG("[>] entering certcr_createCertificateDatabaseEntry\n");
	
	// ---
	
	DEBUGLOG("[+] creating certificate database entry\n");
	
	certificateDatabaseEntry = (CertificateDatabaseEntry*)PR_MALLOC(sizeof(CertificateDatabaseEntry));
	
	if (certificateDatabaseEntry == NULL) {
		DEBUGLOG("[-] cannot create certificate database entry\n");
		
		goto certcr_createCertificateDatabaseEntry1;
	}
	
	// ---
	
	DEBUGLOG("[+] obtaining remote certificate name ex\n");
	
	if (type == NS_CERT_TYPE_CA) {
		name = certcr_obtainCertificateName(host, port, defaultSubject);
	} else {
		name = certcr_obtainRemoteCertificateName(host, port, defaultSubject);
	}
	
	if (name == NULL) {
		DEBUGLOG("[-] cannot obtain remote certificate name ex\n");
		
		goto certcr_createCertificateDatabaseEntry2;
	}
	
	// ---
	
	DEBUGLOG("[+] creating public and private keys\n");
	
	publicKey = NULL;
	privateKey = createEncryptionKeyPair(&publicKey);
	
	if (privateKey == NULL) {
		DEBUGLOG("[-] cannot create private key\n");
		
		goto certcr_createCertificateDatabaseEntry3;
	}
	
	if (publicKey == NULL) {
		DEBUGLOG("[-] cannot create public key\n");
		
		goto certcr_createCertificateDatabaseEntry4;
	}
	
	// ---
	
	DEBUGLOG("[+] creating certificate request\n");
	
	certificateRequest = createCertificateRequest(name, publicKey);
	
	if (certificateRequest == NULL) {
		DEBUGLOG("[-] cannot create certificate request\n");
		
		goto certcr_createCertificateDatabaseEntry5;
	}
	
	// ---
	
	DEBUGLOG("[+] creating certificate validity\n");
	
	// TODO: get number of months from command line
	certificateValidity = createCertificateValidityFromNow(3);
	//
	
	if (certificateValidity == NULL) {
		DEBUGLOG("[-] cannot create certificate validity\n");
		
		goto certcr_createCertificateDatabaseEntry6;
	}
	
	// ---
	
	DEBUGLOG("[+] creating certificate\n");
	
	LL_L2UI(serial, PR_Now());
	
	if (type == NS_CERT_TYPE_CA) {
		certificate = createCertificate(serial, certificateRequest, NULL, certificateValidity, type);
	} else {
		certificate = createCertificate(serial, certificateRequest, NULL, certificateValidity, type);
	}
	
	if (certificate == NULL) {
		DEBUGLOG("[-] cannot create certificate\n");
		
		goto certcr_createCertificateDatabaseEntry7;
	}
	
	// ---
	
	DEBUGLOG("[+] signing certificate\n");
	
	if (type == NS_CERT_TYPE_CA) {
		secStatus = signCertificate(certificate, privateKey);
	} else {
		secStatus = signCertificate(certificate, privateKey);
	}
	
	if (secStatus == SECFailure) {
		DEBUGLOG("[-] cannot sign certificate\n");
		
		goto certcr_createCertificateDatabaseEntry8;
	}
	
	// ---
	
	certificateDatabaseEntry->certificate = certificate;
	certificateDatabaseEntry->privateKey = privateKey;
	
	// ---
	
	CERT_DestroyValidity(certificateValidity);
	CERT_DestroyCertificateRequest(certificateRequest);
	SECKEY_DestroyPublicKey(publicKey);
	CERT_DestroyName(name);
	
	// ---
	
	return certificateDatabaseEntry;
	
	// ---
	
certcr_createCertificateDatabaseEntry8:
	CERT_DestroyCertificate(certificate);
	
certcr_createCertificateDatabaseEntry7:
	CERT_DestroyValidity(certificateValidity);
	
certcr_createCertificateDatabaseEntry6:
	CERT_DestroyCertificateRequest(certificateRequest);
	
certcr_createCertificateDatabaseEntry5:
	SECKEY_DestroyPublicKey(publicKey);
	
certcr_createCertificateDatabaseEntry4:
	SECKEY_DestroyPrivateKey(privateKey);
	
certcr_createCertificateDatabaseEntry3:
	CERT_DestroyName(name);
	
certcr_createCertificateDatabaseEntry2:
	PR_DELETE(certificateDatabaseEntry);
	
certcr_createCertificateDatabaseEntry1:
	return NULL;
}

/* ------------------------------------------------------------------------ */

CertificateDatabaseEntry* ensureCertificateDatabaseEntry(char* host, PRUint16 port, char* defaultSubject) {
	int hostportSize;
	char* hostport;
	PLHashEntry* hashEntry;
	CertificateDatabaseEntry* certificateDatabaseEntry;
	
	// ---
	
	DEBUGLOG("[>] entering ensureCertificateDatabaseEntry\n");
	
	// ---
	
	DEBUGLOG("[+] allocating size for hostport\n");
	
	hostportSize = PL_strlen(host) + 1 + 5 + 1;
	hostport = (char*)PR_MALLOC(hostportSize);
	
	if (hostport == NULL) {
		DEBUGLOG("[-] cannot allocate size for hostport\n");
		
		goto ensureCertificateDatabaseEntryFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] creating hostport\n");
	
	PR_snprintf(hostport, hostportSize, "%s:%u", host, port);
	
	// ---
	
	DEBUGLOG("[+] hostport is %s\n", hostport);
	
	// ---
	
	DEBUGLOG("[+] locking the certificate database\n");
	
	PR_Lock(certificateDatabaseLock);
	
	// ---
	
	DEBUGLOG("[+] retrieving certificate database entry for hostport %s\n", hostport);
	
	certificateDatabaseEntry = PL_HashTableLookup(certificateDatabaseHashTable, hostport);
	
	if (certificateDatabaseEntry == NULL) {
		DEBUGLOG("[+] creating certificate database entry for hostport %s\n", hostport);
		
		certificateDatabaseEntry = certcr_createCertificateDatabaseEntry(host, port, defaultSubject, NS_CERT_TYPE_APP);
		
		if (certificateDatabaseEntry == NULL) {
			DEBUGLOG("[-] cannot create certificate database entry for hostport %s\n", hostport);
			
			goto ensureCertificateDatabaseEntryFailure2;
		}
		
		hashEntry = PL_HashTableAdd(certificateDatabaseHashTable, hostport, certificateDatabaseEntry);
		
		if (hashEntry == NULL) {
			DEBUGLOG("[-] cannot create certificate database entry for hostport %s\n", hostport);
			
			goto ensureCertificateDatabaseEntryFailure2;
		}
	}
	
	// ---
	
	DEBUGLOG("[+] unlocking the certificate database\n");
	
	PR_Unlock(certificateDatabaseLock);
	
	// ---
	
	DEBUGLOG("[+] certificate issuer %s\n", CERT_NameToAscii(&certificateDatabaseEntry->certificate->issuer));
	DEBUGLOG("[+] certificate subject %s\n", CERT_NameToAscii(&certificateDatabaseEntry->certificate->subject));
	
	// ---
	
	// NOTE: we do not free the hostport because it is needed as a key to the hash table
	// PR_DELETE(hostport);
	//
	
	// ---
	
	return certificateDatabaseEntry;
	
	// ---
	
ensureCertificateDatabaseEntryFailure2:
	DEBUGLOG("[+] unlocking the certificate database\n");
	
	PR_Unlock(certificateDatabaseLock);
	
	// ---
	
	PR_DELETE(hostport);
	
ensureCertificateDatabaseEntryFailure1:	
	return NULL;
}

/* ------------------------------------------------------------------------ */

