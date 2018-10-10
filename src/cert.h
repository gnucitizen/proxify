#ifndef CERT_H
#define CERT_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "net.h"

/* ------------------------------------------------------------------------ */

#include "nss.h"
#include "key.h"
#include "ssl.h"
#include "sslproto.h"
#include "cryptohi.h"
#include "pk11func.h"

// NOTE: some of these header files may not be necessery
#include "secasn1.h"
#include "cert.h"
#include "secoid.h"
#include "certdb.h"
//

/* ------------------------------------------------------------------------ */

SECStatus startupSsl(char* directory);
SECStatus shutdownSsl(char* directory);

/* ------------------------------------------------------------------------ */

SECStatus setDomesticPolicies();

/* ------------------------------------------------------------------------ */

SECStatus enableNullCiphers(PRBool isEnabled);

/* ------------------------------------------------------------------------ */

SECStatus enableSsl2(PRBool isEnabled);
SECStatus enableSsl3(PRBool isEnabled);

/* ------------------------------------------------------------------------ */

PRStatus disableAllSslCiphers();
PRStatus enableSomeSslCiphers(char* ciphers);

/* ------------------------------------------------------------------------ */

CERTValidity* createCertificateValidityFromNow(PRUint8 months);

/* ------------------------------------------------------------------------ */

SECKEYPrivateKey* createEncryptionKeyPair(SECKEYPublicKey** pubkey);

/* ------------------------------------------------------------------------ */

SECStatus setCertificateType(CERTCertificate* certificate, unsigned int type);

/* ------------------------------------------------------------------------ */

SECStatus signCertificate(CERTCertificate* certificate, SECKEYPrivateKey* privateKey);

/* ------------------------------------------------------------------------ */

CERTCertificateRequest* createCertificateRequest(CERTName* name, SECKEYPublicKey* publicKey);
CERTCertificate* createCertificate(int serialNumber, CERTCertificateRequest* certificateRequest, CERTCertificate *issuerCertificate, CERTValidity* certificateValidity, unsigned int type);

/* ------------------------------------------------------------------------ */

SECStatus defaultSslAuthCertificate(void* argument, PRFileDesc* socket, PRBool checksig, PRBool isServer);
SECStatus defaultSslHandshakeCallback(PRFileDesc* socket, void* argument);
SECStatus defaultSslBadCertHandler(void* argument, PRFileDesc* socket);

/* ------------------------------------------------------------------------ */

SECStatus installDefaultSslHooks(PRFileDesc* socket);

/* ------------------------------------------------------------------------ */

PRFileDesc* prepareSslSocket(PRFileDesc* tcpSocket, PRBool isServer);

/* ------------------------------------------------------------------------ */

PRFileDesc* makeClientSslSocket(PRFileDesc* tcpSocket);
PRFileDesc* makeServerSslSocket(PRFileDesc* tcpSocket, CERTCertificate* certificate, SECKEYPrivateKey* privateKey);

/* ------------------------------------------------------------------------ */

CERTCertificate* obtainRemoteCertificate(char* host, PRUint16 port);
CERTName* obtainRemoteCertificateName(char* host, PRUint16 port);

/* ------------------------------------------------------------------------ */

typedef struct CertificateDatabaseEntry_t {
	CERTCertificate* certificate;
	SECKEYPrivateKey* privateKey;
} CertificateDatabaseEntry;

/* ------------------------------------------------------------------------ */

CertificateDatabaseEntry* ensureCertificateDatabaseEntry(char* host, PRUint16 port, char* defaultSubject);

/* ------------------------------------------------------------------------ */

SECStatus startupCertcr(char* directory);
SECStatus shutdownCertcr(char* directory);

/* ------------------------------------------------------------------------ */

#endif
