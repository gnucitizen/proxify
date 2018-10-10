#include "forwrd.h"

/* ------------------------------------------------------------------------ */

typedef struct forwrd_ProxyConnectorPrivate_t {
	PRUint16 forwardPort;
	
	// ---
	
	char* dumpDirectory;
	PRBool dumpHex;
	PRBool enableGunziping;
} forwrd_ProxyConnectorPrivate;

/* ------------------------------------------------------------------------ */

static PRFileDesc* forwrd_getSocket(ProxyConnector *proxyConnector, char* host, unsigned int port, PRBool isSsl) {
	forwrd_ProxyConnectorPrivate* proxyConnectorPrivate;
	PRFileDesc* socket;
	
	// ---
	
	proxyConnectorPrivate = (forwrd_ProxyConnectorPrivate*)proxyConnector->private;
	
	// ---
	
	socket = connectToLocal(proxyConnectorPrivate->forwardPort, PR_TRUE, PR_FALSE);
	
	if (socket == NULL) {
		return NULL;
	}
	
	// ---
	
	socket = augmentSocket(socket, proxyConnectorPrivate->dumpDirectory, proxyConnectorPrivate->dumpHex, proxyConnectorPrivate->enableGunziping);
	
	if (socket == NULL) {
		return NULL;
	}
	
	// ---
	
	socket = makeSocketHttpAware(socket);
	
	if (socket == NULL) {
		return NULL;
	}
	
	// ---
	
	return socket;
}

/* ------------------------------------------------------------------------ */

ProxyConnector* createForwrdProxyConnector(char* forwardHost, PRUint16 forwardPort, char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping) {
	ProxyConnector* proxyConnector;
	forwrd_ProxyConnectorPrivate* proxyConnectorPrivate;
	
	// --
	
	proxyConnector = PR_NEWZAP(ProxyConnector);
	
	if (proxyConnector == NULL) {
		return NULL;
	}
	
	// ---
	
	proxyConnectorPrivate = PR_NEWZAP(forwrd_ProxyConnectorPrivate);
	
	if (proxyConnectorPrivate == NULL) {
		return NULL;
	} else {
		proxyConnectorPrivate->forwardPort = forwardPort;
		proxyConnectorPrivate->dumpDirectory = dumpDirectory;
		proxyConnectorPrivate->dumpHex = dumpHex;
		proxyConnectorPrivate->enableGunziping = enableGunziping;
	}
	
	// ---
	
	proxyConnector->private = proxyConnectorPrivate;
	proxyConnector->getSocket = forwrd_getSocket;
	
	// ---
	
	return proxyConnector;
}

void destroyForwrdProxyConnector(ProxyConnector* proxyConnector) {
	PR_DELETE(proxyConnector->private);
	PR_DELETE(proxyConnector);
}
