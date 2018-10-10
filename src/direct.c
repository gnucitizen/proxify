#include "direct.h"

/* ------------------------------------------------------------------------ */

static PRUint32 shortenRawInitialRequestLine(char* source, PRUint32 sourceSize, char* destination, PRUint32 desitnationSize) {
	PRUint32 i;
	PRUint32 k;
	PRUint32 h;
	PRUint32 n;
	PRUint32 f;
	
	// ---
	
	for (i = 0, k = 0, n = 0, f = 0; i < sourceSize && k < desitnationSize; i += 1) {
		if (source[i] == ' ' || source[i] == '/') {
			n += 1;
		}
		
		// +++
		
		if (n == 0) {
			destination[k++] = source[i];
		} else
		if (n == 1) {
			// pass
		} else
		if (n == 2) {
			// pass
		} else
		if (n == 3) {
			if (source[i] == ' ') {
				for (h = 0; h < sourceSize && h < desitnationSize; h += 1) {
					destination[h] = source[h];
				}
				
				// +++
				
				return h;
			}
		} else
		if (n >= 4) {
			if (f++ == 0) {
				destination[k++] = ' ';
				
				// +++
				
				if (k < desitnationSize) {
					destination[k++] = '/';
				}
				
				// +++
				
				if (k < desitnationSize && source[i] != '/') {
					destination[k++] = source[i];
				}
			} else {
				destination[k++] = source[i];
			}
			
			// +++
			
			f += 1;
		}
	}
	
	// ---
	
	return k;
}

/* ------------------------------------------------------------------------ */

static PRDescIdentity direct_identity;
static PRIOMethods direct_methods;

/* ------------------------------------------------------------------------ */

typedef struct direct_Secret_t {
	PRBool isPassedFirstLine;
} direct_Secret;

/* ------------------------------------------------------------------------ */

static PRInt32 PR_CALLBACK direct_send(PRFileDesc* fd, const void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	direct_Secret* secret;
	PRInt32 newAmount;
	char* newBuf;
	PRInt32 result;
	
	// ---
	
	secret = (direct_Secret*)fd->secret;
	
	// --
	
	// TODO: this is kind of a hack so it needs a more generic approach
	if (!secret->isPassedFirstLine) {
		secret->isPassedFirstLine = PR_TRUE;
		
		// +++
		
		newBuf = PR_MALLOC(amount);
		
		if (newBuf == NULL) {
			return -1;
		}
		
		// +++
		
		newAmount = shortenRawInitialRequestLine((char*)buf, amount, newBuf, amount);
		result = (PR_GetDefaultIOMethods())->send(fd, newBuf, newAmount, flags, timeout);
		
		// +++
		
		PR_DELETE(newBuf);
		
		// +++
		
		if (result <= 0) {
			return result;
		} else {
			return amount;
		}
	}
	//
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->send(fd, buf, amount, flags, timeout);
	
	// ---
	
	return result;
}

static PRStatus PR_CALLBACK direct_close(PRFileDesc* fd) {
	PRStatus result;
	
	// ---
	
	PR_DELETE(fd->secret);
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->close(fd);
	
	// ---
	
	return result;
}

/* ------------------------------------------------------------------------ */

static void direct_ensureInitialized() {
	static PRBool isInitialized = PR_FALSE;
	
	// ---
	
	const PRIOMethods *stubMethods;
	
	// ---
	
	if (isInitialized) {
		return;
	}
	
	// ---
	
	isInitialized = PR_TRUE;
	
	// ---
	
	stubMethods = PR_GetDefaultIOMethods();
	
	// ---
	
	direct_identity = PR_GetUniqueIdentity("direct");
	direct_methods = *stubMethods;
	
	// ---
	
	direct_methods.send = direct_send;
	direct_methods.close = direct_close;
}

static PRFileDesc* direct_injectSupportLayer(PRFileDesc* stack) {
	PRFileDesc* layer;
	PRStatus rv;
	
	// ---
	
	layer = PR_CreateIOLayerStub(direct_identity, &direct_methods);
	
	// ---

	// NOTE: initialize
	layer->secret = (void*)PR_NEWZAP(direct_Secret);
	
	if (layer->secret == NULL) {
		goto direct_injectSupportLayerFailure01;
	}
	//
	
	// ---
	
	rv = PR_PushIOLayer(stack, PR_GetLayersIdentity(stack), layer);
	
	if (rv == PR_FAILURE) {
		goto direct_injectSupportLayerFailure02;
	}
	
	// ---
	
	return stack;
	
direct_injectSupportLayerFailure02:
	PR_DELETE(stack->secret);
	
direct_injectSupportLayerFailure01:
	// TODO: dealocate layer somehow
	//
	
	return NULL;
}

/* ------------------------------------------------------------------------ */

typedef struct direct_ProxyConnectorPrivate_t {
	char* dumpDirectory;
	PRBool dumpHex;
	PRBool enableGunziping;
} direct_ProxyConnectorPrivate;

/* ------------------------------------------------------------------------ */

static PRFileDesc* direct_getSocket(ProxyConnector *proxyConnector, char* host, unsigned int port, PRBool isSsl) {
	direct_ProxyConnectorPrivate* proxyConnectorPrivate;
	PRFileDesc* socket;
	
	// ---
	
	proxyConnectorPrivate = (direct_ProxyConnectorPrivate*)proxyConnector->private;
	
	// ---
	
	socket = connectToRemote(host, port, PR_TRUE, isSsl);
	
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
	
	socket = direct_injectSupportLayer(socket);
	
	if (socket == NULL) {
		return NULL;
	}
	
	// ---
	
	return socket;
}

/* ------------------------------------------------------------------------ */

ProxyConnector* createDirectProxyConnector(char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping) {
	ProxyConnector* proxyConnector;
	direct_ProxyConnectorPrivate* proxyConnectorPrivate;
	
	// --
	
	proxyConnector = PR_NEWZAP(ProxyConnector);
	
	if (proxyConnector == NULL) {
		return NULL;
	}
	
	// ---
	
	proxyConnectorPrivate = PR_NEWZAP(direct_ProxyConnectorPrivate);
	
	if (proxyConnectorPrivate == NULL) {
		return NULL;
	} else {
		proxyConnectorPrivate->dumpDirectory = dumpDirectory;
		proxyConnectorPrivate->dumpHex = dumpHex;
		proxyConnectorPrivate->enableGunziping = enableGunziping;
	}
	
	// ---
	
	proxyConnector->private = proxyConnectorPrivate;
	proxyConnector->getSocket = direct_getSocket;
	
	// ---
	
	direct_ensureInitialized();
	
	// ---
	
	return proxyConnector;
}

void destroyDirectProxyConnector(ProxyConnector* proxyConnector) {
	PR_DELETE(proxyConnector->private);
	PR_DELETE(proxyConnector);
}
