#include "httpdm.h"

/* ------------------------------------------------------------------------ */

static PRFileDesc* httpdm_openFile(char* directory, char* suffix) {
	PRInt32 filePathSize;
	char* filePath;
	PRFileDesc* file;
	
	// ---
	
	filePathSize = PL_strlen(directory) + 100 + PL_strlen(suffix);
	filePath = PR_MALLOC(filePathSize);
	
	// ---
	
	PR_snprintf(filePath, filePathSize, "%s/%u%s", directory, PR_IntervalNow(), suffix);
	
	// ---
	
	file = PR_Open(filePath, PR_WRONLY | PR_CREATE_FILE, PR_IRUSR | PR_IWUSR | PR_IRGRP | PR_IWGRP);
	
	// ---
	
	PR_DELETE(filePath);
	
	// ---
	
	return file;
}

static void httpdm_closeFile(PRFileDesc* file) {
	PR_Close(file);
}

/* ------------------------------------------------------------------------ */

static PRDescIdentity httpdm_identity;
static PRIOMethods httpdm_methods;

/* ------------------------------------------------------------------------ */

typedef struct httpdm_Secret_t {
	char* dumpDirectory;
	PRBool dumpHex;
	
	// ---
	
	PRFileDesc* requestFile;
	PRFileDesc* responseFile;
} httpdm_Secret;

/* ------------------------------------------------------------------------ */

static PRInt32 PR_CALLBACK httpdm_recv(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpdm_Secret* secret;
	PRInt32 result;
	
	// ---
	
	secret = (httpdm_Secret*)fd->secret;
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->recv(fd, buf, amount, flags, timeout);
	
	// ---
	
	if (secret->responseFile) {
		PR_Write(secret->responseFile, buf, result);
	}
	
	// --
	
	if (secret->dumpHex) {
		hexDump((char*)buf, result);
	}
	
	// ---
	
	return result;
}

static PRInt32 PR_CALLBACK httpdm_send(PRFileDesc* fd, const void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpdm_Secret* secret;
	PRInt32 result;
	
	// ---
	
	secret = (httpdm_Secret*)fd->secret;
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->send(fd, buf, amount, flags, timeout);
	
	// ---
	
	if (secret->requestFile) {
		PR_Write(secret->requestFile, buf, result);
	}
	
	// --
	
	if (secret->dumpHex) {
		hexDump((char*)buf, result);
	}
	
	// ---
	
	return result;
}

static PRStatus PR_CALLBACK httpdm_close(PRFileDesc* fd) {
	httpdm_Secret* secret;
	PRStatus result;
	
	// ---
	
	secret = (httpdm_Secret*)fd->secret;
	
	// ---
	
	if (secret->requestFile) {
		httpdm_closeFile(secret->requestFile);
	}
	
	if (secret->responseFile) {
		httpdm_closeFile(secret->responseFile);
	}
	
	// ---
	
	PR_DELETE(fd->secret);
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->close(fd);
	
	// ---
	
	return result;
}

/* ------------------------------------------------------------------------ */

static void httpdm_ensureInitialized() {
	static PRBool httpdm_isInitialized = PR_FALSE;
	
	// ---
	
	const PRIOMethods *stubMethods;
	
	// ---
	
	if (httpdm_isInitialized) {
		return;
	}
	
	// ---
	
	httpdm_isInitialized = PR_TRUE;
	
	// ---
	
	stubMethods = PR_GetDefaultIOMethods();
	
	// ---
	
	httpdm_identity = PR_GetUniqueIdentity("httpdm");
	httpdm_methods = *stubMethods;
	
	// ---
	
	PR_ASSERT(httpdm_identity != PR_INVALID_IO_LAYER);
	
	// ---
	
	httpdm_methods.recv = httpdm_recv;
	httpdm_methods.send = httpdm_send;
	httpdm_methods.close = httpdm_close;
}

/* ------------------------------------------------------------------------ */

PRFileDesc* makeSocketObservable(PRFileDesc* socket, char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping) {
	PRFileDesc* layer;
	httpdm_Secret* secret;
	PRFileDesc* requestFile;
	PRFileDesc* responseFile;
	PRStatus rv;
	
	// ---
	
	if (!(dumpDirectory || dumpHex)) {
		return socket;
	}
	
	// ---
	
	httpdm_ensureInitialized();
	
	// ---
	
	requestFile = NULL;
	responseFile = NULL;
	
	// ---
	
	layer = PR_CreateIOLayerStub(httpdm_identity, &httpdm_methods);
	
	if (layer == NULL) {
		goto makeSocketObservable01;
	}
	
	// ---
	
	secret = PR_NEWZAP(httpdm_Secret);
	
	if (secret == NULL) {
		goto makeSocketObservable02;
	} else {
		layer->secret = (void*)secret;
		
		// +++
		
		secret->dumpDirectory = dumpDirectory;
		secret->dumpHex = dumpHex;
		
		// +++
		
		if (dumpDirectory) {
			requestFile = httpdm_openFile(dumpDirectory, "_req");
			
			if (requestFile == NULL) {
				goto makeSocketObservable03;
			}
			
			secret->requestFile = requestFile;
			
			// ^^^
			
			responseFile = httpdm_openFile(dumpDirectory, "_res");
			
			if (responseFile == NULL) {
				goto makeSocketObservable04;
			}
			
			secret->responseFile = responseFile;
		}
	}
	
	// ---
	
	rv = PR_PushIOLayer(socket, PR_GetLayersIdentity(socket), layer);
	
	if (rv == PR_FAILURE) {
		goto makeSocketObservable05;
	}
	
	// ---
	
	return socket;
	
	// ---
	
makeSocketObservable05:
	if (responseFile) {
		httpdm_closeFile(responseFile);
	}
	
makeSocketObservable04:
	if (requestFile) {
		httpdm_closeFile(requestFile);
	}
	
makeSocketObservable03:
	PR_DELETE(layer->secret);
	
makeSocketObservable02:
	PR_DELETE(layer);
	
makeSocketObservable01:
	return NULL;
}
