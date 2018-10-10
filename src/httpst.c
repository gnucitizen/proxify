#include "httpst.h"

/* ------------------------------------------------------------------------ */

#define HTTPST_LINE_BUFFER_SIZE 10240
#define HTTPST_SELF_FLAGS -1337

/* ------------------------------------------------------------------------ */

static char* readHeaderLine(char* sourceBuffer, unsigned int sourceBufferSize, unsigned int *sourceBufferPosition, char* lineBuffer, unsigned int lineBufferSize, unsigned int *lineBufferPosition) {
	for (; *sourceBufferPosition < sourceBufferSize && *lineBufferPosition < lineBufferSize - 1; *sourceBufferPosition += 1, *lineBufferPosition += 1) {
		lineBuffer[*lineBufferPosition] = tolower(sourceBuffer[*sourceBufferPosition]);
		
		// ++
		
		if (lineBuffer[*lineBufferPosition] == '\0') {
			*sourceBufferPosition += 1;
			*lineBufferPosition = 0;
			
			// ^^^
			
			return lineBuffer;
		} else
		if (lineBuffer[*lineBufferPosition] == '\n') {
			lineBuffer[*lineBufferPosition + 1] = '\0';
			
			// ^^^
			
			*sourceBufferPosition += 1;
			*lineBufferPosition = 0;
			
			// ^^^
			
			return lineBuffer;
		}
	}
	
	// ---
	
	return NULL;
}

/* ------------------------------------------------------------------------ */

static PRDescIdentity httpst_identity;
static PRIOMethods httpst_methods;

/* ------------------------------------------------------------------------ */

typedef struct httpst_Secret_t {
	char tempBuffer[HTTPST_LINE_BUFFER_SIZE];
	unsigned int tempBufferPosition;
	
	// ---
	
	PRBool isResponseDone;
	
	// ---
	
	PRBool isSocket;
	PRBool isChunkEncoded;
	unsigned long contentLength;
	
	// ---
	
	unsigned int nextChunkSize;
	
	// ---
	
	PRRecvFN recv;
} httpst_Secret;

/* ------------------------------------------------------------------------ */

static PRInt32 PR_CALLBACK httpst_recv_socket(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpst_Secret* secret;
	PRInt32 result;
	
	// ---
	
	DEBUGLOG("[>] entering httpst recv socket response\n");
	
	// ---
	
	secret = (httpst_Secret*)fd->secret;
	
	// ---
	
	if (secret->isResponseDone == PR_TRUE) {
		return -1;
	}
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->recv(fd, buf, amount, flags, timeout);
	
	// ---
	
	return result;
}

static PRInt32 PR_CALLBACK httpst_recv_chunked(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpst_Secret* secret;
	unsigned int copiedDataSize;
	PRInt32 result;
	char* line;
	
	// ---
	
	DEBUGLOG("[>] entering httpst recv chunked response\n");
	
	// ---
	
	secret = (httpst_Secret*)fd->secret;
	copiedDataSize = 0;
	line = NULL;
	
	// ---
	
	if (secret->isResponseDone == PR_TRUE) {
		return -1;
	}
	
	// ---
	
	if (flags != HTTPST_SELF_FLAGS) {
		result = (PR_GetDefaultIOMethods())->recv(fd, buf, amount, flags, timeout);
	} else {
		result = amount;
	}
	
	// ---
	
	if (secret->nextChunkSize == 0) {
		line = readHeaderLine(buf, result, &copiedDataSize, secret->tempBuffer, sizeof(secret->tempBuffer), &(secret->tempBufferPosition));
		
		// +++
		
		if (line != NULL) {
			if (sscanf(line, "%x", &(secret->nextChunkSize)) == 1) {
				if (secret->nextChunkSize == 0) {
					secret->isResponseDone = PR_TRUE;
				} else {
					secret->nextChunkSize += 2;
					
					// ^^^
					
					httpst_recv_chunked(fd, &((char*)buf)[copiedDataSize], result - copiedDataSize, HTTPST_SELF_FLAGS, timeout);
				}
			}
		}
	} else {
		if (secret->nextChunkSize >= result) {
			secret->nextChunkSize -= result;
		} else {
			copiedDataSize = secret->nextChunkSize;
			secret->nextChunkSize = 0;
			
			// +++
			
			httpst_recv_chunked(fd, &((char*)buf)[copiedDataSize], result - copiedDataSize, HTTPST_SELF_FLAGS, timeout);
		}
	}
	
	// ---
	
	return result;
}

static PRInt32 PR_CALLBACK httpst_recv_sized(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpst_Secret* secret;
	PRInt32 result;
	
	// ---
	
	DEBUGLOG("[>] entering httpst recv sized response\n");
	
	// ---
	
	secret = (httpst_Secret*)fd->secret;
	
	// ---
	
	if (secret->isResponseDone == PR_TRUE) {
		return -1;
	}
	
	// ---
	
	if (flags != HTTPST_SELF_FLAGS) {
		result = (PR_GetDefaultIOMethods())->recv(fd, buf, amount, flags, timeout);
	} else {
		result = amount;
	}
	
	// ---
	
	secret->contentLength -= result;
	
	if (secret->contentLength <= 0) {
		secret->isResponseDone = PR_TRUE;
	}
	
	// ---
	
	return result;
}

/* ------------------------------------------------------------------------ */

static PRInt32 PR_CALLBACK httpst_recv_headers(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpst_Secret* secret;
	unsigned int copiedDataSize;
	PRInt32 result;
	char* line;
	
	// ---
	
	DEBUGLOG("[>] entering httpst recv headers\n");
	
	// ---
	
	secret = (httpst_Secret*)fd->secret;
	copiedDataSize = 0;
	line = NULL;
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->recv(fd, buf, amount, flags, timeout);
	
	// ---
	
	while (PR_TRUE) {
		line = readHeaderLine(buf, result, &copiedDataSize, secret->tempBuffer, sizeof(secret->tempBuffer), &(secret->tempBufferPosition));
		
		// +++
		
		if (line == NULL) {
			break;
		} else
		if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0) {
			if (secret->isSocket) {
				secret->recv = httpst_recv_socket;
			} else
			if (secret->isChunkEncoded) {
				secret->recv = httpst_recv_chunked;
			} else
			if (secret->contentLength) {
				secret->recv = httpst_recv_sized;
			} else {
				secret->recv =  httpst_recv_sized;
			}
			
			break;
		}
		
		// +++
		
		if (!secret->isSocket && !secret->isChunkEncoded && !secret->contentLength) {
			if (strstr(line, "upgrade: websocket") != NULL) {
				secret->isSocket = PR_TRUE;
			} else
			if (strstr(line, "transfer-encoding: chunked") != NULL) {
				secret->isChunkEncoded = PR_TRUE;
			} else
			if (sscanf(line, "content-length: %lu", &(secret->contentLength)) != 1) {
				secret->contentLength = 0;
			}
		}
	}
	
	// ---
	
	if (secret->recv != httpst_recv_headers) {
		secret->recv(fd, &((char*)buf)[copiedDataSize], result - copiedDataSize, HTTPST_SELF_FLAGS, timeout);
	}
	
	// ---
	
	return result;
}

/* ------------------------------------------------------------------------ */

static PRInt32 PR_CALLBACK httpst_recv(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	httpst_Secret* secret;
	PRInt32 result;
	
	// ---
	
	DEBUGLOG("[>] entering httpst recv\n");
	
	// ---
	
	secret = (httpst_Secret*)fd->secret;
	
	// ---
	
	result = secret->recv(fd, buf, amount, flags, timeout);
	
	// ---
	
	return result;
}

static PRInt16 PR_CALLBACK httpst_poll(PRFileDesc* fd, PRInt16 in_flags, PRInt16* out_flags) {
	httpst_Secret* secret;
	PRInt16 result;
	
	// ---
	
	DEBUGLOG("[>] entering httpst poll\n");
	
	// ---
	
	secret = (httpst_Secret*)fd->secret;
	
	// ---
	
	if (secret->isResponseDone && in_flags & PR_POLL_READ) {
		DEBUGLOG("[+] causing socket to end due to end of http stream\n");
		
		 *out_flags = PR_POLL_READ;
		result = in_flags;
	} else {
		result = (PR_GetDefaultIOMethods())->poll(fd, in_flags, out_flags);
	}
	
	// ---
	
	return result;
}

static PRStatus PR_CALLBACK httpst_close(PRFileDesc* fd) {
	PRStatus result;
	
	// ---
	
	DEBUGLOG("[>] entering httpst close\n");
	
	// ---
	
	PR_DELETE(fd->secret);
	
	// ---
	
	result = (PR_GetDefaultIOMethods())->close(fd);
	
	// ---
	
	return result;
}

/* ------------------------------------------------------------------------ */

void httpst_ensureInitialized() {
	static PRBool httpst_isInitialized = PR_FALSE;
	
	// ---
	
	const PRIOMethods *stubMethods;
	
	// ---
	
	if (httpst_isInitialized) {
		return;
	}
	
	// ---
	
	httpst_isInitialized = PR_TRUE;
	
	// ---
	
	stubMethods = PR_GetDefaultIOMethods();
	
	// ---
	
	httpst_identity = PR_GetUniqueIdentity("httpst");
	httpst_methods = *stubMethods;
	
	// ---
	
	PR_ASSERT(httpst_identity != PR_INVALID_IO_LAYER);
	
	// ---
	
	httpst_methods.recv = httpst_recv;
	httpst_methods.poll = httpst_poll;
	httpst_methods.close = httpst_close;
}

/* ------------------------------------------------------------------------ */

PRFileDesc* makeSocketHttpAware(PRFileDesc* socket) {
	PRFileDesc* layer;
	httpst_Secret* secret;
	PRStatus rv;
	
	// ---
	
	httpst_ensureInitialized();
	
	// ---
	
	layer = PR_CreateIOLayerStub(httpst_identity, &httpst_methods);
	
	if (layer == NULL) {
		goto makeSocketHttpAwareFalure01;
	}
	
	// ---
	
	secret = PR_NEWZAP(httpst_Secret);
	
	if (secret == NULL) {
		goto makeSocketHttpAwareFalure02;
	} else {
		layer->secret = (void*)secret;
		
		secret->recv = httpst_recv_headers;
	}
	
	// ---
	
	rv = PR_PushIOLayer(socket, PR_GetLayersIdentity(socket), layer);
	
	if (rv == PR_FAILURE) {
		goto makeSocketHttpAwareFalure03;
	}
	
	// ---
	
	return socket;
	
	// ---
	
makeSocketHttpAwareFalure03:
	PR_DELETE(layer->secret);
	
makeSocketHttpAwareFalure02:
	PR_DELETE(layer);
	
makeSocketHttpAwareFalure01:
	return NULL;
}
