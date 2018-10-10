#include "simple.h"

/* ------------------------------------------------------------------------ */

#define SIMPLE_LINE_BUFFER_SIZE 10240
#define SIMPLE_MAX_REQUEST_LINES 50

/* ------------------------------------------------------------------------ */

static char* mixConnectRequestLines(char* connectLine, char* requestLine, char* prefix, char* destination, unsigned int destinationSize) {
	unsigned int connectLineSize;
	unsigned int requestLineSize;
	unsigned int prefixSize;
	int connectLinePosition;
	int requestLinePosition;
	int prefixPosition;
	int destinationPosition;
	int revertPosition;
	char c;
	
	// ---
	
	DEBUGLOG("[>] entering mixConnectRequestLines\n");
	
	// ---
	
	connectLineSize = (connectLine == NULL ? 0 : PL_strlen(connectLine));
	requestLineSize = (requestLine == NULL ? 0 : PL_strlen(requestLine));
	prefixSize = (prefix == NULL ? 0 : PL_strlen(prefix));
	connectLinePosition = 0;
	requestLinePosition = 0;
	prefixPosition = 0;
	destinationPosition = 0;
	revertPosition = 0;
	
	// ---
	
	#define isConnectLineInBoundries connectLinePosition < connectLineSize
	#define isRequestLineInBoundries requestLinePosition < requestLineSize
	#define isPrefixInBoundries prefixPosition < prefixSize
	#define isDestinationInBoundries destinationPosition < destinationSize
	
	// ---
	
	// NOTE: copy method
	while (PR_TRUE) {
		if (isRequestLineInBoundries && isDestinationInBoundries) {
			c = requestLine[requestLinePosition];
			destination[destinationPosition] = c;
			
			// +++
			
			requestLinePosition += 1;
			destinationPosition += 1;
			
			// +++
			
			if (c == ' ') {
				break;
			}
		} else {
			break;
		}
	}
	//
	
	// ---
	
	// record revert
	revertPosition = destinationPosition;
	//
	
	// ---
	
	// copy prefix
	while (PR_TRUE) {
		if (isPrefixInBoundries && isDestinationInBoundries) {
			c = prefix[prefixPosition];
			destination[destinationPosition] = c;
			
			// +++
			
			prefixPosition += 1;
			destinationPosition += 1;
		} else {
			break;
		}
	}
	//
	
	// ---
	
	// possition netloc
	while (PR_TRUE) {
		if (isConnectLineInBoundries) {
			c = connectLine[connectLinePosition];
			
			// +++
			
			connectLinePosition += 1;
			
			// +++
			
			if (c == ' ') {
				break;
			}
		} else {
			break;
		}
	}
	//
	
	// ---
	
	// copy netloc
	while (PR_TRUE) {
		if (isConnectLineInBoundries && isDestinationInBoundries) {
			c = connectLine[connectLinePosition];
			
			// +++
			
			if (c == ' ') {
				break;
			}
			
			// +++
			
			destination[destinationPosition] = c;
			
			// +++
			
			connectLinePosition += 1;
			destinationPosition += 1;
		} else {
			break;
		}
	}
	//
	
	// ---
	
	// possition rest
	if (isRequestLineInBoundries) {
		c = requestLine[requestLinePosition];
		
		if (c != '/') {
			destinationPosition = revertPosition;
		}
	}
	//
	
	// ---
	
	// copy rest
	while (PR_TRUE) {
		if (isRequestLineInBoundries && isDestinationInBoundries) {
			c = requestLine[requestLinePosition];
			destination[destinationPosition] = c;
			
			// +++
			
			requestLinePosition += 1;
			destinationPosition += 1;
		} else {
			break;
		}
	}
	//
	
	// ---
	
	// ensure null terminated string
	if (isDestinationInBoundries) {
		destination[destinationPosition] = '\0';
	} else
	if (destinationSize > 0) {
		destination[destinationSize - 1] = '\0';
	}
	//
	
	// ---
	
	return destination;
}

/* ------------------------------------------------------------------------ */

typedef struct simple_ProxyServerPrivate_t {
	ProxyConnector* proxyConnector;
	char* defaultSubject;
} simple_ProxyServerPrivate;

/* ------------------------------------------------------------------------ */

// REFERENCE: The basic strategy evolves around the following mechanism
// 1. Read the first line from the client socket
// 2. if first line starts with CONNECT
//    A. read the rest of the request up to SIMPLE_MAX_REQUEST_LINES
//    B. ensure valid certificate database entry
//       a. Send connection 200 or 404 depending on if we have valid
//          certificate database entry
//    C. start ssl on the client
//    D. read the first line from the client ssl socket
//    E. rewrite first line augmenting it with the information from the
//       initial first line
// 3. get socket from connector
// 4. send read/rewritten first line
// 5. copy over client socket data to server socket and vice versa
//    A. the connector has the responsability to close the socket

/* ------------------------------------------------------------------------ */

static void simple_handleConnection(ProxyServer* proxyServer, PRFileDesc* clientSocket) {
	simple_ProxyServerPrivate* proxyServerPrivate;
	ProxyConnector* proxyConnector;
	char* defaultSubject;
	PRStatus prStatus;
	SECStatus secStatus;
	PRFileDesc* serverSocket;
	PRFileDesc* sslSocket;
	PRBool isSsl;
	int scanResult;
	char method[256];
	char host[256];
	unsigned int port;
	int i;
	int headersCount;
	PRInt32 bytesSent;
	CertificateDatabaseEntry* certificateDatabaseEntry;
	char firstLineBuff[SIMPLE_LINE_BUFFER_SIZE];
	char* firstLine;
	char tmpLineBuff[SIMPLE_LINE_BUFFER_SIZE];
	char* tmpLine;
	char sslFirstLineBuff[SIMPLE_LINE_BUFFER_SIZE];
	char* sslFirstLine;
	char newFirstLineBuff[SIMPLE_LINE_BUFFER_SIZE];
	
	// ---
	
	DEBUGLOG("[>] entering handleConnection\n");
	
	// ---
	
	proxyServerPrivate = (simple_ProxyServerPrivate*)proxyServer->private;
	proxyConnector = proxyServerPrivate->proxyConnector;
	defaultSubject = proxyServerPrivate->defaultSubject;
	
	// ---
	
	DEBUGLOG("[+] reinforcing socket to be blocking\n");
	
	prStatus = makeSocketBlocking(clientSocket);
	
	if (prStatus != PR_SUCCESS) {
		DEBUGLOG("[+] cannot reinfore socket to be blocking\n");
		
		PR_Close(clientSocket);
		
		return;
	}
	
	// ---
	
	DEBUGLOG("[+] reading first line from the client socket\n");
	
	firstLine = readCrlfLine(clientSocket, firstLineBuff, sizeof(firstLineBuff));
	
	if (firstLine == NULL) {
		DEBUGLOG("[-] cannot read first line from client socket\n");
		
		PR_Close(clientSocket);
		
		return;
	}
	
	// ---
	
	DEBUGLOG("[+] first line is %s", firstLine);
	
	// ---
	
	DEBUGLOG("[+] parsing CONNECT method\n");
	
	scanResult = sscanf(firstLine, "CONNECT %255[^:]:%u\r\n", host, &port);
	
    if (scanResult != 2) {
		if (strncmp(firstLine, "CONNECT ", 8) == 0) {
			DEBUGLOG("[-] cannot parse CONNECT method\n");
			
			PR_Close(clientSocket);
			
			return;
		} else {
			DEBUGLOG("[+] CONNECT method not found\n");
		}
		
		// +++
		
		tmpLine = tmpLineBuff;
		
		for(i = 0; firstLine[i]; i++) {
			tmpLine[i] = tolower(firstLine[i]);
		}
		
		tmpLine[i + 1] = '\0';
		
		// +++
		
		if (sscanf(tmpLine, "%255s http://%255[^:]:%u", method, host, &port) == 3) {
			isSsl = PR_FALSE;
		} else
		if (sscanf(tmpLine, "%255s https://%255[^:]:%u", method, host, &port) == 3) {
			isSsl = PR_TRUE;
		} else
		if (sscanf(tmpLine, "%255s http://%255[^\x20/]", method, host) == 2) {
			isSsl = PR_FALSE;
			port = 80;
		} else
		if (sscanf(tmpLine, "%255s https://%255[^\x20/]", method, host) == 2) {
			isSsl = PR_TRUE;
			port = 443;
		} else {
			DEBUGLOG("[-] cannot parse host and port from initial line\n");
			
			PR_Close(clientSocket);
			
			return;
		}
	} else {
		// TODO: this is kind of a hack
		if (port == 80) {
			isSsl = PR_FALSE;
		} else {
			isSsl = PR_TRUE;
		}
		//
		
		// +++
		
		DEBUGLOG("[+] reading the rest of the request up to %d lines\n", SIMPLE_MAX_REQUEST_LINES);
		
		headersCount = 0;
		
		while (PR_TRUE) {
			headersCount += 1;
			
			// +++
			
			DEBUGLOG("[+] reading header line\n");
			
			tmpLine = readCrlfLine(clientSocket, tmpLineBuff, sizeof(tmpLineBuff));
			
			if (tmpLine == NULL) {
				DEBUGLOG("[-] cannot read header line\n");
				
				PR_Close(clientSocket);
				
				return;
			}
			
			if (strncmp(tmpLine, "\r\n", 2) == 0) {
				break;
			}
			
			if (headersCount == SIMPLE_MAX_REQUEST_LINES) {
				DEBUGLOG("[-] cannot read the rest of the request up to %d lines\n", SIMPLE_MAX_REQUEST_LINES);
				
				PR_Close(clientSocket);
				
				return;
			}
		}
		
		// +++
		
		certificateDatabaseEntry = NULL;
		
		// +++
		
		if (isSsl) {
			DEBUGLOG("[+] ensuring certificate database entry\n");
			
			certificateDatabaseEntry = ensureCertificateDatabaseEntry(host, port, defaultSubject);
			
			if (certificateDatabaseEntry == NULL) {
				DEBUGLOG("[+] cannot ensure certificate database entry\n");
				
				PR_Send(clientSocket, "HTTP/1.1 404 Not Found\r\n\r\n", 26, 0, DEFAULT_SEND_TIMEOUT);
				PR_Close(clientSocket);
				
				return;
			}
		}
		
		// +++
		
		DEBUGLOG("[+] sending connection OK message\n");
		
		bytesSent = PR_Send(clientSocket, "HTTP/1.0 200 OK\r\n\r\n", 19, 0, DEFAULT_SEND_TIMEOUT);
		
		if (bytesSent is_PR_Send_FAILURE) {
			DEBUGLOG("[-] cannot send connection OK message due to generic failure\n");
			
			PR_Close(clientSocket);
			
			return;
		} else
		if (bytesSent is_PR_Send_CLOSED) {
			DEBUGLOG("[-] cannot send connection OK message due to connection being closed\n");
			
			PR_Close(clientSocket);
			
			return;
		}
		
		// +++
		
		if (isSsl) {
			DEBUGLOG("[+] making ssl server\n");
			
			sslSocket = makeServerSslSocket(clientSocket, certificateDatabaseEntry->certificate, certificateDatabaseEntry->privateKey);
			
			if (sslSocket == NULL) {
				DEBUGLOG("[+] cannot make ssl server\n");
				
				PR_Close(clientSocket);
				
				return;
			}
			
			// ^^^
			
			clientSocket = sslSocket;
			
			// ^^^
			
			DEBUGLOG("[+] resetting ssl handshake\n");
			
			secStatus = SSL_ResetHandshake(clientSocket, PR_TRUE);
			
			if (secStatus == SECFailure) {
				DEBUGLOG("[-] cannot reset ssl handshake\n");
				
				// NOTE: we don't need to do this
				// PR_Close(clientSocket);
				//
				
				PR_Close(clientSocket);
				
				return;
			}
		}
		
		// +++
		
		DEBUGLOG("[+] reading the first line from client socket\n");
		
		sslFirstLine = readCrlfLine(clientSocket, sslFirstLineBuff, sizeof(sslFirstLineBuff));
		
		if (sslFirstLine == NULL) {
			DEBUGLOG("[-] cannot read the first line from the ssl socket\n");
			
			// NOTE: we don't need to do this
			// PR_Close(clientSocket);
			//
			
			PR_Close(clientSocket);
			
			return;
		}
		
		// +++
		
		DEBUGLOG("[+] first ssl line is %s", sslFirstLine);
		
		// +++
		
		DEBUGLOG("[+] rewrite first line\n");
		
		firstLine = mixConnectRequestLines(firstLine, sslFirstLine, "https://", (char*)&newFirstLineBuff, sizeof(newFirstLineBuff));
		
		// +++
		
		DEBUGLOG("[+] first line rewritten to %s", firstLine);
	}
	
	// ---
	
	DEBUGLOG("[+] obtaining connector socket\n");
	
	serverSocket = proxyConnector->getSocket(proxyConnector, host, port, isSsl);
	
	if (serverSocket == NULL) {
		DEBUGLOG("[-] cannot obtain connector socket\n");
		
		PR_Close(clientSocket);
		
		return;
	}
	
	// ---
	
	DEBUGLOG("[+] sending first line\n");
	
	bytesSent = PR_Send(serverSocket, firstLine, (int)PL_strlen(firstLine), 0, DEFAULT_RECV_TIMEOUT);
	
	if (bytesSent is_PR_Send_FAILURE) {
		DEBUGLOG("[-] cannot send first line due to generic failure\n");
		
		PR_Close(serverSocket);
		PR_Close(clientSocket);
		
		return;
	} else
	if (bytesSent is_PR_Send_CLOSED) {
		DEBUGLOG("[-] cannot send first line due to connection being closed\n");
		
		PR_Close(serverSocket);
		PR_Close(clientSocket);
		
		return;
	}
	
	// ---
	
	DEBUGLOG("[+] copy data over\n");
	
	// TODO: handle errors perhaps?
	duplicateSocketData(clientSocket, serverSocket);
	//
	
	// ---
	
	DEBUGLOG("[+] closing server socket\n");
	
	// TODO: handle errors perhaps?
	PR_Close(serverSocket);
	//
	
	// ---
	
	DEBUGLOG("[+] closing client socket\n");
	
	// TODO: handle errors perhaps?
	PR_Close(clientSocket);
	//
}

/* ------------------------------------------------------------------------ */

ProxyServer* createSimpleProxyServer(ProxyConnector* proxyConnector, char* defaultSubject) {
	simple_ProxyServerPrivate* proxyServerPrivate;
	ProxyServer* proxyServer;
	
	// ---
	
	if (proxyConnector == NULL) {
		goto createSimpleProxyServerFailure01; 
	}
	
	// ---
	
	proxyServerPrivate = PR_NEWZAP(simple_ProxyServerPrivate);
	
	if (proxyServerPrivate == NULL) {
		goto createSimpleProxyServerFailure01;
	}
	
	// ---
	
	proxyServerPrivate->proxyConnector = proxyConnector;
	proxyServerPrivate->defaultSubject = defaultSubject;
	
	// ---
	
	proxyServer = PR_NEWZAP(ProxyServer);
	
	if (proxyServer == NULL) {
		goto createSimpleProxyServerFailure02;
	}
	
	// ---
	
	proxyServer->private = proxyServerPrivate;
	proxyServer->handleConnection = simple_handleConnection;
	
	// ---
	
	return proxyServer;
	
	// ---
	
createSimpleProxyServerFailure02:
	PR_DELETE(proxyServerPrivate);
	
createSimpleProxyServerFailure01:
	return NULL;
}

void destroySimpleProxyServer(ProxyServer* proxyServer) {
	PR_DELETE(proxyServer->private);
	PR_DELETE(proxyServer);
}
