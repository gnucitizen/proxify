#include "net.h"

/* ------------------------------------------------------------------------ */

#define SOCKET_DATA_CHUNK_BUFFER_SIZE 10240

/* ------------------------------------------------------------------------ */

PRStatus getLocalNetAddr(PRUint16 port, PRNetAddr* netAddr) {
	PRStatus prStatus;
	
	// ---
	
	DEBUGLOG("[>] entering getLocalNetAddr\n");
	
	// ---
	
	DEBUGLOG("[+] using loopback address\n");
	
	prStatus = PR_SetNetAddr(PR_IpAddrLoopback, PR_AF_INET, port, netAddr);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot use loopback address\n");
		
		return PR_FAILURE;
	}
	
	// ---
	
	return PR_SUCCESS;
}

PRStatus getRemoteNetAddr(char* host, PRUint16 port, PRNetAddr* netAddr) {
	PRStatus prStatus;
	PRHostEnt hostEntry;
	int hostCount;
	char hostData[PR_NETDB_BUF_SIZE];
	
	// ---
	
	DEBUGLOG("[>] entering getRemoteNetAddr\n");
	
	// ---
	
	DEBUGLOG("[+] obtaining host by name\n");
	
	prStatus = PR_GetHostByName(host, hostData, sizeof(hostData), &hostEntry);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot obtain host by name\n");
		
		return PR_FAILURE;
	}
	
	// ---
	
	DEBUGLOG("[+] creating network address from host and port\n");
	
	hostCount = PR_EnumerateHostEnt(0, &hostEntry, port, netAddr);
	
	if (hostCount < 0) {
		DEBUGLOG("[-] cannot create network address from host and port\n");
		
		return PR_FAILURE;
	}
	
	// ---
	
	return PR_TRUE;
}

/* ------------------------------------------------------------------------ */

PRFileDesc* connectToLocal(PRUint16 port, PRBool isBlocking, PRBool isSsl) {
	PRStatus prStatus;
	SECStatus secStatus;
	PRNetAddr netAddr;
	PRFileDesc* tcpSocket;
	PRFileDesc* sslSocket;
	PRSocketOptionData socketOptionData;
	
	// ---
	
	DEBUGLOG("[>] entering connectToLocal\n");
	
	// ---
	
	sslSocket = NULL;
	
	// ---
	
	DEBUGLOG("[+] getting network address\n");
	
	prStatus = getLocalNetAddr(port, &netAddr);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot get network address\n");
		
		goto connectToLocalCleanup1;
	}
	
	// ---
	
	DEBUGLOG("[+] creating tcp socket\n");
	
	tcpSocket = PR_NewTCPSocket();
	
	if (tcpSocket == NULL) {
		DEBUGLOG("[-] cannot create tcp socket\n");
		
		goto connectToLocalCleanup1;
	}
	
	// ---
	
	if (isBlocking == PR_TRUE) {
		DEBUGLOG("[+] ensuring that tcp socket is blocking\n");
		
		socketOptionData.option = PR_SockOpt_Nonblocking;
		socketOptionData.value.non_blocking = PR_FALSE;
		
		prStatus = PR_SetSocketOption(tcpSocket, &socketOptionData);
		
		if (prStatus == PR_FAILURE) {
			DEBUGLOG("[-] cannot ensure that tcp socket is blocking\n");
			
			goto connectToLocalCleanup2;
		}
	}
	
	// ---
	
	if (isSsl == PR_TRUE) {
		DEBUGLOG("[+] creating ssl socket from tcp socket\n");
		
		sslSocket = makeClientSslSocket(tcpSocket);
		
		if (sslSocket == NULL) {
			goto connectToLocalCleanup2;
		}
		
		tcpSocket = sslSocket;
	}
	
	// ---
	
	DEBUGLOG("[+] connecting to socket\n");
	
	prStatus = PR_Connect(tcpSocket, &netAddr, DEFAULT_CONNECT_TIMEOUT);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot connect to socket\n");
		
		goto connectToLocalCleanup2;
	}
	
	// ---
	
	if (isSsl == PR_TRUE) {
		DEBUGLOG("[+] reseting ssl handshake as client\n");
		
		secStatus = SSL_ResetHandshake(sslSocket, PR_FALSE);
		
		if (secStatus == SECFailure) {
			DEBUGLOG("[-] cannot reset ssl handshake as client\n");
			
			goto connectToLocalCleanup2;
		}
	}
	
	// ---
	
	return tcpSocket;
	
	// ---
	
connectToLocalCleanup2:
	DEBUGLOG("[+] closing tcp socket\n");
	
	prStatus = PR_Close(tcpSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot close tcp socket\n");
	}
	
connectToLocalCleanup1:
	return NULL;
}

PRFileDesc* connectToRemote(char* host, PRUint16 port, PRBool isBlocking, PRBool isSsl) {
	PRStatus prStatus;
	SECStatus secStatus;
	PRNetAddr netAddr;
	PRFileDesc* tcpSocket;
	PRFileDesc* sslSocket;
	PRSocketOptionData socketOptionData;
	
	// ---
	
	DEBUGLOG("[>] entering connectToRemote\n");
	
	// ---
	
	sslSocket = NULL;
	
	// ---
	
	DEBUGLOG("[+] getting network address\n");
	
	prStatus = getRemoteNetAddr(host, port, &netAddr);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot get network address\n");
		
		goto connectToRemoteCleanup1;
	}
	
	// ---
	
	DEBUGLOG("[+] creating tcp socket\n");
	
	tcpSocket = PR_NewTCPSocket();
	
	if (tcpSocket == NULL) {
		DEBUGLOG("[-] cannot create tcp socket\n");
		
		goto connectToRemoteCleanup1;
	}
	
	// ---
	
	if (isBlocking == PR_TRUE) {
		DEBUGLOG("[+] ensuring that tcp socket is blocking\n");
		
		socketOptionData.option = PR_SockOpt_Nonblocking;
		socketOptionData.value.non_blocking = PR_FALSE;
		
		prStatus = PR_SetSocketOption(tcpSocket, &socketOptionData);
		
		if (prStatus == PR_FAILURE) {
			DEBUGLOG("[-] cannot ensure that tcp socket is blocking\n");
			
			goto connectToRemoteCleanup2;
		}
	}
	
	// ---
	
	if (isSsl == PR_TRUE) {
		DEBUGLOG("[+] creating ssl socket from tcp socket\n");
		
		sslSocket = makeClientSslSocket(tcpSocket);
		
		if (sslSocket == NULL) {
			goto connectToRemoteCleanup2;
		}
		
		tcpSocket = sslSocket;
	}
	
	// ---
	
	DEBUGLOG("[+] connecting to socket\n");
	
	prStatus = PR_Connect(tcpSocket, &netAddr, DEFAULT_CONNECT_TIMEOUT);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot connect to socket\n");
		
		goto connectToRemoteCleanup2;
	}
	
	// ---
	
	if (isSsl == PR_TRUE) {
		DEBUGLOG("[+] reseting ssl handshake as client\n");
		
		secStatus = SSL_ResetHandshake(sslSocket, PR_FALSE);
		
		if (secStatus == SECFailure) {
			DEBUGLOG("[-] cannot reset ssl handshake as client\n");
			
			goto connectToRemoteCleanup2;
		}
	}
	
	// ---
	
	return tcpSocket;
	
	// ---
	
connectToRemoteCleanup2:
	DEBUGLOG("[+] closing tcp socket\n");
	
	prStatus = PR_Close(tcpSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot close tcp socket\n");
	}
	
connectToRemoteCleanup1:
	return NULL;
}

/* ------------------------------------------------------------------------ */

PRInt32 forwardSocketDataChunk(PRFileDesc* fromSocket, PRFileDesc* toSocket) {
	char buffer[SOCKET_DATA_CHUNK_BUFFER_SIZE];
	PRInt32 amount;
	
	// ---
	
	DEBUGLOG("[>] entering forwardSocketDataChunk\n");
	
	// ---
	
	DEBUGLOG("[+] receiving from socket\n");
	
	amount = PR_Recv(fromSocket, &buffer, sizeof(buffer), 0, DEFAULT_RECV_TIMEOUT);
	
	if (amount is_PR_Recv_FAILURE) {
		DEBUGLOG("[-] cannot receive from socket due to general failure\n");
		
		return amount;
	} else
	if (amount is_PR_Recv_CLOSED) {
		DEBUGLOG("[-] cannot receive from socket due to connection closed\n");
		
		return amount;
	}
	
	// ---
	
	DEBUGLOG("[+] sending to socket\n");
	
	amount = PR_Send(toSocket, &buffer, amount, 0, DEFAULT_SEND_TIMEOUT);
	
	if (amount is_PR_Send_FAILURE) {
		DEBUGLOG("[-] cannot send to socket due to general failure\n");
		
		return amount;
	} else
	if (amount is_PR_Send_CLOSED) {
		DEBUGLOG("[-] cannot send to socket due to connection closed\n");
		
		return amount;
	}
	
	// ---
	
	return amount;
}

PRInt32 duplicateSocketData(PRFileDesc* socketA, PRFileDesc* socketB) {
	PRPollDesc pollfds[2];
	PRPollDesc* pds;
	PRInt32 status;
	PRIntn npds;
	
	// ---
	
	DEBUGLOG("[>] entering duplicateSocketData\n");
	
	// ---
	
	pds = pollfds;
	
	memset(&pds[0], 0, sizeof(pds[0]));
	memset(&pds[1], 0, sizeof(pds[1]));
	
	pollfds[0].fd = socketA;
	pollfds[0].in_flags = PR_POLL_READ;
	pollfds[1].fd = socketB;
	pollfds[1].in_flags = PR_POLL_READ;
	
	npds = 2;
	
	// ---
	
	DEBUGLOG("[+] duplicating socket data\n");
	
	while (PR_TRUE) {			
		pollfds[0].out_flags = 0;
        pollfds[1].out_flags = 0;
		
		// +++
		
		DEBUGLOG("[+] polling sockets\n");
		
		status = PR_Poll(pds, npds, DEFAULT_IO_TIMEOUT);
		
		if (status is_PR_Poll_FAILURE) {
			DEBUGLOG("[-] cannot poll sockets due to failure\n");
			
			return status;
		} else
		if (status is_PR_Poll_TIMEOUT) {
			DEBUGLOG("[-] cannot poll sockets due to timeout\n");
			
			return status;
		}
		
		// +++
		
		if (pollfds[0].out_flags & PR_POLL_READ) {
			status = forwardSocketDataChunk(pollfds[0].fd, pollfds[1].fd);
			
			if (status <= 0) {
				return status;
			}
		}
		
		if (pollfds[1].out_flags & PR_POLL_READ) {
			status = forwardSocketDataChunk(pollfds[1].fd, pollfds[0].fd);
			
			if (status <= 0) {
				return status;
			}
		}
	}
	
	// ---
	
	DEBUGLOG("[-] duplicateSocketData reached impossible state\n");
	
	// ---
	
	return -1;
}

/* ------------------------------------------------------------------------ */

PRStatus makeSocketBlocking(PRFileDesc* socket) {
	PRSocketOptionData socketOptionData;
	PRStatus prStatus;
	
	// ---
	
	socketOptionData.option = PR_SockOpt_Nonblocking;
	socketOptionData.value.non_blocking = PR_FALSE;
	
	// --
	
	prStatus = PR_SetSocketOption(socket, &socketOptionData);
	
	if (prStatus == PR_SUCCESS) {
		return PR_SUCCESS;
	}
	
	// ---
	
	return PR_FAILURE;
}

PRStatus reuseSocketAddress(PRFileDesc* socket) {
	PRSocketOptionData socketOptionData;
	PRStatus prStatus;
	
	// ---
	
	socketOptionData.option = PR_SockOpt_Reuseaddr;
	socketOptionData.value.reuse_addr = PR_TRUE;
	
	// --
	
	prStatus = PR_SetSocketOption(socket, &socketOptionData);
	
	if (prStatus == PR_SUCCESS) {
		return PR_SUCCESS;
	}
	
	// ---
	
	return PR_FAILURE;
}

PRStatus keepSocketAlive(PRFileDesc* socket) {
	PRSocketOptionData socketOptionData;
	PRStatus prStatus;
	
	// ---
	
	socketOptionData.option = PR_SockOpt_Keepalive;
	socketOptionData.value.reuse_addr = PR_TRUE;
	
	// --
	
	prStatus = PR_SetSocketOption(socket, &socketOptionData);
	
	if (prStatus == PR_SUCCESS) {
		return PR_SUCCESS;
	}
	
	// ---
	
	return PR_FAILURE;
}

/* ------------------------------------------------------------------------ */

char* readCrlfLine(PRFileDesc* fd, char* buf, int len) {
	char* p;
	int i;
	char c;
	PRInt32 n;
	
	// ---
	
	DEBUGLOG("[>] entering readCrlfLine\n");
	
	// ---
	
	p = buf;
	i = 0;
	
	// ---
	
	memset(buf, 0, len);
	
	// ---
	
	while (PR_TRUE) {
		if (i == len) {
			DEBUGLOG("[-] the http line could not be read because we have reached the end of the buffer\n");
			
			return NULL;
		}
		
		// +++
		
		i += 1;
		
		// +++
		
		n = PR_Recv(fd, &c, 1, 0, DEFAULT_RECV_TIMEOUT);
		
		if (n is_PR_Recv_FAILURE) {
			DEBUGLOG("[-] PR_Recv(fd, &c, 1, 0, DEFAULT_RECV_TIMEOUT):n -> generic failure\n");
			
			return NULL;
		} else
		if (n is_PR_Recv_CLOSED) {
			DEBUGLOG("[-] PR_Recv(fd, &c, 1, 0, DEFAULT_RECV_TIMEOUT):n -> connection closed\n");
			
			return NULL;
		} else {
			if (n == 1) {
				if (c == '\n') {
					if (i < len - 2) {
						*p++ = c;
						*p = '\0';
						
						return buf;
					} else {
						DEBUGLOG("[+] the http line could not be read because we don't have enough spice to write the remaining characters\n");
						
						return NULL;
					}
				} else {
					*p++ = c;
				}
			} else {
				DEBUGLOG("[-] we managed to reach an impossible state inside a loop\n");
				
				return NULL;
			}
		}
	}
	
	// ---
	
	DEBUGLOG("[-] we managed to exit an impossible loop\n");
	
	// ---
	
	return NULL;
}
