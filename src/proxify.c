#include "proxify.h"

/* ------------------------------------------------------------------------ */

#define VERSION "3.0"

/* ------------------------------------------------------------------------ */

#define SERVER_BACKLOG 5

/* ------------------------------------------------------------------------ */

#define SSL_CACHE_MAX_ENTRIES 256
#define SSL_CACHE_TIMEOUT 0
#define SSL_CACHE_TIMEOUT3 0
#define SSL_CACHE_DIRECTORY NULL

/* ------------------------------------------------------------------------ */

#define SERVER_CPUS 4

/* ------------------------------------------------------------------------ */

#define SERVER_INITIAL_THREADS 4
#define SERVER_MAX_THREADS 100
#define SERVER_STACK_SIZE (512 * 1024)

/* ------------------------------------------------------------------------ */

#define EXIT_CODE_SUCCESS 0
#define EXIT_CODE_USAGE_FAILURE 1
#define EXIT_CODE_ENVIRONMENT_FAILURE 2
#define EXIT_CODE_DATABASE_DIRECTORY_FAILURE 3
#define EXIT_CODE_CERT_FAILURE 4
#define EXIT_CODE_DISABLE_ALL_SSL_CIPHERS_FAILURE 5
#define EXIT_CODE_DISABLE_SOME_SSL_CIPHERS_FAILURE 6
#define EXIT_CODE_ENABLE_SSL2_FAILURE 7
#define EXIT_CODE_ENABLE_SSL3_FAILURE 8
#define EXIT_CODE_ENABLE_NULL_CIPHERS_FAILURE 9
#define EXIT_CODE_CONFIGURE_SSL_SERVER_SESSION_ID_CACHE 10
#define EXIT_CODE_CREATE_THREAD_POOL_FAILURE 11
#define EXIT_CODE_DUMP_DIRECTORY_FAILURE 12
#define EXIT_CODE_CREATE_PROXY_CONNECTOR_FAILURE 13
#define EXIT_CODE_CREATE_PROXY_SERVER_FAILURE 14
#define EXIT_CODE_RUN_SERVER_FAILURE 15
#define EXIT_CODE_SHUTDOWN_THREAD_POOL_FAILURE 16

/* ------------------------------------------------------------------------ */

static PRBool isRunning = PR_TRUE;

/* ------------------------------------------------------------------------ */

static const char* builtinSubject = "c=US,st=California,l=Mountain View,o=Proxify Inc,ou=QA,cn=";

/* ------------------------------------------------------------------------ */

static ProxyServer* proxyServer = NULL;
static ProxyConnector* proxyConnector = NULL;

/* ------------------------------------------------------------------------ */

static void disclaimer() {
	#ifndef PROPRIATERY_TOOL
		fprintf(
			stderr,
			"Proxify Version %s\n"
			"\n"
			"Copyright 2013 Websecurify. All rights reserved.\n"
			"Commercial use of this software is strictly prohibited.\n"
			"For commercial options please contact us at http://www.websecurify.com/.\n"
			"\n",
			VERSION
		);
	#endif
}

static void usage(char* programName) {
#ifndef PROPRIATERY_TOOL
	fprintf(
		stderr,
		"usage: %s <-p port> [-P port] [-H host] [-z23NSxZ] [-D dir] [-d dir] [-s subject] [-c ciphers]\n"
		"-p starts the proxy defined by local port\n"
		"-P forwards proxied requests to port\n"
		"-H forwards proxied requests to host\n"
		"-x hex dump data on screen\n"
		"-D dump data to directory\n"
		"-Z inflate gzip content\n"
		"-d use database specified in directory\n"
		"-z prevents process zombification\n"
		"-2 disables SSL2\n"
		"-3 disables SSL3\n"
		"-N disables null ciphers\n"
		"-S uses a builtin subject line for not reachable targets\n"
		"-s sets default subject line for not reachable targets\n"
		"-c enables specific ciphers letter(s) chosen from the following list\n"
		"\tA\tSSL2 RC4 128 WITH MD5\n"
		"\tB\tSSL2 RC4 128 EXPORT40 WITH MD5\n"
		"\tC\tSSL2 RC2 128 CBC WITH MD5\n"
		"\tD\tSSL2 RC2 128 CBC EXPORT40 WITH MD5\n"
		"\tE\tSSL2 DES 64 CBC WITH MD5\n"
		"\tF\tSSL2 DES 192 EDE3 CBC WITH MD5\n"
		"\tc\tSSL3 RSA WITH RC4 128 MD5\n"
		"\td\tSSL3 RSA WITH 3DES EDE CBC SHA\n"
		"\te\tSSL3 RSA WITH DES CBC SHA\n"
		"\tf\tSSL3 RSA EXPORT WITH RC4 40 MD5\n"
		"\tg\tSSL3 RSA EXPORT WITH RC2 CBC 40 MD5\n"
		"\ti\tSSL3 RSA WITH NULL MD5\n"
		"\tj\tSSL3 RSA FIPS WITH 3DES EDE CBC SHA\n"
		"\tk\tSSL3 RSA FIPS WITH DES CBC SHA\n"
		"\tl\tSSL3 RSA EXPORT WITH DES CBC SHA\n"
		"\tm\tSSL3 RSA EXPORT WITH RC4 56 SHA\n",
		programName
	);
#endif
}

/* ------------------------------------------------------------------------ */

static void PR_CALLBACK handleConnection(void* argument) {
	PRFileDesc* clientSocket;
	
	// ---
	
	DEBUGLOG("[>] entering handleConnection\n");
	
	// ---
	
	clientSocket = (PRFileDesc*)argument;
	
	// ---
	
	proxyServer->handleConnection(proxyServer, clientSocket);
}

/* ------------------------------------------------------------------------ */

static PRStatus acceptConnections(PRThreadPool* threadPool, PRFileDesc* listenSocket) {
	PRFileDesc* clientSocket;
	PRNetAddr netAddr;
	PRJob* clientJob;
	PRStatus prStatus;
	
	// --
	
	DEBUGLOG("[>] entering acceptConnections\n");
	
	// ---
	
	while (isRunning) {
		DEBUGLOG("[+] accepting socket\n");
		
		clientSocket = PR_Accept(listenSocket, &netAddr, DEFAULT_ACCEPT_TIMEOUT);
		
		if (clientSocket == NULL) {
			DEBUGLOG("[-] cannot accept socket\n");
			
			continue;
		}
		
		// +++
		
		#ifdef DEBUG
			char netAddrStr[80];
			
			prStatus = PR_NetAddrToString(&netAddr, netAddrStr, sizeof(netAddrStr));
			
			if (prStatus == PR_SUCCESS) {
				DEBUGLOG("[+] accepted connection from %s:%d\n", netAddrStr, netAddr.inet.port);
			}
		#endif
		
		// +++
		
		DEBUGLOG("[+] creating queue job\n");
		
		clientJob = PR_QueueJob(threadPool, handleConnection, clientSocket, PR_FALSE);
		
		if (clientJob == NULL) {
			DEBUGLOG("[-] cannot create queue job\n");
			
			// ^^^
			
			DEBUGLOG("[+] closing client socket\n");
			
			prStatus = PR_Close(clientSocket);
			
			if (prStatus != PR_SUCCESS) {
				DEBUGLOG("[-] cannot close client socket\n");
			}
		}
	}
	
	// ---
	
	return PR_SUCCESS;
}

/* ------------------------------------------------------------------------ */

static PRStatus runServer(PRThreadPool* threadPool, PRUint16 serverPort) {
	PRFileDesc* listenSocket;
	PRStatus prStatus;
	PRNetAddr netAddr;
	
	// --
	
	DEBUGLOG("[>] entering runServer\n");
	
	// ---
	
	DEBUGLOG("[+] creating new listening socket\n");
	
	listenSocket = PR_NewTCPSocket();
	
	if (listenSocket == NULL) {
		DEBUGLOG("cannot create new listening socket\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] forcing listening socket to be blocking\n");
	
	prStatus = makeSocketBlocking(listenSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot force listening socket to be blocking\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] forcing listening socket to reuse local address\n");
	
	prStatus = reuseSocketAddress(listenSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot force listening socket to reuse local address\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] forcing listening socket to periodicaly check for alive connection\n");
	
	prStatus = keepSocketAlive(listenSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot force listening socket to periodicaly check for alive connection\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] binding listening socket\n");
	
	netAddr.inet.family = PR_AF_INET;
	netAddr.inet.ip = PR_INADDR_ANY;
	netAddr.inet.port = PR_htons(serverPort);
	
	prStatus = PR_Bind(listenSocket, &netAddr);
	
	if (prStatus == PR_FAILURE) {
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] configuring maximum queue size for pending connections\n");
	
	prStatus = PR_Listen(listenSocket, SERVER_BACKLOG);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot configure maximum queue size for pending connections\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] accepting connections\n");
	
	prStatus = acceptConnections(threadPool, listenSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot accept connections\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	DEBUGLOG("[+] closing listening socket\n");
	
	prStatus = PR_Close(listenSocket);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot close listening socket\n");
		
		goto runServerFailure1;
	}
	
	// ---
	
	return PR_SUCCESS;
	
	// ---
	
runServerFailure1:
	DEBUGLOG("[+] closing listening socket\n");
	
	prStatus = PR_Close(listenSocket);
	
	if (prStatus != PR_SUCCESS) {
		DEBUGLOG("[-] cannot close listening socket\n");
	}
	
	return PR_FAILURE;
}

/* ------------------------------------------------------------------------ */

int main(int argc, char** argv) {
	short exitCode;
	PRBool preventZombification;
	PRBool disableSsl2;
	PRBool disableSsl3;
	PRBool disableNull;
	PRBool enableGunziping;
	char* cipherString;
	char* databaseDirectory;
	char* dumpDirectory;
	PRUint16 serverPort;
	PRUint16 forwardPort;
	char* forwardHost;
	char* defaultSubject;
	PRBool dumpHex;
	char* programName;
	PLOptState* optState;
	PLOptStatus optStatus;
	PRStatus prStatus;
	SECStatus secStatus;
	PRThreadPool* threadPool;
	
	// ---
	
	DEBUGLOG("[>] entering main\n");
	
	// ---
	
	disclaimer();
	
	// ---
	
	exitCode = EXIT_CODE_SUCCESS;
	
	// --
	
	DEBUGLOG("[+] parsing command line\n");
	
	preventZombification = PR_FALSE;
	disableSsl2 = PR_FALSE;
	disableSsl3 = PR_FALSE;
	disableNull = PR_FALSE;
	enableGunziping = PR_FALSE;
	cipherString = NULL;
	databaseDirectory = NULL;
	dumpDirectory = NULL;
	serverPort = 0;
	forwardPort = 0;
	forwardHost = NULL;
	defaultSubject = NULL;
	dumpHex = PR_FALSE;
	programName = PL_strdup(argv[0]);
	optState = PL_CreateOptState(argc, argv, "z23NZc:d:D:p:P:H:s:Sx");
	
	while ((optStatus = PL_GetNextOpt(optState)) == PL_OPT_OK) {
		switch(optState->option) {
			case 'z': preventZombification = PR_TRUE; break;
			case '2': disableSsl2 = PR_TRUE; break;
			case '3': disableSsl3 = PR_TRUE; break;
			case 'N': disableNull = PR_TRUE; break;
			case 'Z': enableGunziping = PR_TRUE; break;
			case 'c': cipherString = PL_strdup(optState->value); break;
			case 'd': databaseDirectory = PL_strdup(optState->value); break;
			case 'D': dumpDirectory = PL_strdup(optState->value); break;
			case 'p': serverPort = atoi(optState->value); break;
			case 'P': forwardPort = atoi(optState->value); break;
			case 'H': forwardHost = PL_strdup(optState->value); break;
			case 's': defaultSubject = PL_strdup(optState->value); break;
			case 'S': defaultSubject = PL_strdup(builtinSubject); break; 
			case 'x': dumpHex = PR_TRUE; break;
			
			default:
			case '?':
				exitCode = EXIT_CODE_USAGE_FAILURE;
				
				PL_DestroyOptState(optState);
				
				goto mainFailureShowUsage1;
		}
	}
	
	PL_DestroyOptState(optState);
	
	if (serverPort == 0) {
		exitCode = EXIT_CODE_USAGE_FAILURE;
		
		goto mainFailureShowUsage1;
	}
	
	// ---
	
	DEBUGLOG("[+] starting environment\n");
	
	prStatus = startupEnvironment();
	
	if (prStatus == PR_FAILURE) {
		RUNLOG("[-] cannot start environment\n");
		
		exitCode = EXIT_CODE_ENVIRONMENT_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	if (databaseDirectory) {
		DEBUGLOG("[+] checking database directory for validity\n");
		
		if (!directoryExists(databaseDirectory)) {
			RUNLOG("[-] cannot find database directory\n");
			
			exitCode = EXIT_CODE_DATABASE_DIRECTORY_FAILURE;
			
			goto mainFailure1;
		}
	}
	
	// ---
	
	DEBUGLOG("[+] starting certcr\n");
	
	secStatus = startupCertcr(databaseDirectory);
	
	if (secStatus == SECFailure) {
		RUNLOG("[-] cannot start certcr\n");
		
		exitCode = EXIT_CODE_CERT_FAILURE;
		
		goto mainFailure1;
	}
	
	// ---
	
	if (cipherString) {
		DEBUGLOG("[+] disabling all ssl ciphers\n");
		
		prStatus = disableAllSslCiphers();
		
		if (prStatus == PR_FAILURE) {
			RUNLOG("[-] cannot disable all ssl ciphers\n");
			
			exitCode = EXIT_CODE_DISABLE_ALL_SSL_CIPHERS_FAILURE;
			
			goto mainFailure2;
		}
		
		// +++
		
		DEBUGLOG("[+] enabling some selected ssl ciphers\n");
		
		prStatus = enableSomeSslCiphers(cipherString);
		
		if (prStatus == PR_FAILURE) {
			RUNLOG("[+] cannot enable selected ssl ciphers\n");
			
			exitCode = EXIT_CODE_DISABLE_SOME_SSL_CIPHERS_FAILURE;
			
			goto mainFailureShowUsage2;
		}
	}
	
	// ---
	
	DEBUGLOG("[+] enabling on ssl v2\n");
	
	secStatus = enableSsl2(!disableSsl2);
	
	if (secStatus == SECFailure) {
		RUNLOG("[-] cannot enable ssl v2\n");
		
		exitCode = EXIT_CODE_ENABLE_SSL2_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	DEBUGLOG("[+] enabling on ssl v3\n");
	
	secStatus = enableSsl3(!disableSsl3);
	
	if (secStatus == SECFailure) {
		RUNLOG("[-] cannot enable ssl v3\n");
		
		exitCode = EXIT_CODE_ENABLE_SSL3_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	DEBUGLOG("[+] enabling null ciphers\n");
	
	secStatus = enableNullCiphers(!disableNull);
	
	if (secStatus == SECFailure) {
		RUNLOG("[-] cannot enable null ciphers\n");
		
		exitCode = EXIT_CODE_ENABLE_NULL_CIPHERS_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	DEBUGLOG("[+] configuring server session id cache\n");
	
	secStatus = SSL_ConfigServerSessionIDCache(SSL_CACHE_MAX_ENTRIES, SSL_CACHE_TIMEOUT, SSL_CACHE_TIMEOUT3, SSL_CACHE_DIRECTORY);
	
	if (secStatus == SECFailure) {
		RUNLOG("[-] cannot configure server session id cache\n");
		
		exitCode = EXIT_CODE_CONFIGURE_SSL_SERVER_SESSION_ID_CACHE;
		
		goto mainFailure2;
	}
	
	// ---
	
	DEBUGLOG("[+] configure concurency\n");
	
	PR_SetConcurrency(SERVER_CPUS);
	
	// ---
	
	DEBUGLOG("[+] creating thread pool\n");
	
	threadPool = PR_CreateThreadPool(SERVER_INITIAL_THREADS, SERVER_MAX_THREADS, SERVER_STACK_SIZE);
	
	if (threadPool == NULL) {
		RUNLOG("[-] cannot create thread pool\n");
		
		exitCode = EXIT_CODE_CREATE_THREAD_POOL_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	if (dumpDirectory) {
		DEBUGLOG("[+] checking dump directory for validity\n");
		
		if (!directoryExists(dumpDirectory)) {
			RUNLOG("[-] cannot find dump directory\n");
			
			exitCode = EXIT_CODE_DUMP_DIRECTORY_FAILURE;
			
			goto mainFailure2;
		}
	}
	
	// ---
	
	DEBUGLOG("[+] create proxy connector\n");
	
	if (forwardPort > 0) {
		proxyConnector = createForwrdProxyConnector(forwardHost, forwardPort, dumpDirectory, dumpHex, enableGunziping);
	} else {
		proxyConnector = createDirectProxyConnector(dumpDirectory, dumpHex, enableGunziping);
	}
	
	if (proxyConnector == NULL) {
		RUNLOG("[-] cannot crate proxy connector\n");
		
		exitCode = EXIT_CODE_CREATE_PROXY_CONNECTOR_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	DEBUGLOG("[+] create proxy server\n");
	
	proxyServer = createSimpleProxyServer(proxyConnector, defaultSubject);
	
	if (proxyServer == NULL) {
		RUNLOG("[-] cannot create proxy server\n");
		
		exitCode = EXIT_CODE_CREATE_PROXY_SERVER_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	if (preventZombification) {
		DEBUGLOG("[+] perventing process zombification\n");
		
		INSTALL_ZOMBIE_VACCINE();
	}
	
	// ---
	
	DEBUGLOG("[+] running server\n");
	
	prStatus = runServer(threadPool, serverPort);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot run server\n");
		
		exitCode = EXIT_CODE_RUN_SERVER_FAILURE;
		
		goto mainFailure3;
	}
	
	// ---
	
	isRunning = PR_FALSE;
	
	// ---
	
	DEBUGLOG("[+] shutting down thread pool\n");
	
	prStatus = PR_ShutdownThreadPool(threadPool);
	
	if (prStatus == PR_FAILURE) {
		RUNLOG("[-] cannot shutdown thread pool\n");
		
		exitCode = EXIT_CODE_SHUTDOWN_THREAD_POOL_FAILURE;
		
		goto mainFailure2;
	}
	
	// ---
	
	DEBUGLOG("[+] shutting down certcr\n");
	
	shutdownCertcr(databaseDirectory);
	
	// ---
	
	DEBUGLOG("[+] shutting down environment\n");
	
	// NOTE: this wont work
	PR_ProcessExit(exitCode); // shutdownEnvironment();
	//
	
	// ---
	
	return exitCode;
	
	// ---
	
mainFailureShowUsage2:
	DEBUGLOG("[+] shutting down certcr\n");
	
	shutdownCertcr(databaseDirectory);
	
	// ---
	
	DEBUGLOG("[+] shutting down environment\n");
	
	// NOTE: this wont work
	PR_ProcessExit(exitCode); // shutdownEnvironment();
	//
	
mainFailureShowUsage1:
	usage(programName);
	
	// ---
	
	return exitCode;
	
mainFailure3:
	isRunning = PR_FALSE;
	
	// ---
	
	DEBUGLOG("[+] shutting down thread pool\n");
	
	prStatus = PR_ShutdownThreadPool(threadPool);
	
	if (prStatus == PR_FAILURE) {
		DEBUGLOG("[-] cannot shutdown thread pool\n");
	}
	
mainFailure2:
	DEBUGLOG("[+] shutting down certcr\n");
	
	shutdownCertcr(databaseDirectory);
	
mainFailure1:
	DEBUGLOG("[+] shutting down environment\n");
	
	// NOTE: this wont work
	PR_ProcessExit(exitCode); // shutdownEnvironment();
	//
	
	// ---
	
	return exitCode;
}
