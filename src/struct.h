#ifndef STRUCT_H
#define STRUCT_H

/* ------------------------------------------------------------------------ */

#include "common.h"

/* ------------------------------------------------------------------------ */

typedef struct ProxyServer_t {
	void* private;
	void (* handleConnection)(struct ProxyServer_t *proxyServer, PRFileDesc* clientSocket);
} ProxyServer;

/* ------------------------------------------------------------------------ */

typedef struct ProxyConnector_t {
	void* private;
	PRFileDesc* (* getSocket)(struct ProxyConnector_t *proxyConnector, char* host, unsigned int port, PRBool isSsl);
} ProxyConnector;

/* ------------------------------------------------------------------------ */

#endif
