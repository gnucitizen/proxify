#ifndef SIMPLE_H
#define SIMPLE_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "cert.h"
#include "net.h"
#include "struct.h"

/* ------------------------------------------------------------------------ */

ProxyServer* createSimpleProxyServer(ProxyConnector* proxyConnector, char* defaultSubject);
void destorySimpleProxyServer();

/* ------------------------------------------------------------------------ */

#endif
