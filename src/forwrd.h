#ifndef FORWRD_H
#define FORWRD_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "net.h"
#include "augment.h"
#include "httpst.h"
#include "struct.h"

/* ------------------------------------------------------------------------ */

ProxyConnector* createForwrdProxyConnector(char* forwardHost, PRUint16 forwardPort, char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping);
void destoryForwrdProxyConnector();

/* ------------------------------------------------------------------------ */

#endif
