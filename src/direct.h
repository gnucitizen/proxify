#ifndef DIRECT_H
#define DIRECT_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "net.h"
#include "augment.h"
#include "httpst.h"
#include "struct.h"

/* ------------------------------------------------------------------------ */

ProxyConnector* createDirectProxyConnector(char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping);
void destoryDirectProxyConnector();

/* ------------------------------------------------------------------------ */

#endif
