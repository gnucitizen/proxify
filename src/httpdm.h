#ifndef HTTPDM_H
#define HTTPDM_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "hexdmp.h"

/* ------------------------------------------------------------------------ */

PRFileDesc* makeSocketObservable(PRFileDesc* stack, char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping);

/* ------------------------------------------------------------------------ */

#endif
