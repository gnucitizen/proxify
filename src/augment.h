#ifndef AUGMENT_H
#define AUGMENT_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "httpdm.h"

/* ------------------------------------------------------------------------ */

PRFileDesc* augmentSocket(PRFileDesc* socket, char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping);

/* ------------------------------------------------------------------------ */

#endif
