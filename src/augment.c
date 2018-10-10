#include "augment.h"

/* ------------------------------------------------------------------------ */

PRFileDesc* augmentSocket(PRFileDesc* socket, char* dumpDirectory, PRBool dumpHex, PRBool enableGunziping) {
	socket = makeSocketObservable(socket, dumpDirectory, dumpHex, enableGunziping);
	
	if (socket == NULL) {
		return NULL;
	}
	
	// ---
	
	return socket;
}
