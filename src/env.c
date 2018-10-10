#include "env.h"

/* ------------------------------------------------------------------------ */

PRStatus startupEnvironment() {
	DEBUGLOG("[>] entering startupEnvironment\n");
	
	// ---
	
	DEBUGLOG("[+] initializing nspr\n");
	
	PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
	
	// ---
	
	return PR_SUCCESS;
}

PRStatus shutdownEnvironment() {
	DEBUGLOG("[>] entering shutdownEnvironment\n");
	
	// ---
	
	DEBUGLOG("[+] deinitializing nspr\n");
	
	PR_Cleanup();
	
	// ---
	
	return PR_SUCCESS;
}
