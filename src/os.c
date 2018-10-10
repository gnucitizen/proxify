#include "os.h"

/* ------------------------------------------------------------------------ */

PRBool directoryExists(char* directory) {
	PRDir* dir;
	
	// ---
	
	dir = PR_OpenDir(directory);
	
	if (dir) {
		PR_CloseDir(dir);
		
		// +++
		
		return PR_TRUE;
	}
	
	// ---
	
	return PR_FALSE;
}
