#include "hexdmp.h"

/* ------------------------------------------------------------------------ */

void hexDump(void* data, int size) {
	unsigned char* p = data;
	char bytestr[4] = {0};
	char addrstr[10] = {0};
	char hexstr[16 * 3 + 5] = {0};
	char charstr[16 * 1 + 5] = {0};
	
	//---
	
	unsigned char c;
	int n;
	
	//---
	
	for(n = 1; n <= size; n++) {
		if (n % 16 == 1) {
			PR_snprintf(addrstr, sizeof(addrstr), "%.4x", (*(unsigned int*)p - *(unsigned int*)data));
		}
		
		// +++
		
		c = *p;
		
		// +++
		
		if (isalnum(c) == 0) {
			c = '.';
		}
		
		// +++
		
		PR_snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
		strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
		
		// +++
		
		PR_snprintf(bytestr, sizeof(bytestr), "%c", c);
		strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);
		
		// +++
		
		if(n % 16 == 0) { 
			printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
			
			// ^^^
			
			hexstr[0] = 0;
			charstr[0] = 0;
		} else if(n%8 == 0) {
			strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
			strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
		}
		
		// +++
		
		p++;
	}
	
	// ---
	
	if (strlen(hexstr) > 0) {
		printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
	}
}
