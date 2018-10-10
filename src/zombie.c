#include "zombie.h"

/* ------------------------------------------------------------------------ */

#ifdef LINUX

#endif

/* ------------------------------------------------------------------------ */

#ifdef WINNT

#define DEFAULT_ZOMBIE_WAIT_TIME (PR_TicksPerSecond() * 1)

// ---

static int getOwnPid() {
	return GetCurrentProcessId();
}

static int getParentPid() {
	int parentPid = -1;
	int ownPid = getOwnPid();
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32 = { 0 };
	
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if(Process32First(handle, &pe32)) {
		do {
			if (pe32.th32ProcessID == ownPid) {
				parentPid = pe32.th32ParentProcessID;
				
				break;
    		}
		} while (Process32Next(handle, &pe32));
	}
	
	CloseHandle(handle);
	
	return parentPid;
}

// ---

static PRBool processExistsByPid(int pid) {
	PRBool exists = PR_FALSE;
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32 = { 0 };
	
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if(Process32First(handle, &pe32)) {
		do {
			if (pe32.th32ProcessID == pid) {
				exists = PR_TRUE;
				
				break;
    		}
		} while (Process32Next(handle, &pe32));
	}
	
	CloseHandle(handle);
	
	return exists;
}

// ---

void PR_CALLBACK checkSelfIfZombie(void* argument) {
	int parentPid = getParentPid();
	PRIntervalTime defaultZombieWaitTime = DEFAULT_ZOMBIE_WAIT_TIME;
	
	while (processExistsByPid(parentPid)) {
		PR_Sleep(defaultZombieWaitTime);
	}
	
	PR_ProcessExit(666);
}

#endif
