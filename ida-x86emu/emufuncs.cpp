/*
   Source for x86 emulator IdaPro plugin
   File: emufuncs.cpp
   Copyright (c) 2004, Chris Eagle
   
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option) 
   any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
   more details.
   
   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <windows.h>
#include <winnt.h>

#ifdef CYGWIN
#include <psapi.h>
#endif

#include "cpu.h"
#include "emufuncs.h"
#include "memmgr.h"
#include "hooklist.h"

#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>

#include "../idastruct/idastruct.h"


#define FAKE_HANDLE_BASE 0x80000000

extern ea_t loaded_base;
extern HWND x86Dlg;

struct HandleList {
   char *handleName;
   dword handle;
   dword id;
   dword maxAddr;
   dword NoF;  //NumberOfNames
   dword NoN;  //NumberOfFunctions
   dword *eat; // AddressOfFunctions  export address table
   dword *ent; // AddressOfNames      export name table
   word *eot;  // AddressOfNameOrdinals  export ordinal table
   HandleList *next;
};

static HandleList *moduleHead = NULL;

//stick dummy values up in kernel space to distinguish them from
//actual library handles
static dword moduleHandle = FAKE_HANDLE_BASE;    

//persistant module identifier
static dword moduleId = 1;

typedef enum {R_FAKE = -1, R_NO = 0, R_YES = 1} Reply;

int emu_alwaysLoadLibrary = ASK;
int emu_alwaysGetModuleHandle = ASK;

HookEntry hookTable[] = {
   {"VirtualAlloc", emu_VirtualAlloc},
   {"VirtualFree", emu_VirtualFree},
   {"LocalAlloc", emu_LocalAlloc},
   {"LocalFree", emu_LocalFree},
   {"GetProcAddress", emu_GetProcAddress},
   {"GetModuleHandle", emu_GetModuleHandle},
   {"LoadLibrary", emu_LoadLibrary},
   {"LoadLibraryA", emu_LoadLibrary},
   {"HeapCreate", emu_HeapCreate},
   {"HeapDestroy", emu_HeapDestroy},
   {"HeapAlloc", emu_HeapAlloc},
   {"HeapFree", emu_HeapFree},
   {"GetProcessHeap", emu_GetProcessHeap},
   {"malloc", emu_malloc},
   {"calloc", emu_calloc},
   {"realloc", emu_realloc},
   {"free", emu_free},
   {NULL, NULL}
};

HandleList *findModule(HandleList *l, char *h) {
   HandleList *hl;
   for (hl = l; hl; hl = hl->next) {
      if (stricmp(h, hl->handleName) == 0) break;
   }
   return hl;
}

HandleList *findModule(dword handle) {
   HandleList *hl;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (hl->handle == handle) break;
      if (hl->id == handle) break;       //for compatibility with old handle assignment style
   }
   return hl;
}

unsigned int getPEoffset(HMODULE mod) {
   IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER *) mod;
   if (hdr->e_magic == IMAGE_DOS_SIGNATURE) {
      return hdr->e_lfanew;
   }
   return 0;
}

IMAGE_NT_HEADERS *getPEHeader(HMODULE mod) {
   unsigned int offset = getPEoffset(mod);
   if (offset == 0) return NULL;
   IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)(offset + (char*)mod);
   if (pe->Signature != IMAGE_NT_SIGNATURE) {
      pe = NULL;
   }
   return pe;
}

HandleList *addModule(char *mod, int id) {
   HMODULE h;
   if ((id & FAKE_HANDLE_BASE) != 0) {
      h = (HMODULE)id;
   }
   else {
      h = GetModuleHandle(mod);
   }
   HandleList *m = NULL;
   if (h == NULL && emu_alwaysLoadLibrary != NEVER) {
      int load = R_YES;
      if (id == 0 && emu_alwaysLoadLibrary == ASK) {
         load = askbuttons_c("Yes", "No", "Fake it", 1, "No handle found for %s. Load it now?", mod);
      }
      if (id || load == R_YES) h = LoadLibrary(mod);
      else if (load == R_FAKE) h = (HMODULE) (FAKE_HANDLE_BASE | moduleId++);
   }
   if (h != NULL) {
      m = (HandleList*) calloc(1, sizeof(HandleList));
      m->next = moduleHead;
      moduleHead = m;
      m->handleName = _strdup(mod);
      m->handle = (dword) h;
      m->id = id ? (id & ~FAKE_HANDLE_BASE) : moduleId++;
      if ((id & FAKE_HANDLE_BASE) == 0) {
#ifdef CYGWIN         
         MODULEINFO mi;
         if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) {
            m->maxAddr = mi.SizeOfImage + (dword) h;
         }
#else
         //Microsoft does not see fit to include psapi.h and psapi.lib with Visual Studio
         //You will need the Platform SDK to get access to it, so here is a kludge fix
         m->maxAddr = FAKE_HANDLE_BASE;
#endif
         IMAGE_NT_HEADERS *pe = getPEHeader(h);
         if (pe) {
            DWORD export_dir = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + m->handle;
  
            IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY*) export_dir;
            m->NoF = ed->NumberOfFunctions;
            m->NoN = ed->NumberOfNames;
   
            m->eat = (dword*)(ed->AddressOfFunctions + m->handle);
            m->ent = (dword*)(ed->AddressOfNames + m->handle);
            m->eot = (word*)(ed->AddressOfNameOrdinals + m->handle);
         }
      }
   }
   return m;
}

void freeModuleList() {
   for (HandleList *p = moduleHead; p; moduleHead = p) {
      p = p->next;
      free(moduleHead->handleName);
      free(moduleHead);
   }
   moduleHandle = FAKE_HANDLE_BASE;
}

void loadModuleList(Buffer &b) {
   freeModuleList();
   int n, len;
   b.read((char*)&n, sizeof(n));
   for (int i = 0; i < n; i++) {
/*
      HandleList *m = (HandleList*) malloc(sizeof(HandleList));
      m->next = moduleHead;
      moduleHead = m;
      b.read((char*)&m->handle, sizeof(m->handle));
      if (m->handle > moduleHandle) moduleHandle = m->handle;
      b.read((char*)&len, sizeof(len));
      m->handleName = (char*) malloc(len);
      b.read((char*)m->handleName, len);
*/
      dword id, tempid;
      char *name;
      b.read((char*)&id, sizeof(id));
      tempid = id & ~FAKE_HANDLE_BASE;
      if (tempid > moduleId) moduleId = tempid;
      b.read((char*)&len, sizeof(len));
      name = (char*) malloc(len);
      b.read((char*)name, len);
      HandleList *m = addModule(name, id);
      free(name);
   }
}

void saveModuleList(Buffer &b) {
   int n = 0, len;
   for (HandleList *p = moduleHead; p; p = p->next) n++;
   b.write((char*)&n, sizeof(n));
   for (HandleList *m = moduleHead; m; m = m->next) {
      dword moduleId = m->id | (m->handle & FAKE_HANDLE_BASE); //set high bit of id if using fake handle
      b.write((char*)&moduleId, sizeof(moduleId));
      len = strlen(m->handleName) + 1; //save terminating null
      b.write((char*)&len, sizeof(len));
      b.write((char*)m->handleName, len);
   }
}

/*
 * Build a C string by reading from the specified address until a NULL is
 * encountered.  Returned value must be free'd
 *
 */

char *getString(MemoryManager *mgr, dword addr) {
   int size = 16;
   int i = 0;
   byte *str = NULL, ch;
   str = (byte*) malloc(size);
   if (addr) {
      while (ch = mgr->readByte(addr++)) {
         if (i == size) {
            str = (byte*)realloc(str, size + 16);
            size += 16;
         }
         str[i++] = ch;
      }
      if (i == size) {
         str = (byte*)realloc(str, size + 1);
      }
   }
   str[i] = 0;
   return (char*)str;
}

/*
 * This function is used for all unemulated API functions
 */
void unemulated(MemoryManager *mgr, dword addr) {
   HookNode *n = find(addr);
   static char format[] = "%s called without an emulation. Check your stack layout!\n";
   if (n) {
      int len = sizeof(format) + strlen(n->getName()) + 10;
      char *mesg = (char*) malloc(len);
      qsnprintf(mesg, len, format, n->getName());
      MessageBox(x86Dlg, mesg, "Unemulated", MB_OK);
      msg(format, n->getName());
      free(mesg);
   }
}

/*
   These functions emulate various API calls.  The idea is
   to invoke them after all parameters have been pushed onto the
   stack.  Each function understands its corresponding parameters
   and calling conventions and leaves the stack in the proper state
   with a result in eax.  Because these are invoked from the emulator
   no return address gets pushed onto the stack and the functions can
   get right at their parameters on top of the stack.
*/

void emu_HeapCreate(MemoryManager *mgr, dword addr) {
   /* DWORD flOptions =*/ pop(SIZE_DWORD); 
   /* SIZE_T dwInitialSize =*/ pop(SIZE_DWORD);
   dword dwMaximumSize = pop(SIZE_DWORD);
   //we are not going to try to do growable heaps here
   if (dwMaximumSize == 0) dwMaximumSize = 0x01000000;
   eax = mgr->addHeap(dwMaximumSize);
}

void emu_HeapDestroy(MemoryManager *mgr, dword addr) {
   dword hHeap = pop(SIZE_DWORD); 
   eax = mgr->destroyHeap(hHeap);
}

void emu_GetProcessHeap(MemoryManager *mgr, dword addr) {
   eax = mgr->heap ? mgr->heap->getHeapBase() : 0;
}

void emu_HeapAlloc(MemoryManager *mgr, dword addr) {
   dword hHeap = pop(SIZE_DWORD); 
   /* DWORD dwFlags =*/ pop(SIZE_DWORD);
   dword dwBytes = pop(SIZE_DWORD);
   EmuHeap *h = mgr->findHeap(hHeap);
   //are HeapAlloc  blocks zero'ed?
   eax = h ? h->calloc(dwBytes, 1) : 0;

   struct_init(initial_eip, eax, dwBytes);
}

void emu_HeapFree(MemoryManager *mgr, dword addr) {
   dword hHeap = pop(SIZE_DWORD); 
   /* DWORD dwFlags =*/ pop(SIZE_DWORD);
   dword lpMem = pop(SIZE_DWORD);
   EmuHeap *h = mgr->findHeap(hHeap);
   eax = h ? h->free(lpMem) : 0;
}

void emu_VirtualAlloc(MemoryManager *mgr, dword addr) {
   /*dword lpAddress =*/ pop(SIZE_DWORD); 
   dword dwSize = pop(SIZE_DWORD);
   /*dword flAllocationType =*/ pop(SIZE_DWORD);
   /*dword flProtect =*/ pop(SIZE_DWORD);
   eax = mgr->heap->calloc(dwSize, 1);

   struct_init(initial_eip, eax, dwSize);
}

void emu_VirtualFree(MemoryManager *mgr, dword addr) {
   eax = mgr->heap->free(pop(SIZE_DWORD));
   /*dword dwSize =*/ pop(SIZE_DWORD);
   /*dword dwFreeType =*/ pop(SIZE_DWORD);
}

void emu_LocalAlloc(MemoryManager *mgr, dword addr) {
   /*dword uFlags =*/ pop(SIZE_DWORD); 
   dword dwSize = pop(SIZE_DWORD);
   eax = mgr->heap->malloc(dwSize);

   struct_init(initial_eip, eax, dwSize);
}

void emu_LocalFree(MemoryManager *mgr, dword addr) {
   eax = mgr->heap->free(pop(SIZE_DWORD));
}

static char *lastProcName = NULL;

//funcName should be a library function name, and funcAddr its address
hookfunc checkForHook(char *funcName, dword funcAddr, dword moduleId) {
   int i = 0;
   for (i = 0; hookTable[i].fName; i++) {
      if (!strcmp(hookTable[i].fName, funcName)) {
         //if there is an emulation, hook it
         return addHook(funcName, funcAddr, hookTable[i].func, moduleId);
      }
   }
   //there is no emulation, pass all calls to the "unemulated" stub
   return addHook(funcName, funcAddr, unemulated, moduleId);
}

//FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)
void emu_GetProcAddress(MemoryManager *mgr, dword addr) {
   static dword address = 0x80000000;
   static dword bad = 0xFFFFFFFF;
   dword hModule = pop(SIZE_DWORD); 
   dword lpProcName = pop(SIZE_DWORD);
   FARPROC h = NULL;
   HookNode *n;
   int i;
   HandleList *m = findModule(hModule);
   free(lastProcName);
   if (lpProcName < 0x10000) {
      //getting function by ordinal value
      if (m) {
         char *dot;
         lastProcName = (char*) malloc(strlen(m->handleName) + 16);
         sprintf(lastProcName, "%s_0x%4.4X", m->handleName, m->handle);
         dot = strchr(lastProcName, '.');
         if (dot) *dot = '_';
         if ((m->handle & FAKE_HANDLE_BASE) == 0) {
            h = GetProcAddress((HMODULE)m->handle, (char*)lpProcName);
         }
      }
   }
   else {
      //getting function by name
      lastProcName = getString(mgr, lpProcName);
      if (m && (m->handle & FAKE_HANDLE_BASE) == 0) {
         h = GetProcAddress((HMODULE)m->handle, lastProcName);
      }
   }
   msg("GetProcAddress called: %s", lastProcName);
   //first see if this function is already hooked
   if (n = find(lastProcName)) {
      eax = n->getAddr();
   }
   else {  //this is where we need to check if auto hooking is turned on else if (autohook) {
      //if it wasn't hooked, see if there is an emulation for it
      //use h to replace "address" and "bad" below
      for (i = 0; hookTable[i].fName; i++) {
         if (!strcmp(hookTable[i].fName, lastProcName)) {
            //if there is an emulation, hook it
            eax = h ? (dword)h : address++;
            addHook(lastProcName, eax, hookTable[i].func, m ? m->id : 0);
            break;
         }
      }
      if (hookTable[i].fName == NULL) {
         //there is no emulation, pass all calls to the "unemulated" stub
         eax = h ? (dword)h : bad--;
         addHook(lastProcName, eax, unemulated, m ? m->id : 0);
      }
   }
   msg(" (0x%X)\n", eax);
}

/*
 * This is how we build import tables based on calls to 
 * GetProcAddress: create a label at addr from lastProcName.
 */

void makeImportLabel(dword addr) {
   for (dword cnt = 0; cnt < 4; cnt++) {
      do_unknown(addr, true); //undefine it
   }
   doDwrd(addr, 4);
   if (!set_name(addr, lastProcName, SN_PUBLIC | SN_NOCHECK | SN_NOWARN)) { //failed, probably duplicate name
      //undefine old name and retry once
      dword oldName = get_name_ea(BADADDR, lastProcName);
      if (oldName != BADADDR && del_global_name(oldName)) {
         set_name(addr, lastProcName, SN_PUBLIC | SN_NOCHECK | SN_NOWARN);
      }
   }
}

HandleList *moduleCommon(MemoryManager *mgr, dword addr) {
   dword lpModName = pop(SIZE_DWORD);
   char *modName = getString(mgr, lpModName);
   HandleList *m = findModule(moduleHead, modName);
   if (m) {
      free(modName);
   }
   else {
      m = addModule(modName, 0);
   }
   if (m) {
      msg(" called: %s (%X)\n", m->handleName, m->handle);
   }
   return m;
}

/*
 * To do: Need to mimic actual GetModuleHandle
 *          add .dll extension if no extension provided
 *          return first occurrence if duplicate suffix
 */

//HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)
void emu_GetModuleHandle(MemoryManager *mgr, dword addr) {
   msg("GetModuleHandle");
   HandleList *m = moduleCommon(mgr, addr);
   eax = m->handle;
}

//HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)
void emu_LoadLibrary(MemoryManager *mgr, dword addr) {
   msg("LoadLibrary");
   HandleList *m = moduleCommon(mgr, addr);
   eax = m->handle;
}

void emu_malloc(MemoryManager *mgr, dword addr) {
   dword dwSize = readDword(esp);
   eax = mgr->heap->malloc(dwSize);

   struct_init(initial_eip, eax, dwSize);
}

void emu_calloc(MemoryManager *mgr, dword addr) {
	dword num = readDword(esp);
	dword dwSize = readDword(esp + 4);
    eax = mgr->heap->calloc(num, dwSize);
	
	struct_init(initial_eip, eax, num * dwSize);
}

void emu_realloc(MemoryManager *mgr, dword addr) {
   eax = mgr->heap->realloc(readDword(esp), readDword(esp + 4));
}

void emu_free(MemoryManager *mgr, dword addr) {
   mgr->heap->free(readDword(esp));
}

void doImports(MemoryManager *mgr, dword import_directory, dword image_base) {
   while (1) {
      dword val = get_long(import_directory); //OriginalFirstThunk
      val |= get_long(import_directory + 4);  //TimeDateStamp
      val |= get_long(import_directory + 8); //ForwarderChain
      dword Name = get_long(import_directory + 12);
      dword FirstThunk = get_long(import_directory + 16);
      
      if (val == 0 && Name == 0 && FirstThunk == 0) break;
      char *dllName = getString(mgr, Name + image_base);

      HandleList *m = findModule(moduleHead, dllName);
      if (m == NULL) m = addModule(dllName, 0);
      
      free(dllName);

      dword thunk;
      while ((thunk = get_long(FirstThunk + image_base)) != 0) {
         dword t = FirstThunk + image_base;
         netnode n(t);
         if (netnode_exist(n)) {
            ssize_t size = n.name(NULL, 0);
            if (size > 0) {
               char *funcName = (char*)malloc(size + 1);
               n.name(funcName, size + 1);
               funcName[size] = 0;
//               msg("netnode(%X) exists, name: %s\n", t, funcName);
               FARPROC f;
               if (m->handle & FAKE_HANDLE_BASE) {
                  f = (FARPROC)t;
               }
               else {
                  f = GetProcAddress((HMODULE)m->handle, funcName);
                  reverseLookupExport((dword)f);
               }
               put_long(t, (dword)f);
               if (f) {
                  checkForHook(funcName, (dword)f, m->id);
               }
               free(funcName);
            }
         }
         FirstThunk += 4;
      }      
      import_directory += 20;
   }   
}

//okay to call for ELF, but module list should be empty
HandleList *moduleFromAddress(dword addr) {
   HandleList *hl, *result = NULL;
   dword min = 0;
   for (hl = moduleHead; hl; hl = hl->next) {
#ifdef CYGWIN
      if (addr < hl->maxAddr && addr >= hl->handle) {
         result = hl;
         break;
      }
#else
      //Because MS does not include psapi stuff in Visual Studio
      if (addr > min && addr < hl->maxAddr && addr >= hl->handle) {
         result = hl;
         min = hl->handle;
      }
#endif
   }
   return result;
}

bool isModuleAddress(dword addr) {
   return moduleFromAddress(addr) != NULL;
}

int reverseLookupFunc(dword *EAT, dword func, dword max, dword base) {
   for (unsigned int i = 0; i < max; i++) {
      if ((EAT[i] + base) == func) return i;
   }
   return -1;
}

int reverseLookupOrd(word *EOT, word ord, dword max) {
   for (unsigned int i = 0; i < max; i++) {
      if (EOT[i] == ord) return i;
   }
   return -1;
}

char *reverseLookupExport(dword addr) {
   HandleList *hl;
   for (hl = moduleHead; hl; hl = hl->next) {
      if (addr < hl->maxAddr && addr >= hl->handle) break;
   }
   if (hl == NULL) return NULL;
   if (hl->handle & FAKE_HANDLE_BASE) return NULL;

   int idx = reverseLookupFunc(hl->eat, addr, hl->NoF, hl->handle);
   if (idx != -1) {
      idx = reverseLookupOrd(hl->eot, idx, hl->NoN);
      if (idx != -1) {
//         msg("reverseLookupExport: %X == %s\n", addr, (char*)(hl->ent[idx] + hl->handle));
         return (char*) (hl->ent[idx] + hl->handle);
      }
   }
   return NULL;
}

