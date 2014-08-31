/*
   Source for x86 emulator IdaPro plugin
   Copyright (c) 2003,2004,2005 Chris Eagle
   Copyright (c) 2004, Jeremy Cooper
   
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

/*
 *  This is the x86 Emulation plugin module
 *
 *  It is known to compile with
 *
 *      - Visual C++ 6.0
 *
 */

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS 1
#endif

#include <windows.h>
#include <winnt.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include "resource.h"
#include "cpu.h"
#include "memmgr.h"
#include "emufuncs.h"
#include "hooklist.h"
#include "break.h"

#include <allins.hpp>
#include "../idastruct/idastruct.h"

#ifndef CYGWIN
#define strcasecmp stricmp
#endif

void memoryAccessException();

HWND mainWindow;
HFONT fixed;
HWND x86Dlg;
HCURSOR waitCursor;
HMODULE hModule;

// The magic number for verifying the database blob
static const int X86EMU_BLOB_MAGIC = 0x4D363858;  // "X86M"

//The version number with which to tag the data in the
//database storage node
static const int X86EMU_BLOB_VERSION_MAJOR = 0;
static const int X86EMU_BLOB_VERSION_MINOR = 1;

//The node name to use to identify the plug-in's storage
//node in the IDA database.
static const char x86emu_node_name[] = "$ X86 CPU emulator state";

//The IDA database node identifier into which the plug-in will
//store its state information when the database is saved.
static netnode x86emu_node(x86emu_node_name);

//will contain base address for loaded image.  Use with RVAs
ea_t loaded_base;
IMAGE_NT_HEADERS nt;

//Values used by the input dialog box
char value[80]; //value entered by the user
char title[80]; //dynamic title for the input dialog
char prompt[80]; //dynamic prompt for the input dialog
char initial[80]; //dynamic initial value for the input dialog

//This is the original window procedure for the register edit controls
//required in order to subclass the controls to handle double clicks
LONG oldProc;     
LONG oldSegProc;     

//text names for each of the register edit controls
char *names[] = {"EAX", "EBX", "ECX", "EDX", "EBP", 
               "ESP", "ESI", "EDI", "EIP", "EFLAGS"};

//window handles for each of the register edit controls
HWND editBoxes[10];

//A structure to handle all memory accesses
MemoryManager *mgr;

//should align to a 16 byte boundary.  It doesn't initially
//but get fixed in the initialization call. Set to stackTop - 1
//in response to WM_INITDIALOG
dword listTop;

//set to true is saved emulator state is found
bool cpuInit = false;

//callback for events in the emulator window
BOOL CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);

//callback for input dialog events
BOOL CALLBACK InputDlgProc(HWND, UINT, WPARAM, LPARAM);

//subclass procedure for the register edit controls
LRESULT EditSubclassProc(HWND, UINT, WPARAM, LPARAM);

//function to ensure that a particular address is being displayed in the
//stack display area. return true if the address was newly added, false
//if the address was already present
bool ensureDisplay(dword address);

//the memory line at address has changed, update it
void updateMemory(dword address);

//convert a control ID to a pointer to the corresponding register
unsigned int *toReg(int controlID) {
   //offsets from control ID to register set array index
   static int registerMap[8] = {0, 2, -1, -1, 1, -1, 0, 0};

   controlID -= IDC_EAX;
   if (controlID < 8) {
      return &general[controlID + registerMap[controlID]];
   }
   return controlID == 8 ? &eip : &eflags;
}

//update all register displays from existing register values
//useful after a breakpoint or "run to"
//i.e. synchronize the display to the actual cpu/memory values
void syncDisplay() {
   char buf[16];
   for (int i = IDC_EAX; i <= IDC_EFLAGS; i++) {
      unsigned int *reg = toReg(i);
      sprintf(buf, "0x%08X", *reg);
      SetDlgItemText(x86Dlg, i, buf);
   }
//   ensureDisplay(esp);
}

//update the specified register display with the specified 
//value.  useful to update register contents based on user
//input
void updateRegister(int controlID, DWORD val) {
   char buf[16];
   unsigned int *reg = toReg(controlID);
   *reg = val;
   sprintf(buf, "0x%08X", val);
   SetDlgItemText(x86Dlg, controlID, buf);
   if (controlID == IDC_ESP) {
      ensureDisplay(esp);
   }
}

//Tell IDA that the thing at the current eip location is
//code and ask it to change the display as appropriate.
void codeCheck(void) {
   ea_t loc = eip;
   if (isUnknown(getFlags(loc))) {
      auto_make_code(loc); //or ua_code(loc);
   }
   else if (!isHead(getFlags(loc))) {
      while (!isHead(getFlags(loc))) loc--; //find start of current
      do_unknown(loc, true); //undefine it
      auto_make_code(eip); //make code at eip, or ua_code(eip);
   }
}

//get an int value from edit box string
//assumes value is a valid hex string
dword getEditBoxInt(HWND dlg, int dlgItem) {
   char value[80];
   dword newVal = 0;
   GetDlgItemText(dlg, dlgItem, value, 80);
   if (strlen(value) != 0) {
      sscanf(value, "%X", &newVal);
   }
   return newVal;
}

//display a single line input box with the given title, prompt
//and initial data value.  If the user does not cancel, their
//data is placed into the global variable "value"
int inputBox(char *boxTitle, char *msg, char *init) {
   strncpy(title, boxTitle, 80);
   title[79] = 0;
   strncpy(prompt, msg, 80);
   prompt[79] = 0;
   strncpy(initial, init, 80);
   initial[79] = 0;
   int result = DialogBox(hModule, MAKEINTRESOURCE(IDD_INPUTDIALOG),
                          x86Dlg, InputDlgProc);
   return result == 2;
}

//respond to a double click on one of the register
//edit controls, by asking the user for a new
//value for that register
void doubleClick(HWND edit) {
   int idx = 0;
   while (editBoxes[idx] != edit) idx++;
   int ctl = IDC_EAX + idx;
   unsigned int *reg = toReg(ctl);
   char message[32] = "Enter new value for ";
   char original[16];
   strcat(message, names[idx]);
   sprintf(original, "%08X", *reg);
   if (inputBox("Update register", message, original)) {
      dword newVal;
      sscanf(value, "%X", &newVal);
      updateRegister(ctl, newVal);
   }
}

//build the string representaion of a given memory line
//addr should have been 16 byte aligned
char *memoryLine(dword addr) {
   static char buf[80];
   char *temp = buf + 10;
   sprintf(buf, "%08X: ", addr);
   for (int i = 0; i < 16; i++) {
      sprintf(temp, "%02X ", mgr->readByte(addr++));
      temp += 3;
   }
   return buf;
}

//update the memory display at the given address
//first ensure we are displaying this address, and if so
//delete the old values and insert the new ones
void updateStack(dword addr) {
   addr &= 0xFFFFFFF0;
   if (ensureDisplay(addr)) return; 
   dword index = (addr - listTop) / 16;
   SendDlgItemMessage(x86Dlg, IDC_MEMORY, LB_DELETESTRING, index, 0);
   SendDlgItemMessage(x86Dlg, IDC_MEMORY, LB_INSERTSTRING, 
                      index, (LPARAM) memoryLine(addr));
}

//addr should be 16 byte aligned.  Mapping from x86 addresses
//to internal stack address is squirelly due to internal stack
//implementation
void addListEntry(dword addr) {
   SendDlgItemMessage(x86Dlg, IDC_MEMORY, LB_INSERTSTRING, 
                      0, (LPARAM) memoryLine(addr));
}

//ensure that contents of address are being displayed
//in the stack list box
bool ensureDisplay(dword address) {
   address = (address - 1) & 0xFFFFFFF0;
   if (mgr->stack->contains(address)) {
      if (address >= listTop) return false;  //addr is already in the list
      dword oldTop = listTop & 0xFFFFFFF0;
      listTop = address;
      for (dword addr = oldTop - 16; addr >= listTop; addr -= 16) {
         addListEntry(addr);
      }
   }
   return true;
}

dword parseNumber(char *numb) {
   dword val = (dword)strtol(numb, NULL, 0); //any base
   if (val == 0x7FFFFFFF) {
      val = strtoul(numb, NULL, 0); //any base
   }
   return val;
}

//ask the user for space separated data and push it onto the 
//stack in right to left order as a C function would
void pushData() {
   int count = 0;
   if (inputBox("Push Stack Data", "Enter space separated data", "")) {
      char *ptr;
      while (ptr = strrchr(value, ' ')) {
         *ptr++ = 0;
         if (strlen(ptr)) {
            dword val = parseNumber(ptr);
            push(val, SIZE_DWORD);
            count++;
         }
      }
      if (strlen(value)) {
         dword val = parseNumber(value);
         push(val, SIZE_DWORD);
         count++;
      }
   }
   if (count) {
      syncDisplay();
   }
}

//ask user for an address range and dump that address range
//to a user named file;
void dumpRange() {
   char buf[80];
   sprintf(buf, "0x%08X-0x%08X", get_screen_ea(), inf.maxEA);
   if (inputBox("Enter Range", "Enter the address range to dump (inclusive)", buf)) {
      char *end;
      dword start = strtoul(value, &end, 0);
      if (end) {
         dword finish = strtoul(++end, NULL, 0);
         OPENFILENAME ofn;
         char szFile[260];       // buffer for file name
         memset(&ofn, 0, sizeof(ofn));

         // Initialize OPENFILENAME
         ofn.lStructSize = sizeof(ofn);
         ofn.hwndOwner = x86Dlg;
         ofn.lpstrFile = szFile;
         //
         // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
         // use the contents of szFile to initialize itself.
         //
         *szFile = '\0';
         ofn.nMaxFile = sizeof(szFile);
         ofn.lpstrFilter = "All\0*.*\0Text\0*.TXT\0";
         ofn.nFilterIndex = 1;
         ofn.lpstrFileTitle = NULL;
         ofn.nMaxFileTitle = 0;
         ofn.lpstrInitialDir = NULL;
         ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;         
         unsigned char val;
         if (GetSaveFileName(&ofn)) {
            FILE *f = fopen(szFile, "wb");
            for (; start <= finish; start++) {
               val = get_byte(start);           //change this to read out of any location (stack, heap, etc...)
               fwrite(&val, 1, 1, f);
            }
            fclose(f);
         }
      }
   }
}

BOOL CALLBACK SegmentDlgProc(HWND hwndDlg, UINT message, 
                             WPARAM wParam, LPARAM lParam) { 
   char buf[16];
   int i;
   switch (message) { 
      case WM_INITDIALOG: {
         for (i = IDC_CS_REG; i <= IDC_GS_BASE; i++) {
            SendDlgItemMessage(hwndDlg, i, WM_SETFONT, (WPARAM)fixed, FALSE);
            if (i < IDC_CS_BASE) {
               sprintf(buf, "0x%04.4X", segReg[i - IDC_CS_REG]);
            }
            else {
               sprintf(buf, "0x%08X", segBase[i - IDC_CS_BASE]);
            }
            SetDlgItemText(hwndDlg, i, buf);
         }
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
            case IDOK: //OK Button 
               for (i = IDC_CS_REG; i <= IDC_GS_BASE; i++) {
                  dword newVal;
                  GetDlgItemText(hwndDlg, i, buf, 16);
                  sscanf(buf, "%X", &newVal);
                  if (i < IDC_CS_BASE) {
                     segReg[i  - IDC_CS_REG] = (short)newVal;
                  }
                  else {
                     segBase[i - IDC_CS_BASE] = newVal;
                  }
               }
               EndDialog(hwndDlg, 0);
               return TRUE; 
            case IDCANCEL: //CANCEL Button 
               EndDialog(hwndDlg, 0);
               return TRUE; 
         } 
   } 
   return FALSE; 
} 

BOOL CALLBACK MemoryDlgProc(HWND hwndDlg, UINT message, 
                            WPARAM wParam, LPARAM lParam) { 
   switch (message) { 
      case WM_INITDIALOG: {
         char buf[16];
         for (int i = IDC_STACKTOP; i <= IDC_HEAPSIZE; i++) {
            HWND ctl = GetDlgItem(hwndDlg, i);
            SendDlgItemMessage(hwndDlg, i, WM_SETFONT, (WPARAM)fixed, FALSE);
         }
         sprintf(buf, "0x%08X", mgr->stack->getStackTop());
         SetDlgItemText(hwndDlg, IDC_STACKTOP, buf);
         sprintf(buf, "0x%08X", mgr->stack->getStackSize());
         SetDlgItemText(hwndDlg, IDC_STACKSIZE, buf);
         if (mgr->heap) {
            sprintf(buf, "0x%08X", mgr->heap->getHeapBase());
            SetDlgItemText(hwndDlg, IDC_HEAPBASE, buf);
            sprintf(buf, "0x%08X", mgr->heap->getHeapSize());
            SetDlgItemText(hwndDlg, IDC_HEAPSIZE, buf);
         }
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
         case IDOK: {//OK Button 
               mgr->initStack(getEditBoxInt(hwndDlg, IDC_STACKTOP), 
                              getEditBoxInt(hwndDlg, IDC_STACKSIZE));
               esp = mgr->stack->getStackTop();
               unsigned int heapSize = getEditBoxInt(hwndDlg, IDC_HEAPSIZE);
               if (heapSize) {
                  mgr->initHeap(getEditBoxInt(hwndDlg, IDC_HEAPBASE),
                                heapSize);
               }
               EndDialog(hwndDlg, 0);
               SendDlgItemMessage(x86Dlg, IDC_MEMORY, LB_RESETCONTENT, 0, 0);
               listTop = mgr->stack->getStackTop() - 1;
               ensureDisplay(listTop);
               syncDisplay();
               return TRUE; 
            }
         case IDCANCEL: //Cancel Button 
            EndDialog(hwndDlg, 0);
            return TRUE; 
         } 
   } 
   return FALSE; 
}

//ask user for an file name and load the file into memory
//at the specified address
void memLoadFile(dword start) {
   OPENFILENAME ofn;
   char szFile[260];       // buffer for file name
   unsigned char buf[512], *ptr;
   int readBytes;
   memset(&ofn, 0, sizeof(ofn));

   // Initialize OPENFILENAME
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = x86Dlg;
   ofn.lpstrFile = szFile;
   //
   // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
   // use the contents of szFile to initialize itself.
   //
   *szFile = '\0';
   ofn.nMaxFile = sizeof(szFile);
   ofn.lpstrFilter = "All\0*.*\0";
   ofn.nFilterIndex = 1;
   ofn.lpstrFileTitle = NULL;
   ofn.nMaxFileTitle = 0;
   ofn.lpstrInitialDir = NULL;
   ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;         
//   unsigned char val;
   if (GetOpenFileName(&ofn)) {
      FILE *f = fopen(szFile, "rb");
      while ((readBytes = fread(buf, 1, sizeof(buf), f)) > 0) {
         ptr = buf;
         for (; readBytes > 0; readBytes--) {
            writeMem(start++, *ptr++, SIZE_BYTE);
         }
      }
      fclose(f);
   }
}

BOOL CALLBACK SetMemoryDlgProc(HWND hwndDlg, UINT message, 
                               WPARAM wParam, LPARAM lParam) { 
   switch (message) { 
      case WM_INITDIALOG: {
         char buf[32];
         sprintf(buf, "0x%08X", get_screen_ea());
         SendDlgItemMessage(hwndDlg, IDC_MEM_ADDR, WM_SETFONT, (WPARAM)fixed, FALSE);
         SendDlgItemMessage(hwndDlg, IDC_MEM_VALUES, WM_SETFONT, (WPARAM)fixed, FALSE);
         SetDlgItemText(hwndDlg, IDC_MEM_ADDR, buf);
         SetDlgItemText(hwndDlg, IDC_MEM_VALUES, "");
         CheckRadioButton(hwndDlg, IDC_HEX_BYTES, IDC_MEM_LOADFILE, IDC_HEX_DWORDS); 
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
         case IDOK: {//OK Button 
               dword btn;
               dword addr = getEditBoxInt(hwndDlg, IDC_MEM_ADDR);
               dword len = SendDlgItemMessage(hwndDlg, IDC_MEM_VALUES, WM_GETTEXTLENGTH, (WPARAM)0, (LPARAM)0);
               char *vals = (char*) malloc(len + 1);
               char *v = vals;
               GetDlgItemText(hwndDlg, IDC_MEM_VALUES, vals, len + 1);
               vals[len] = 0;
               for (btn = IDC_HEX_BYTES; btn <= IDC_MEM_LOADFILE; btn++) {
                  if (IsDlgButtonChecked(hwndDlg, btn) == BST_CHECKED) break;
               }
               switch (btn) {
               case IDC_MEM_LOADFILE:
                  memLoadFile(addr);
                  break;
               case IDC_MEM_ASCII: case IDC_MEM_ASCIIZ:
                  while (*v) writeMem(addr++, *v++, SIZE_BYTE);
                  if (btn == IDC_MEM_ASCIIZ) writeMem(addr, 0, SIZE_BYTE);
                  break;
               case IDC_HEX_BYTES: case IDC_HEX_WORDS: case IDC_HEX_DWORDS: {
                     dword sz = btn - IDC_HEX_BYTES + 1;
                     char *ptr;
                     while (ptr = strchr(v, ' ')) {
                        *ptr++ = 0;
                        if (strlen(v)) {
                           writeMem(addr, strtoul(v, NULL, 16), sz);
                           addr += sz;
                        }
                        v = ptr;
                     }
                     if (strlen(v)) {
                        writeMem(addr, strtoul(v, NULL, 16), sz);
                     }
                     break;
                  }
               }
               free(vals);
               EndDialog(hwndDlg, 0);
               return TRUE; 
            }
         case IDCANCEL: //Cancel Button 
            EndDialog(hwndDlg, 0);
            return TRUE; 
         } 
   } 
   return FALSE; 
}

static bool doPatchHook = false;

BOOL CALLBACK HookDlgProc(HWND hwndDlg, UINT message, 
                          WPARAM wParam, LPARAM lParam) { 
   switch (message) { 
      case WM_INITDIALOG: {
         char buf[16];
         SendDlgItemMessage(hwndDlg, IDC_CALLLOC, WM_SETFONT, (WPARAM)fixed, FALSE);
         for (int i = 0; hookTable[i].fName; i++) {
            SendDlgItemMessage(hwndDlg, IDC_HOOKNAME, CB_ADDSTRING, 
                               0, (LPARAM)hookTable[i].fName);
         }
         sprintf(buf, "0x%08X", get_screen_ea());
         SetDlgItemText(hwndDlg, IDC_CALLLOC, buf);
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
         case IDOK: {//OK Button 
               unsigned int callAddr = getEditBoxInt(hwndDlg, IDC_CALLLOC);
               int selected = SendDlgItemMessage(hwndDlg, IDC_HOOKNAME, CB_GETCURSEL, 0, 0);
               if (selected != CB_ERR) {
                  if (doPatchHook) {
                     patch_long(callAddr, callAddr);
                  }
                  //We don't have an associated module for this func so pass 0 for id
                  addHook(hookTable[selected].fName, callAddr, hookTable[selected].func, 0);
               }
               EndDialog(hwndDlg, 0);
               return TRUE; 
            }
         case IDCANCEL: //Cancel Button 
            EndDialog(hwndDlg, 0);
            return TRUE; 
         } 
   } 
   return FALSE; 
}

//skip the instruction at eip
void skip() {
   //this relies on IDA's decoding, not our own
   eip += get_item_size(eip);
   syncDisplay();
   jumpto(eip, 0);
}

//This is the main callback function for the emulator interface
BOOL CALLBACK DlgProc(HWND hwndDlg, UINT message, 
                      WPARAM wParam, LPARAM lParam) { 
   switch (message) { 
      case WM_INITDIALOG: {
         x86Dlg = hwndDlg;
         listTop = mgr->stack->getStackTop() - 1;
         if (!cpuInit) {
            eip = get_screen_ea();
         }
         waitCursor = LoadCursor(NULL, IDC_WAIT); 
         for (int i = IDC_EAX; i <= IDC_EFLAGS; i++) {
            HWND ctl = GetDlgItem(hwndDlg, i);
            editBoxes[i - IDC_EAX] = ctl;
            oldProc = SetWindowLong(ctl, GWL_WNDPROC, (LONG) EditSubclassProc);
            SendDlgItemMessage(hwndDlg, i, WM_SETFONT, (WPARAM)fixed, FALSE);
         }
         SendDlgItemMessage(hwndDlg, IDC_MEMORY, WM_SETFONT, (WPARAM)fixed, FALSE);
         addListEntry(mgr->stack->getStackTop() - 16);
         syncDisplay();
         return TRUE; 
      }
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
            case IDC_RESET: //reset the display/emulator
               resetCpu();
               eip = get_screen_ea();
               syncDisplay();
               return TRUE;
            case IDC_STEP: //STEP 
			   codeCheck();			  
               executeInstruction();
               syncDisplay();
               codeCheck();
               jumpto(eip, 0);
               return TRUE; 
            case IDC_JUMP_CURSOR: //Reset eip.cursor
               eip = get_screen_ea();
               syncDisplay();
               jumpto(eip, 0);
               return TRUE;
            case IDC_RUN: {//Run
               codeCheck();
               HCURSOR old = SetCursor(waitCursor);
               while (!isBreakpoint(eip)) {
                  executeInstruction();
               }
               syncDisplay();
               SetCursor(old);
               jumpto(eip, 0);
               return TRUE;
            }
            case IDC_SKIP: //Skip the next instruction
               skip();
               return TRUE;
            case IDC_RUN_TO_CURSOR: {//Run to cursor
               codeCheck();
               HCURSOR old = SetCursor(waitCursor);
               dword endAddr = get_screen_ea();
               while (eip != endAddr) {
                  executeInstruction();
               }
               syncDisplay();
               SetCursor(old);
               return TRUE; 
            }
            case IDC_HIDE: 
               ShowWindow(hwndDlg, SW_HIDE);    
               return TRUE; 
            case IDC_MEMORY:
               if (HIWORD(wParam) == LBN_DBLCLK) {
                  //modify stack contents in here
               }
               return TRUE;
            case IDC_SET_MEMORY:
               DialogBox(hModule, MAKEINTRESOURCE(IDD_SET_MEMORY),
                         x86Dlg, SetMemoryDlgProc);
               return TRUE;
            case IDC_PUSH:
               pushData();
               return TRUE;
            case IDC_DUMP: 
               dumpRange();
               return TRUE;
            case IDC_SEGMENTS: 
               DialogBox(hModule, MAKEINTRESOURCE(IDD_SEGMENTDIALOG),
                         x86Dlg, SegmentDlgProc);
               return TRUE;
            case IDC_SETTINGS: 
               DialogBox(hModule, MAKEINTRESOURCE(IDD_MEMORY),
                         x86Dlg, MemoryDlgProc);
               return TRUE;
            case IDC_VIRTUAL_ALLOC:
               emu_VirtualAlloc(mgr);
               skip();  //now skip the call for stepping purposes
               return TRUE;
            case IDC_VIRTUAL_FREE:
               emu_VirtualFree(mgr);
               skip();  //now skip the call for stepping purposes
               return TRUE;
            case IDC_MALLOC:
               emu_malloc(mgr);
               skip();  //now skip the call for stepping purposes
               return TRUE;
            case IDC_CALLOC:
               emu_calloc(mgr);
               skip();  //now skip the call for stepping purposes
               return TRUE;
            case IDC_REALLOC:
               emu_realloc(mgr);
               skip();  //now skip the call for stepping purposes
               return TRUE;
            case IDC_FREE:
               emu_free(mgr);
               skip();  //now skip the call for stepping purposes
               return TRUE;
            case IDC_HOOK:
               doPatchHook = false;
               DialogBox(hModule, MAKEINTRESOURCE(IDD_HOOKDLG),
                         x86Dlg, HookDlgProc);
               return TRUE;
            case IDC_PATCHHOOK: 
               doPatchHook = true;
               DialogBox(hModule, MAKEINTRESOURCE(IDD_HOOKDLG),
                         x86Dlg, HookDlgProc);
               return TRUE;
            case IDC_GPA: {//set a GetProcAddress save point
               char loc[16];
               qsnprintf(loc, 16, "0x%08X", get_screen_ea());
               if (inputBox("GetProcAddress Save Point", "Specify location of GetProcAddress save", loc)) {
                  sscanf(value, "%X", &gpaSavePoint);
               }
               return TRUE;
            }
            case IDC_BREAKPOINT: {
               char loc[16];
               dword bp;
               qsnprintf(loc, 16, "0x%08X", get_screen_ea());
               if (inputBox("Set Breakpoint", "Specify breakpoint location", loc)) {
                  sscanf(value, "%X", &bp);
                  addBreakpoint(bp);
               }
               return TRUE;
            }
            case IDC_CLEARBREAK: {
               char loc[16];
               dword bp;
               qsnprintf(loc, 16, "0x%08X", get_screen_ea());
               if (inputBox("Remove Breakpoint", "Specify breakpoint location", loc)) {
                  sscanf(value, "%X", &bp);
                  removeBreakpoint(bp);
               }
               return TRUE;
            }
            case IDC_MEMEX:
               initial_eip = eip;  //since we are not going through executeInstruction
               memoryAccessException();
               syncDisplay();
               jumpto(eip, 0);
               return TRUE;
            case IDC_EXPORT: {
               char loc[16];
               dword export_addr;
               qsnprintf(loc, 16, "0x%08X", eax);
               if (inputBox("Export Lookup", "Specify export address", loc)) {
                  sscanf(value, "%X", &export_addr);
                  char *exp = reverseLookupExport(export_addr);
                  if (exp) {
//                     msg("reverseLookupExport: %s\n", exp);
                     int len = 20 + strlen(exp);
                     char *mesg = (char*)malloc(len);
                     qsnprintf(mesg, len, "0x%08X: %s", export_addr, exp);
                     MessageBox(x86Dlg, mesg, "Export Lookup", MB_OK);
                     free(mesg);
                  }
                  else {
//                     msg("reverseLookupExport failed\n");
                     MessageBox(x86Dlg, "No name found", "Export Lookup", MB_OK);
                  }
               }
               return TRUE;
            }
         } 
   } 
   return FALSE; 
} 

//subclassing procedure for the register edit controls.  only want to catch
//double clicks here and open an edit window in response.  Otherwise, pass
//the message along
LRESULT EditSubclassProc(HWND hwndCtl, UINT message, 
                         WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_LBUTTONDBLCLK:
         doubleClick(hwndCtl);
         return TRUE;
   }
   return CallWindowProc((WNDPROC) oldProc, hwndCtl, message, wParam, lParam);
}

//open an input dialog.  Use the globals, title, prompt, and initial to 
//configure the dialog box.  return the user entry in global value
BOOL CALLBACK InputDlgProc(HWND hwndDlg, UINT message, 
                           WPARAM wParam, LPARAM lParam) { 
   switch (message) { 
      case WM_INITDIALOG:
         SendDlgItemMessage(hwndDlg, IDC_DATA, WM_SETFONT, (WPARAM)fixed, FALSE);
         SetDlgItemText(hwndDlg, IDC_MESSAGE, prompt);
         SetDlgItemText(hwndDlg, IDC_DATA, initial);
         SendMessage(hwndDlg, WM_SETTEXT, FALSE, (LPARAM)title);
         return TRUE; 
      case WM_COMMAND: 
         switch (LOWORD(wParam)) { 
            case IDC_DATA: //STEP 
               return TRUE; 
            case ID_OK: //STEP from cursor
               GetDlgItemText(hwndDlg, IDC_DATA, value, 80);
               EndDialog(hwndDlg, 2);
               return TRUE; 
            case ID_CANCEL: //Run
               EndDialog(hwndDlg, -1);
               return TRUE; 
         } 
   } 
   return FALSE; 
} 

//
// Called by IDA to notify the plug-in of certain UI events.
// At the moment this is only used to catch the "saving" event
// so that the plug-in can save its state in the database.
//
static int idaapi uiCallback(void *cookie, int code, va_list va) {
   switch (code) {
   case ui_saving:
      //
      // The user is saving the database.  Save the plug-in
      // state with it.
      //
      x86emu_node.create(x86emu_node_name);
      if (saveState(x86emu_node) == X86EMUSAVE_OK) {
         msg("Emulator state was saved.\n");
      }
      else {
         msg("Emulator state save failed.\n");
      }
      break;
   default:
      break;
   }
   return 0;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
int init(void) {
   dword loadStatus;
   cpuInit = false;
   
   if (strcmp(inf.procName, "metapc")) return PLUGIN_SKIP;
//   if ( ph.id != PLFM_386 ) return PLUGIN_SKIP;

   mainWindow = (HWND)callui(ui_get_hwnd).vptr;

   resetCpu();

   //
   // See if there's a previous CPU state in this database that can
   // be used.
   //
   if (netnode_exist(x86emu_node)) {
      // There's an x86emu node in the database.  Attempt to
      // instantiate the CPU state from it.
      msg("Loading x86emu state from existing netnode.\n");
      loadStatus = loadState(x86emu_node);

      if (loadStatus == X86EMULOAD_OK) {
         cpuInit = true;
         mgr = mm;
      }
      else {
         msg("error restoring x86emu state: %d.\n", loadStatus);
      }
   }
   else {
      msg("No saved x86emu state data was found.\n");
   }
   if (!cpuInit) {
      mgr = new MemoryManager(nextaddr(0), prevaddr(0xFFFFFFFF));
      if (inf.filetype == f_PE) {
         mgr->initStack(0x01300000, 0x01300000);
         enableSEH();
         //typical values for Windows segment registers
         es = ss = ds = 0x23;
         cs = 0x1b;
         fs = 0x38;
      }
      else { //"elf" and others land here
         mgr->initStack(0xC0000000, 0x01000000);
      }
      mgr->initHeap(0xA0000000, 0x01000000); //stick a heap in there
      initProgram(get_screen_ea(), mgr);
   }
   fixed = (HFONT)GetStockObject(ANSI_FIXED_FONT);

   hModule = GetModuleHandle("x86emu.plw");

   idastruct_init();

   return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void term(void)
{
   unhook_from_notification_point(HT_UI, uiCallback, NULL);
   DestroyWindow(x86Dlg); 
   x86Dlg = NULL; 
   delete mgr;
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void run(int arg) {
  if (x86Dlg == NULL) {
      x86Dlg = CreateDialog(hModule, MAKEINTRESOURCE(IDD_EMUDIALOG),
                            mainWindow, DlgProc);
      if (inf.filetype == f_PE) {
         //init some PE specific stuff
         netnode penode("$ PE header");
         loaded_base = penode.altval(-2);
         if(penode.valobj(&nt, sizeof(nt)) < 0)
		 {
			 msg("x86emu fatal error: valobj did not return object\n");
			 return	;
		 }
         
         ea_t import_directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + loaded_base;
//         msg("import directory: %X\n", import_directory);
         doImports(mgr, import_directory, loaded_base);
      }
  }
  if (x86Dlg) {
     ShowWindow(x86Dlg, SW_SHOW);
  }
  hook_to_notification_point(HT_UI, uiCallback, NULL);
}

//--------------------------------------------------------------------------
char comment[] = "This is an x86 emulator";

char help[] =
        "An x86 emulation module\n"
        "\n"
        "This module allows you to step through an x86 program.\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "x86 Emulator";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F8";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
