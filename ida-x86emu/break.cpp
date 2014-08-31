/*
   break.cpp
   Breakpoint implementation for IdaPro x86 emulator
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

#include <stdlib.h>

static unsigned int *bp_list = 0;

static unsigned int count = 0;
static unsigned int size = 0;

void addBreakpoint(unsigned int addr) {
   if (count == size) {
      bp_list = (unsigned int*) realloc(bp_list, (size + 10) * sizeof(unsigned int));
      size += 10;
   }
   bp_list[count++] = addr;
}

void removeBreakpoint(unsigned int addr) {
   for (unsigned int i = 0; i < count; i++) {
      if (bp_list[i] == addr) {
         bp_list[i] = bp_list[--count];
         break;
      }
   }
}

bool isBreakpoint(unsigned int addr) {
   for (unsigned int i = 0; i < count; i++) {
      if (bp_list[i] == addr) return true;
   }
   return false;
}



