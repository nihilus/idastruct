/*
   Headers for x86 emulator
   Copyright (c) 2003, Chris Eagle
   
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

#ifndef __X86DEFS_H
#define __X86DEFS_H

#ifndef __IDP__

#ifndef WIN32

#include <sys/types.h>
typedef int64_t quad;
typedef u_int64_t uquad;

#else   //WIN32

typedef __int64 quad;
typedef unsigned __int64 uquad;

#endif  //WIN32

typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;

#else   //#ifdef __IDP__

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif  // USE_DANGEROUS_FUNCTIONS

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>

typedef __int64 quad;
typedef unsigned __int64 uquad;

extern ea_t loaded_base;

#endif

//#include "memmgr.h"

typedef uchar  byte;
typedef ushort word;
typedef uint   dword;
typedef uquad  qword;

#define CARRY 0x1
#define PARITY 0x4
#define AUX_CARRY 0x10
#define ZERO  0x40
#define SIGN 0x80
#define TRAP 0x100
#define INTERRUPT 0x200
#define DIRECTION 0x400
#define OVERFLOW 0x800

#define CF CARRY
#define PF PARITY
#define AF AUX_CARRY
#define ZF ZERO
#define SF SIGN
#define TF TRAP
#define IF INTERRUPT
#define DF DIRECTION
#define OF OVERFLOW

#define D (eflags & DF)

#define SET(x) (eflags |= (x))
#define CLEAR(x) (eflags &= (~x))

#define O (eflags & OF)
#define NO (!(eflags & OF))

#define B (eflags & CF)
#define C B
#define NAE B
#define NB (!(eflags & CF))
#define AE NB
#define NC NB

#define E (eflags & ZF)
#define Z E
#define NE (!(eflags & ZF))
#define NZ NE

#define BE (eflags & (ZF | CF))
#define NA BE
#define NBE (!(eflags & (ZF | CF)))
#define A NBE

#define S (eflags & SF)
#define NS (!(eflags & SF))

#define P (eflags & PF)
#define PE P
#define NP (!(eflags & PF))
#define PO NP

#define L (((eflags & (SF | OF)) == SF) || \
          ((eflags & (SF | OF)) == OF))
#define NGE L
#define NL (((eflags & (SF | OF)) == 0) || \
           ((eflags & (SF | OF)) == (SF | OF)))
#define GE NL

#define LE (((eflags & (SF | OF)) == SF) || \
           ((eflags & (SF | OF)) == OF)  || Z)
#define NG LE
#define NLE ((((eflags & (SF | OF)) == 0) || \
            ((eflags & (SF | OF)) == (SF | OF))) && NZ)
#define G NLE

#define H_MASK 0x0000FF00

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3
#define ESP 4
#define EBP 5
#define ESI 6
#define EDI 7

#define eax (general[EAX])
#define ecx (general[ECX])
#define edx (general[EDX])
#define ebx (general[EBX])
#define esp (general[ESP])
#define ebp (general[EBP])
#define esi (general[ESI])
#define edi (general[EDI])

#define CS 0
#define SS 1
#define DS 2
#define ES 3
#define FS 4
#define GS 5

#define cs (segReg[CS])
#define ss (segReg[SS])
#define ds (segReg[DS])
#define es (segReg[ES])
#define fs (segReg[FS])
#define gs (segReg[GS])

#define csBase (segBase[CS])
#define ssBase (segBase[SS])
#define dsBase (segBase[DS])
#define esBase (segBase[ES])
#define fsBase (segBase[FS])    //FS:[0] -> SEH for Win32
#define gsBase (segBase[GS])

#define CR0 0
#define CR1 1
#define CR2 2
#define CR3 3
#define CR4 4

#define cr0 (control[CR0])
#define cr1 (control[CR1])
#define cr2 (control[CR2])
#define cr3 (control[CR3])
#define cr4 (control[CR4])

#define DR0 0
#define DR1 1
#define DR2 2
#define DR3 3
#define DR4 4
#define DR5 5
#define DR6 6
#define DR7 7

#define dr0 (debug_regs[DR0])
#define dr1 (debug_regs[DR1])
#define dr2 (debug_regs[DR2])
#define dr3 (debug_regs[DR3])
#define dr4 (debug_regs[DR4])
#define dr5 (debug_regs[DR5])
#define dr6 (debug_regs[DR6])
#define dr7 (debug_regs[DR7])

#define MOD_0 0
#define MOD_1 0x40
#define MOD_2 0x80
#define MOD_3 0xC0

#define RM(x)     ((x) & 0x07)
#define MOD(x)    ((x) & 0xC0)
#define REG(x) (((x) >> 3) & 0x07)
#define HAS_SIB(x) (RM(x) == 4)

#define SCALE(x) (1 << ((x) >> 6))
#define INDEX(x) (((x) >> 3) & 0x07)
#define BASE(x)  ((x) & 0x07)

/*
typedef struct _DescriptorTableReg_t {
   dword base;
   word limit;
} DescriptorTableReg;

extern dword debug_regs[8];
extern dword general[8];
extern dword initial_eip;
extern dword eip;
extern dword eflags;
extern dword control[5];
extern dword segBase[6];   //cached segment base addresses
extern word segReg[6];
extern DescriptorTableReg gdtr;
extern DescriptorTableReg idtr;
*/

#define PREFIX_LOCK  0x01
#define PREFIX_REPNE 0x02
#define PREFIX_REP   0x04
#define PREFIX_CS    0x08
#define PREFIX_SS    0x10
#define PREFIX_DS    0x20
#define PREFIX_ES    0x40
#define PREFIX_FS    0x80
#define PREFIX_GS    0x100
#define PREFIX_SIZE    0x200
#define PREFIX_ADDR    0x400
#define PREFIX_SIMD    0x800

#define SEG_MASK     0x1F8

//operand types
#define TYPE_REG  1
#define TYPE_IMM  2
#define TYPE_MEM  4

//operand sizes
#define SIZE_BYTE 1
#define SIZE_WORD 2
#define SIZE_DWORD 4

void updateStack(dword addr);

/*
//masks to clear out bytes appropriate to the sizes above
extern dword SIZE_MASKS[5];

//masks to clear out bytes appropriate to the sizes above
extern dword SIGN_BITS[5];

//masks to clear out bytes appropriate to the sizes above
extern qword CARRY_BITS[5];

extern byte BITS[5];

extern dword gpaSavePoint;

typedef struct _AddrInfo_t {
   dword addr;
   byte type;
} AddrInfo;

//struct to describe an instruction being decoded
typedef struct _inst {
   AddrInfo source;
   AddrInfo dest;
   dword opsize;  //operand size for this instruction
   dword prefix;  //any prefix flags
   byte opcode;   //opcode, first or second byte (if first == 0x0F)
} inst;

void initProgram(unsigned int entry, MemoryManager *mgr);
void enableSEH();

void resetCpu();

void push(dword val, byte size);
dword pop(byte size);
dword readDword(dword addr);
void writeMem(dword addr, dword val, byte size);
dword readMem(dword addr, byte size);

int executeInstruction();

*/
#endif
