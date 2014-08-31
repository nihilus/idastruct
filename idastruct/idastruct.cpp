#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <intel.hpp>
#include <funcs.hpp>
#include <nalt.hpp>
#include <struct.hpp>

#include "idastruct.h"
#include "../ida-x86emu/cpu.h"
#include "../ida-x86emu/x86defs.h"

struct _options options;
strace_t *strace = NULL;

struct _alloc_hist *alloc_hist = NULL;

// table of known allocator functions and arg offsets 
// -- deprecated in favor of emufuncs hooks 
struct _alloc_function alloc_functions[] = { 
// func			 sz  num
{ "VirtualAlloc", 4,  -1  }, 
{ "HeapAlloc",    8,  -1  },
{ "LocalAlloc",   4,  -1  },
{ "malloc",       0,  -1  },
{ "calloc",       4,   0  },
{ "_qcalloc",     4,   0  },
{ 0, 0 }
};


/*

typedef struct _itrace {
	ea_t addr;				// address of reference
	unsigned short off;		// struct offset
	unsigned char  reftype; // RWX
	unsigned char  len;		// value len
} itrace_t; 

typedef struct _strace { 
	struct _strace *next;
	ea_t addr;			// originating addr for this struct
	struct_t *sptr;		// ida struct ptr
	unsigned int base;	// identified base ptr (return from call)
	unsigned int size;	// struct size
	struct _itrace *itrace; // instruction trace
} strace_t;


//// struct creation logic ////

emu_allocfunc hook:			// added at end of emulated
							// allocator functions

		struct_init(addr, base, size)

//// tracing logic ////

executeInstruction_hook:	// added at end of function

	// check if src or dst are deref'd and where they are stored
	if(strace)
		struct_trace(addr);

executeInstruction_hook_end:


if src operand == addr in struct range
	add_trace(dst operand value)
	
if dst operand == deref && in struct range
	add struct member
*/


// wrapper function for add_struc_member with nice error msgs
int struct_member_add(struc_t *sptr, char *name, ea_t offset, 
					  flags_t flag, typeinfo_t *type, asize_t nbytes)
{
	int ret = add_struc_member(sptr, name, offset, flag, type, nbytes);
	switch(ret)
	{
		case STRUC_ERROR_MEMBER_NAME: 
			msg("[idastruct] error: already has member with this name (bad name)\n");
			break;
		case STRUC_ERROR_MEMBER_OFFSET: 
			msg("[idastruct] error: already has member at this offset\n");
			break;
		case STRUC_ERROR_MEMBER_SIZE: 
			msg("[idastruct] error: bad number of bytes or bad sizeof(type)\n");
			break;
		case STRUC_ERROR_MEMBER_TINFO: 
			msg("[idastruct] error: bad typeid parameter\n");
			break;
		case STRUC_ERROR_MEMBER_STRUCT: 
			msg("[idastruct] error: bad struct id (the 1st argument)\n");
			break;
		case STRUC_ERROR_MEMBER_UNIVAR: 
			msg("[idastruct] error: unions can't have variable sized members\n");
			break;
		case STRUC_ERROR_MEMBER_VARLAST: 
			msg("[idastruct] error: variable sized member should be the last member in the structure\n");
			break;
		case STRUC_ERROR_MEMBER_NESTED: 
			msg("[idastruct] error: recursive structure nesting is forbidden\n");
			break;
	}
	
	return ret;
}


void struct_trace(ea_t addr)
{
	strace_t *trace;
	ua_ana0(addr);
	
	for(int opnum = 0; cmd.Operands[opnum].type != o_void; opnum++)
	{
		op_t *op = &cmd.Operands[opnum];
		char *opname = NULL;
		unsigned int val = 0;

		switch(opnum)
		{
		case 0:
			opname = "dst";
			break;
		case 1:
			opname = "src";
			break;
		case 2:
			opname = "aux";
			break;
		}

		switch(op->type)
		{
		case o_displ:
			// if operand if is a register deref'd
			// get absolute value 
			// check if it points to beginning of structures
			val = general[op->reg] + op->addr;
			break;
		case o_phrase:
			val = general[op->phrase];
			break;
		}

		for(trace = strace; trace; trace = trace->next)
		{
			if(val >= trace->base && val <= trace->base + trace->size)
			{
				char name[256];
//				char cmt[512];
				struc_t *sptr = trace->sptr;
				member_t *mptr = get_member(sptr, val - trace->base);
				
				if(!mptr)
				{				
					char *mtype; 
					switch(get_dtyp_size(op->dtyp))
					{
					case 1:
						mtype = "_byte";
						break;
					case 2:
						mtype = "_word";
						break;
					case 4:
						mtype = "_dword";
						break;
					case 8: 
						mtype = "_qword";
						break;
					default:
						mtype = "_offset";
						break;
					}

					qsnprintf(name, 256, "%s_%d", mtype, val - trace->base);
					//msg("%s\n", name);
					//qsnprintf(name, 256, "offset_%d", val - trace->base);
					if(struct_member_add(sptr, name, val - trace->base, 0, NULL, get_dtyp_size(op->dtyp)) < 0)
					{
						trace = trace->next;
						continue;
					}
					mptr = get_member(sptr, val - trace->base);

				}
				//get_member_fullname(mptr->id, name, sizeof(name) -1);
				//append_cmt(addr, name, true);

				tid_t path[2];
				path[0] = sptr->id;
				path[1] = mptr->id;
				op_stroff(addr, opnum, path, 2, 0);
			}
		}

	}


	return;
}



int allocator_call_hist(ea_t addr)
{
	int ret = -1;	// 0: no  1: yes  -1: unknown
	struct _alloc_hist *hist = alloc_hist; 

	while(hist)
	{
		if(hist->addr == addr)
		{
			ret = hist->cstruct;
			break;
		}
		hist = hist->next;
	}

	return -1;
}


int analyze_struct_size (ea_t addr)
{
	int size = -1;

	#if 0
	// this code is now obsolete because functions 
	// are hooked in emufuncs.cpp. 

	char fname[128];
	struct _alloc_function *func = &alloc_functions[0];	

	// check if this ea is a call
	// if call, check if call is an allocator function we know of 

	ua_outop(addr, fname, sizeof(fname) - 1, 0);
	tag_remove(fname, fname, 0);

	while(func)
	{
		if(!strncmp(func->name, fname, strlen(func->name)))
			return readMem(esp + func->offset, SIZE_DWORD);

		func++;
	}
	#endif

	return size;
}

struc_t * struct_create(int size)
{
	struc_t *sptr;

	sptr = get_struc(add_struc(BADADDR, NULL, false));
	if(!sptr)
	{
		msg("[idastruct] error: could not create structure\n");
		return NULL;
	}

	return sptr;
}

int get_disasm(ea_t addr, char *buf, int bufsz)
{
	char mnem[32];
	char *ptr = buf;

	ua_ana0(addr);
	ua_mnem(addr, mnem, sizeof(mnem) - 1);

	qsnprintf(buf, bufsz - 1, "%08x: %-5s ", addr, mnem);
	ptr += strlen(buf);

	for(int opnum = 0; cmd.Operands[opnum].type != o_void; opnum++)
	{
		char op_str[128];

		if(opnum != 0)
			qsnprintf(op_str, sizeof(op_str), ", ");

		ua_outop(addr, op_str, sizeof(op_str) - 3, opnum);
		tag_remove(op_str, op_str, 0);
		
		qsnprintf(ptr, bufsz - 1 - (ptr - buf), "%s", op_str);
		ptr += strlen(op_str);
	}
	return 0;
}


int struct_init(ea_t addr, ea_t base, size_t size)
{
	char buf[1024];
	strace_t *st = strace;

	// skip if this alloc has already been identified
	while(st)
	{
		if(st->addr == addr)
			return 0;
		st = st->next;
	}

	if(!size && options.detect_size)
	{
		if((size = analyze_struct_size(addr)) < 0)
			if(options.verbose)
				msg("[idastruct] could not auto-detect structure size\n");
	}
	
	// failsafe -- if size wasn't detected, just ask for it
	if(!size)
	{
		if(!asklong((sval_t *)&size, "Structure size"))
		{
			if(options.verbose)
				msg("[idastruct] structure size unknown .. skipping\n");
			return -1;
		}
	}
	

	// check call history for action to take on this call
	if(allocator_call_hist(addr) != -1)
		return -1;

	// this call has not been traced or permanently skipped
	get_disasm(addr, buf, 1024);
	int ref = askbuttons_c(NULL, NULL, "Skip once", 0, 
		"Create structure reference at this call:\n\n%s        (%d bytes @ 0x%08x)",
		buf, size, base);

	// skip once 
	if(ref == -1)
		return -1;

	// save action for this call
	struct _alloc_hist *cur = (struct _alloc_hist *)qcalloc(1, sizeof(struct _alloc_hist));
	if(!cur)
	{
		msg("[idastruct] error: could not store allocator state\n");
		return -1;
	}
	cur->addr = addr;
	cur->cstruct = ref;

	// insert into history
	cur->next = alloc_hist;
	alloc_hist = cur;  

	// user decided to not trace structure
	if(ref == 0)
		return -1; 

	// create structure trace
	st = (strace_t *)qcalloc(1, sizeof(strace_t));
	if(!st)
	{
		msg("[idastruct] error: could not allocate memory\n");
		return -1;
	}

	st->addr = addr;
	st->size = size;
	st->base = base;
	st->sptr = struct_create(st->size);
	if(!st->sptr)
		return -1;

	if(options.verbose)
	{
		msg("[idastruct] structure initialized\n");
		msg("            code origin:    0x%08x\n", addr);
		msg("            structure base: 0x%08x\n", st->base);
		msg("            structure size: %d bytes\n", st->size);
	}

	// push struct trace
	st->next = strace; 
	strace = st; 	

	return 0;
}


void idastruct_init(void)
{
	options.verbose       = true;
	options.detect_struct = true;
	options.detect_size   = false;

	return;
}
