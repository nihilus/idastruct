#ifndef __IDASTRUCT_H
#define __IDASTRUCT_H

#include <struct.hpp>

struct _options {
	bool verbose;
	bool detect_struct;
	bool detect_size;
};
extern struct _options options;

// stores info about traced structures 
typedef struct _strace { 
	struct _strace *next;
	ea_t     addr;			// originating call for this struct
	struc_t *sptr;			// ida struct ptr
	ea_t     base;			// identified base_addr ptr (return from call)
	size_t   size;			// struct size
	struct _itrace *itrace; // instruction trace
} strace_t;
extern strace_t *strace;

// stores info about instruction xrefs
typedef struct _itrace {
	struct _itrace *next;
	ea_t addr;				// address of reference
	unsigned short off;		// struct offset
	unsigned char  reftype; // RWX
	unsigned char  len;		// type len
} itrace_t; 

// stores whether to create structures at an allocator function
struct _alloc_hist {
	struct _alloc_hist *next;
	ea_t addr;				// addr of call
	char cstruct;			// create struct? 0: no  1: yes  
};

// stores argument info about allocator functions
struct _alloc_function {
	char *name;
	int  size;	// arg holding size
	int  num;   // arg holding number of elements 
};


extern int struct_init(ea_t addr, ea_t base, size_t size);
extern void struct_trace(ea_t addr);
extern void idastruct_init();

/* 
unsigned long registers[8];
unsigned long eip;
unsigned long eflags;

typedef struct _itrace {
	struct _itrace *next, *prev;
	ea_t addr;				// address of reference
	ea_t xref;				// address referenced
	unsigned char  reftype; // RWX
} itrace_t; 


add_xref(ea, dst);
while(ea = ea.next)
{	
	while(op = operand.next)
	{
		mask = SIZE_MASKS[opsize];
		switch(op->type)
		{
		case o_imm:
			val = op->addr & mask;
			break;
		case o_displ:
			val = (general[op->reg] + op->addr) & mask;
			break;
		case o_phrase:
			val = general[op->phrase] & mask;
			break;
		}
	}

	if(search_itrace_list(val))
	{
		remove_xref(ea, dst);
	}
	else if search_itrace_list(src)
	{
		add_xref(ea, dst);
	}
}
*/
#endif
