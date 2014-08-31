/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-97 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@estar.msk.su
 *                              FIDO:   2:5020/209
 *
 */

#ifndef _PRO_H
#define _PRO_H

/*
  This is the first header included in IDA project.
  It defines the most common types, functions and data.
  Also, it tries to make system dependent definitions.

  The following preprocessor macros are used in the project
  (the list may be incomplete)

  Platform must be specified as one of:

   __OS2__     OS/2
   __MSDOS__   MS DOS 32-bit extender
   __NT__      MS Windows (all platforms)
   __LINUX__   Linux

   __AMD64__   Compiling for Windows64
   UNDER_CE    Compiling for WindowsCE

   __EA64__    64-bit address size (sizeof(ea_t)==8)
   __X64__     64-bit IDA itself (sizeof(void*)==8)

*/

// __AMD64__ implies __X64__, __NT__
#ifdef __AMD64__
#undef __X64__
#define __X64__
#undef __NT__
#define __NT__
#endif

// Only 64-bit IDA is available on 64-bit plaforms
#ifdef __X64__
#undef __EA64__
#define __EA64__
#endif

#include <stdlib.h>     /* size_t, NULL, memory */
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <ctype.h>
#if defined(__BORLANDC__)
#  include <io.h>       /* open, ... */
#  include <dir.h>      /* mkdir */
#  ifdef __NT__
#    include <alloc.h>
#  endif
#  include <new.h>
#define WIN32_LEAN_AND_MEAN
#else
#if defined(__WATCOMC__) || defined(_MSC_VER)
#ifndef UNDER_CE
#  include <io.h>
#  include <direct.h>
#endif
#  include <limits.h>
#else
#  include <unistd.h>
#  include <sys/stat.h>
#endif
#endif
#ifdef UNDER_CE         // Windows CE does not have many files...
#define getenv(x) NULL  // no getenv under Windows CE
int rename(const char *ofile, const char *nfile);
int unlink(const char *file);
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#if defined(__WATCOMC__) || !defined(__cplusplus)
#include <string.h>
#else
#define STL_SUPPORT_PRESENT
#include <string>
using std::string;
#endif

#pragma pack(push, 1)
/*==================================================*/
#ifdef __cplusplus
#define EXTERNC         extern "C"
#define C_INCLUDE       EXTERNC {
#define C_INCLUDE_END   }
#define INLINE          inline
#else
#define EXTERNC
#define C_INCLUDE
#define C_INCLUDE_END
#define INLINE
#endif

/*==================================================*/
#if !defined(__OS2__) && !defined(__MSDOS__) && !defined(__NT__) && !defined(__LINUX__)
#error "Please define one of: __NT__, __OS2__, __MSDOS__, __LINUX__"
#endif

#if defined(__LINUX__) && defined(__BORLANDC__)
#define __KYLIX__
#endif

/*==================================================*/
#ifndef MAXSTR
#define MAXSTR 1024
#endif

// Some NT functions require __cdecl calling convention
#ifdef __NT__
#define NT_CDECL __cdecl
#else
#define NT_CDECL
#endif

/*==================================================*/

#define __MF__  0               // Byte sex of our platform
                                // (Most significant byte First)
                                // 0 - little endian (Intel 80x86)
                                // 1 - big endian (PowerPC)

/*==================================================*/
/* Macro to avoid of message 'Parameter ... is never used' */
#if defined(__BORLANDC__) && !defined(__NT__) || defined(__WATCOMC__)
#define qnotused(x)     (x=x)
#elif defined(__BORLANDC__) || defined(_MSC_VER)
#define qnotused(x)     &x
#else
#define qnotused(x)
#endif

// GNU C complains about some data types in va_arg because they are promoted to int
// and proposes to replace them by int.
#ifdef __GNUC__
#define va_argi(va, type)  ((type)va_arg(va, int))
#else
#define va_argi(va, type)  va_arg(va, type)
#endif

/*==================================================*/
#ifdef __WATCOMC__
#define CONST_CAST(x)   (x)
#else
#define CONST_CAST(x)   const_cast<x>
#endif

/*==================================================*/

#if defined(__IDP__) && defined(__NT__) // for modules
#define idaapi          __stdcall
#define idaman          EXTERNC
#define ida_export      idaapi
#define ida_export_data __declspec(dllimport)
#elif defined(__NT__)                   // for the kernel
#define idaapi          __stdcall
#define idaman          EXTERNC __declspec(dllexport)
#define ida_export      idaapi
#define ida_export_data
#elif defined(__LINUX__)                // for linux
#define idaapi
#define idaman          EXTERNC
#define ida_export      idaapi
#define ida_export_data
#else                                   // for watcom
#define idaapi
#define idaman          extern
#define ida_export
#define ida_export_data
#endif

/*==================================================*/
#if (defined(__WATCOMC__) && (__WATCOMC__ < 1100)) \
  || defined(__DOS16__)                            \
  || !defined(__cplusplus)

typedef int bool;
#define false 0
#define true 1

#endif

/*==================================================*/
/* uchar, ... */
/*--------------------------------------------------*/
// Linux C mode compiler already has these types defined
#if !defined(__LINUX__) || defined(__cplusplus)
typedef unsigned char  uchar;
typedef unsigned short ushort;
#if defined(__KYLIX__) // Borland Kylix has uint
using Qt::uint;
#else
typedef unsigned int   uint;
#endif
typedef unsigned long  ulong;
#endif

#include <llong.hpp>

typedef          char   int8;
typedef signed   char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef unsigned short  uint16;
typedef          long   int32;
typedef unsigned long   uint32;
typedef longlong        int64;
typedef ulonglong       uint64;

// signed size_t - used to check for size overflows when
// the counter becomes negative
// it is better to use this type instead of size_t because of this
#ifndef __GNUC__        // GNU C defines ssize_t for us
#ifdef __X64__
typedef int64 ssize_t;
#else
typedef int32 ssize_t;
#endif
#endif

#ifdef __cplusplus
inline bool can_place32(uint64 a) { return a == (uint64)(uint32)low(a); }
inline bool can_place32(int64 a)  { return a == ( int64)( int32)low(a); }
#endif

#if defined(__GNUC__)
#define FMT_64 "ll"
#elif defined(_MSC_VER)
#define FMT_64 "I64"
#elif defined (__BORLANDC__)
#define FMT_64 "L"
#else
#error "unknown compiler"
#endif

#ifdef __EA64__
typedef ulonglong ea_t;   // effective address
typedef ulonglong sel_t;  // segment selector
typedef ulonglong asize_t;// memory chunk size
typedef longlong adiff_t; // address difference
#define FMT_EA FMT_64
#else
typedef ulong ea_t;       // effective address
typedef ulong sel_t;      // segment selector
typedef ulong asize_t;    // memory chunk size
typedef long  adiff_t;    // address difference
#define FMT_EA "l"
#endif

typedef asize_t uval_t;   // unsigned value used by the processor
                          // for 32-bit ea_t, ulong
                          // for 64-bit ea_t, ulonglong
typedef adiff_t sval_t;   // nsigned value used by the processor
                          // for 32-bit ea_t, ulong
                          // for 64-bit ea_t, ulonglong
#define BADADDR ea_t(-1)  // this value is used for 'bad address'

// Windows64 declarations
#ifdef __AMD64__
#define time _time32       // time() function disappeared in Window64
#define ctime _ctime32
#define mktime _mktime32
#define localtime _localtime32
#define time_t __time32_t
#define qstat _stat64
#define qfstat _fstat64
#define qstatbuf struct __stat64
#else
#define qstat stat
#define qfstat fstat
#define qstatbuf struct stat
#endif

// non standard functions are missing:
#ifdef _MSC_VER
int idaapi vsscanf(const char *input, const char *format, va_list va);
#if _MSC_VER <= 1200
#define for if(0) ; else for  // MSVC is not compliant to the ANSI standard :(
#endif
#endif

/*==================================================*/
/* error codes */
/*--------------------------------------------------*/

#define eOk        0    /* No error             */
#define eOS        1    /* OS error, see errno  */
#define eDiskFull  2    /* Disk Full            */
#define eReadError 3    /* Read Error           */

typedef int error_t;

/*--------------------------------------------------*/
/* internal code of last error occured              */
/* see err.h for error handling functions           */

idaman error_t ida_export_data qerrno;


/*==================================================*/
/* type of OS */
/*--------------------------------------------------*/
typedef enum
{
   osMSDOS,
   osAIX_RISC,
   osOS2,
   osNT,
   osLINUX,
} ostype_t;

extern ostype_t ostype;

/*==================================================*/
idaman void *ida_export qalloc( size_t size );
idaman void *ida_export qrealloc( void *alloc, size_t newsize );
idaman void *ida_export qcalloc( size_t nitems, size_t itemsize );
idaman void  ida_export qfree( void *alloc );
idaman char *ida_export qstrdup( const char *string );
#define qnew(t)        ((t*)qalloc(sizeof(t)))
#define qnewarray(t,n) ((t*)qcalloc((n),sizeof(t)))

#define qnumber(a)     (sizeof(a)/sizeof((a)[0]))

// gcc complains about offsetof(), we had make our version
#ifdef __GNUC__
#define qoffsetof(type, name) (((char *)&((type *)1)->name)-(char*)1)
#else
#define qoffsetof offsetof
#endif

// Reverse memory block
// (the first byte is exchanged with the last bytes, etc.)
// analog of strrev() function
//      buf - pointer to buffer to reverse
//      size - size of buffer
// returns: pointer to buffer

idaman void *ida_export memrev(void *buf, ssize_t size);

#ifdef __GNUC__
idaman int ida_export memicmp(const void *x, const void *y, size_t size);
#endif

/*==================================================*/
/* strings */
#if !defined(__BORLANDC__) && !defined(_MSC_VER)
idaman char *ida_export strlwr(char *s);
idaman char *ida_export strupr(char *s);
#endif
#ifdef __LINUX__
#define strnicmp strncasecmp
#define stricmp  strcasecmp
#elif defined(_MSC_VER)
#define strnicmp _strnicmp
#define stricmp  _stricmp
#endif
/*--------------------------------------------------*/
char *strcompact(char *string);
char *strcenter(char *s, size_t len);

// Replace all entries of 'char1' by 'char2' in string 'str'

idaman char *ida_export strrpl(char *str, int char1, int char2);

// Get tail of a string

inline       char *tail(      char *str) { return strchr(str, '\0'); }
inline const char *tail(const char *str) { return strchr(str, '\0'); }


// qstrncpy makes sure that there is a terminating zero
// nb: this function doesn't fill the whole buffer zeroes as strncpy does

idaman char *ida_export qstrncpy(char *dst, const char *src, size_t dstsize);


// qstpncpy returns pointer to the end of the destination

idaman char *ida_export qstpncpy(char *dst, const char *src, size_t dstsize);


// nb: qstrncat() accepts the size of the 'dst' as 'dstsize' and returns dst

idaman char *ida_export qstrncat(char *dst, const char *src, size_t dstsize);


// We forbid using dangerous functions in IDA Pro
#ifndef USE_DANGEROUS_FUNCTIONS
#if defined(__BORLANDC__) && __BORLANDC__ < 0x560  // for BCB5 (YH)
#include <stdio.h>
#endif
#undef strcpy
#define strcpy          dont_use_strcpy            // use qstrncpy
#define stpcpy          dont_use_stpcpy            // use qstpncpy
#define strncpy         dont_use_strncpy           // use qstrncpy
#define strcat          dont_use_strcat            // use qstrncat
#define strncat         dont_use_strncat           // use qstrncat
#define gets            dont_use_gets              // use fgets
#define sprintf         dont_use_sprintf           // use qsnprintf
#define snprintf        dont_use_snprintf          // use qsnprintf
#define wsprintfA       dont_use_wsprintf          // use qsnprintf
#endif

/*--------------------------------------------------*/
// Our definitions of qsnprintf/qsscanf support one additional format specifier
//
//      %a              which corresponds to ea_t
//
// Usual optional fields like the width can be used too: %04a
// The width specifier will be doubled for 64-bit version
// These function return the number of characters _actually written_ to the output string
// excluding the terminating zero. (which is different from the snprintf)
// They always terminate the output with a zero byte (if n > 0)
idaman int ida_export qvsnprintf(char *buffer, size_t n, const char *format, va_list va);
idaman int ida_export qvsscanf(const char *input, const char *format, va_list va);
idaman int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...);
idaman int ida_export append_snprintf(char *buf, char *end, const char *format, ...);
idaman int ida_export qsscanf(const char *input, const char *format, ...);

/*==================================================*/
/* file name declarations */
/* maximum number of characters in path and file specification */
#if defined(__GNUC__) || defined(__KYLIX__)
#define QMAXPATH        PATH_MAX
#define QMAXFILE        PATH_MAX
#else
#define QMAXPATH        _MAX_PATH
#define QMAXFILE        (_MAX_FNAME+_MAX_EXT)
#endif


// construct 'path' from component's list terminated by NULL, return 'path'.
// It is forbidden to pass NULL as the output buffer
// buf may be == s1
// Returns pointer to buf

idaman char *ida_export vqmakepath(char *buf, size_t bufsize, const char *s1, va_list);
idaman char *ida_export qmakepath(char *buf, size_t bufsize, const char *s1, ...);

// split 'path' into 'dir' and 'file' parts, you may specify NULL
// as 'dir'/'file' parameters. 'path' may be changed.
// return the file part

idaman char *ida_export qsplitpath(char *path, char **dir, char **file);


// construct filename from base name and extension, return 'file'.
// buf may be == base
// It is forbidden to pass NULL as the output buffer

idaman char *ida_export qmakefile(char *buf,
                                  size_t bufsize,
                                  const char *base,
                                  const char *ext);


// split filename to base name and extension, you may specify NULL
// as 'base'/'ext' parameters. 'file' may be changed.
//  return the base part

idaman char *ida_export qsplitfile(char *file, char **base, char **ext);


// Is the file name absolute (not relative to the current dir?)

idaman bool ida_export qisabspath(const char *file);


// Get the file name part of the path
// path==NULL -> returns NULL

idaman const char *ida_export qbasename(const char *path);
#ifdef __cplusplus
inline char *qbasename(char *path) { return (char *)qbasename((const char *)path); }
#endif

// Convert relative path to absolute path

char *qmake_full_path(char *dst, size_t dstsize, const char *src);


// Delimiter of directory lists
#if defined(__UNIX__) || defined(__LINUX__)
#define DELIMITER       ":"     // Unix
#else
#define DELIMITER       ";"     // MS DOS, Windows, other systems
#endif

// Set file name extension unconditionally
//      outbuf  - buffer to hold the answer. may be the same
//                as the file name.
//      bufsize - output buffer size
//      file    - the file name
//      ext     - new extension (with or without '.')
// returns: pointer to the new file name

idaman char *ida_export set_file_ext(char *outbuf,
                                     size_t bufsize,
                                     const char *file,
                                     const char *ext);


// Get pointer to extension of file name
//      file - file name
// returns: pointer to the file extension or NULL if extension doesn't exist

idaman const char *ida_export get_file_ext(const char *file);
#ifdef __cplusplus
inline bool idaapi has_file_ext(const char *file)
  { return get_file_ext(file) != NULL; }
#endif

// Set file name extension if none exist
// This function appends the extension to a file name.
// It won't change file name if extension already exists
//      buf     - output buffer
//      bufsize - size of the output buffer
//      file    - file name
//      ext     - extension (with or without '.')
// returns: pointer to the new file name

#ifdef __cplusplus
inline char *idaapi make_file_ext(char *buf,
                                  size_t bufsize,
                                  const char *file,
                                  const char *ext)
{
  if ( has_file_ext(file) )
    return qstrncpy(buf, file, bufsize);
  else
    return set_file_ext(buf, bufsize, file, ext);
}
#endif

// Sanitize the file name
// Remove the directory path
// Replace wildcards ? * and chars<' ' by _
// If the file name is empty, then
//      namesize != 0: generate a new temporary name
//      namesize == 0: return false
// else return true

idaman bool ida_export sanitize_file_name(char *name, size_t namesize);

/*==================================================*/
/* input/output */
/*--------------------------------------------------*/
#if !defined(__MSDOS__) && !defined(__OS2__) && !defined(__NT__) && !defined(_MSC_VER)
#define O_BINARY        0
#endif

#ifndef SEEK_SET
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2
#endif
/*--------------------------------------------------*/
/* you should use these functions for file i/o                */
/* they do the same as their counterparts from Clib.          */
/* the only difference is that they set 'qerrno' variable too */

idaman int   ida_export qopen(const char *file, int mode);     /* open existing file */
idaman int   ida_export qcreate(const char *file, int stat);   /* create new file with O_RDWR */
idaman int   ida_export qread(int h, void *buf, size_t n);
idaman int   ida_export qwrite(int h, const void *buf, size_t n);
idaman long  ida_export qtell(int h);
idaman long  ida_export qseek(int h, long offset, int whence);
idaman int   ida_export qclose(int h);
idaman ulong ida_export qfilesize(const char *fname);  // 0 if file does not exist
idaman ulong ida_export qfilelength(int h);            // -1 if error
idaman int   ida_export qchsize(int h, unsigned long fsize);
idaman int   ida_export qmkdir(const char *file, int mode);
idaman bool  ida_export qfileexist(const char *file);
idaman bool  ida_export qisdir(const char *file);

/*==================================================*/
idaman void ida_export qexit(int code);
idaman void ida_export qatexit(void (idaapi *func)(void));

/*==================================================*/
/* universal min, max */
/*--------------------------------------------------*/
#define qmin(a,b) ((a) < (b)? (a): (b))
#define qmax(a,b) ((a) > (b)? (a): (b))

//----------------------------------------------------------------------
// rotate left
#ifdef __cplusplus
template<class T> T qrotl(T value, T count)
{
  const size_t nbits = sizeof(T) * 8;
  count %= nbits;

  T high = value >> (nbits - count);
  value <<= count;
  value |= high;
  return value;
}

// rotate right
template<class T> T qrotr(T value, T count)
{
  const size_t nbits = sizeof(T) * 8;
  count %= nbits;

  T low = value << (nbits - count);
  value >>= count;
  value |= low;
  return value;
}
#endif

// BCB6 treats multicharacter constant differently from old versions
// We are forced to abandon them (it is good because they are not portable anyway)

#define MC2(c1, c2)          ushort(((c2)<<8)|c1)
#define MC3(c1, c2, c3)      ulong(((((c3)<<8)|(c2))<<8)|c1)
#define MC4(c1, c2, c3, c4)  ulong(((((((c4)<<8)|(c3))<<8)|(c2))<<8)|c1)

/*==================================================*/
/* Add-ins for 2/4 byte read/writes.
        h - file handle
        res - value read from file
        size - size of value in bytes (1,2,4)
        mostfirst - is MSB first? (0/1)

   All these functions return 0 - Ok */

idaman int ida_export readbytes(int h,ulong *res,int size,int mostfirst);
idaman int ida_export writebytes(int h,ulong l,int size,int mostfirst);

idaman int ida_export read2bytes(int h,ushort *res,int mostfirst);
#define read4bytes(h,res,mostfirst)     readbytes(h,res,4,mostfirst)
#define write2bytes(h,l,mostfirst)      writebytes(h,l,2,mostfirst)
#define write4bytes(h,l,mostfirst)      writebytes(h,l,4,mostfirst)

/*==================================================*/
#ifdef __cplusplus
inline ulong swap32(ulong x)
  { return (x>>24) | (x<<24) | ((x>>8) & 0x0000FF00L) | ((x<<8) & 0x00FF0000L); }
inline ushort swap16(ushort x)
  { return ushort((x<<8) | (x>>8)); }
#else
#define swap32(x) ulong((x>>24) | (x<<24) | ((x>>8) & 0x0000FF00L) | ((x<<8) & 0x00FF0000L))
#define swap16(x) ushort((x<<8) | (x>>8))
#endif

#ifdef __EA64__
#define swapea  swap64
#else
#define swapea  swap32
#endif

#if __MF__
#define qhtonl(x) (x)
#define qntohl(x) (x)
#define qhtons(x) (x)
#define qntohs(x) (x)
#else
#define qhtons(x) swap16(x)
#define qntohs(x) swap16(x)
#define qhtonl(x) swap32(x)
#define qntohl(x) swap32(x)
#endif

// Rotate a value
// this function can be used to rotate a value to the right
// if the count is negative
//  x - value to rotate
//  count - shift amount
//  bits - number of bits to rotate (32 will rotate a dword)
//  offset - number of first bit to rotate
//           (bits=8 offset=16 will rotate the third byte of the value)
// returns the rotated value

idaman uval_t ida_export rotate_left(uval_t x, int count, size_t bits, size_t offset);


#ifdef __cplusplus
// swap 2 objects of the same type using memory copies
template <class T> inline void qswap(T &a, T &b)
{
  char temp[sizeof(T)];
  memcpy(&temp, &a, sizeof(T));
  memcpy(&a, &b, sizeof(T));
  memcpy(&b, &temp, sizeof(T));
}
#endif

// append a character to the buffer checking the buffer size
#define APPCHAR(buf, end, chr)                    \
  do                                              \
  {                                               \
    char __chr = chr;                             \
    if ( buf < end )                              \
      *buf++ = __chr;                             \
  } while (0)

// append a zero byte to the buffer checking the buffer size
#define APPZERO(buf, end)                         \
  do                                              \
  {                                               \
    if ( buf >= end )                             \
      end[-1] = '\0';                             \
    else                                          \
      *buf = '\0';                                \
  } while (0)

// append a string to the buffer checking the buffer size
#define APPEND(buf, end, name)                    \
  do                                              \
  {                                               \
    const char *__ida_in = name;                  \
    while ( true )                                \
    {                                             \
      if ( buf >= end )                           \
      {                                           \
        buf = end-1;                              \
        buf[0] = '\0';                            \
        break;                                    \
      }                                           \
      if (( *buf = *__ida_in++) == '\0' )         \
        break;                                    \
      buf++;                                      \
    }                                             \
  } while ( 0 )

// append a string to the buffer checking the buffer size, max 'size' characters
// nb: the trailing zero might be absent in the output buffer!
#define NAPPEND(buf, end, block, size)            \
  do                                              \
  {                                               \
    const char *__ida_in = block;                 \
    int __msize = size;                           \
    while ( --__msize >= 0 )                      \
    {                                             \
      if ( buf >= end )                           \
      {                                           \
        buf = end-1;                              \
        buf[0] = '\0';                            \
        break;                                    \
      }                                           \
      if ( (*buf = *__ida_in++) == 0 )            \
        break;                                    \
      buf++;                                      \
    }                                             \
  } while (0)

/*==================================================*/
// The following templates are reimplementation of the vector and string
// classes from STL. Only the most essential functions are implemented.
// The reason why we have them is that they are not compiler dependent
// (hopefully) and therefore can be used in IDA API

#if defined(__cplusplus)

template <class T> class qvector
{
  T *array;
  size_t n, alloc;
  qvector<T> &assign(const qvector<T> &x)
  {
    if ( x.n > 0 )
    {
      array = (T*)qalloc(x.alloc * sizeof(T));
      if ( array != NULL )
      {
        alloc = x.alloc;
        for ( size_t i=0; i < x.n; i++ )
          array[i] = x.array[i];
        n = x.n;
      }
    }
    return *this;
  }
public:
  qvector(void) : array(NULL), n(0), alloc(0) {}
  qvector(const qvector<T> &x) : array(NULL), n(0), alloc(0) { assign(x); }
  ~qvector(void) { clear(); }
  void push_back(const T &x)
  {
    if ( n >= alloc )
    {
      int m = qmax(8, alloc * 2);
      T *a = (T*)qrealloc(array, m * sizeof(T));
      if ( a == NULL ) throw std::bad_alloc();
      array = a;
      alloc = m;
    }
    new (array+n) T(x); // create a new element in the qvector
    n++;
  }
  void pop_back(void)
  {
    if ( n > 0 )
      array[--n].~T();
  }
  size_t size(void) const { return n; }
  bool empty(void) const { return n == 0; }
  const T &operator[](size_t idx) const { return array[idx]; }
        T &operator[](size_t idx)       { return array[idx]; }
  void clear(void)
  {
    if ( n > 0 )
    {
      for ( size_t i=0; i < n; i++ )
        array[i].~T();
      qfree(array);
      array = NULL;
      alloc = 0;
      n = 0;
    }
  }
  qvector<T> &operator=(const qvector<T> &x)
  {
    clear();
    return assign(x);
  }
  void resize(size_t s, const T &x)
  {
    if ( s < n )
    {
      while ( n > s )
        array[--n].~T();
    }
    else if ( s >= alloc )
    {
      T *a = (T*)qrealloc(array, s * sizeof(T));
      if ( a == NULL ) throw std::bad_alloc();
      array = a;
      alloc = s;
    }
    while ( n < s )
    {
      new(array+n) T(x);
      n++;
    }
  }
  // method to extract data from the vector and to empty it
  // the caller must free the result of this function
  T *extract(void)
  {
    T *res = array;
    if ( alloc > n )
      res = (T*)qrealloc(array, n * sizeof(T));
    array = NULL;
    alloc = 0;
    n = 0;
    return res;
  }
};

class qstring    // implement simple qstring class
{
  qvector<char> body;
public:
  qstring(void) {}
  qstring(const char *ptr)
  {
    size_t len = strlen(ptr) + 1;
    body.resize(len, '\0');
    memcpy(&body[0], ptr, len);
  }
  qstring(const char *ptr, size_t len)
  {
    body.resize(len, '\0');
    memcpy(&body[0], ptr, len);
  }
  size_t length(void) const { size_t l = body.size(); return l ? l - 1 : 0; }
  const char *c_str(void) const { return body.size() ? &body[0] : ""; }
  qstring &operator+=(char c)
  {
    size_t len = length();
    body.resize(len+2, '\0');
    body[len]   = c;
    body[len+1] = '\0';
    return *this;
  }
  qstring &operator+=(const qstring &r)
  {
    size_t len = length();
    size_t rlen = r.length();
    body.resize(len+rlen+1, '\0');
    memcpy(&body[len], &r.body[0], rlen);
    body[len+rlen] = '\0';
    return *this;
  }
  bool operator==(const qstring &r)
  {
    return strcmp(&body[0], &r.body[0]) == 0;
  }
  // extract C string from qstring. Must free it.
  char *extract(void) { return body.extract(); }
};
#endif

// macros for easy debugging
#define ZZZ msg("%s:%d\n", __FILE__, __LINE__)
#define BPT __emit__(0xcc)

#ifdef UNICODE
// Convert an ascii string to a unicode string. Return the result
// bufsize must be number of characters the output buffer can hold
const wchar_t *cwstr(wchar_t *buf, const char *src, size_t bufsize);
// Convert a unicode string to an ascii string. Return the result
const char *wcstr(char *buf, const wchar_t *src, size_t bufsize);
#else
#define cwstr(dst, src, dstsize) qstrncpy(dst, src, dstsize)
#define wcstr(dst, src, dstsize) qstrncpy(dst, src, dstsize)
#endif

// Old Visual C++ compilers were not defining the following:
#ifdef __NT__
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif
#ifndef BELOW_NORMAL_PRIORITY_CLASS
#define BELOW_NORMAL_PRIORITY_CLASS       0x00004000
#endif
#endif

#pragma pack(pop)
#endif /* _PRO_H */
