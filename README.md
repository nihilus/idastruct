idastruct - ida structure recognition plugin 
Copyright (C) 2005 Richard Johnson <rjohnson@idefense.com>
-------------------------------------------------------------------------------

idastruct is an ida plugin which aims to assist reverse engineers in
identifying high-level objects and structures in binary code. 

idastruct utilizes the excellent x86 emulator plugin 'ida-x86emu' by Chris
Eagle and Jermey Cooper as a basis for evaluating operand values and
determining references within tracked boundaries. 

This results in automated creation of IDA structures, enumeration or member
references, and renaming of disassembly offsets to symbolic names corresponding
to the newly created structures and members in the IDA database. 

Currently idastruct lacks a full editing / analysis engine, however it is
capable of simplifying the mundane task of tracking references within given
boundaries of structure allocations. 


Compiling
---------

This distribution includes Visual Studio 2005 project files. This project has
been built using IDA Pro SDK 4.9. Some known issues with the default header
files included with IDA 4.9 SDK can cause errors depending on Visual Studio
version/settings. The author has supplied an updated version of idp.hpp and
pro.h to Datarescue, however if it has not been made available on the forums,
it is available upon request (note, I have included it in the idasdk folder.)  

The ida-x86emu tree is current CVS (2005-12-25) checkout. The supplied script
should allow for updates from the ida-x86emu CVS server while maintaining the
patches to the ida-x86emu source tree. 


Installing
----------

Copy Debug/x86emu.plw to your IDA plugins directory


Testing
-------

1) Open test/test_struct.exe in IDA Pro
2) Place cursor on entry point
3) Type alt-f8 or select the x86emu plugin option from the plugins menu 
   (this will bring up the x86emu dialog, initalized to entry point)
4) Select the last line in the function (the ret instruction)
5) Click "Run to Cursor" option in x86emu

idastruct will prompt the user on each heap allocation call to determine how to
treat the allocated memory. Once a trace has been initialized, idastruct will
track memory access within the boundaries of the allocated memory regions. 


Credits
-------

ida-x86emu is authored by:
   Chris Eagle, cseagle at redshift d0t c0m
   Jermey Cooper, jeremy at baymoo, org 
See the ida-x86emu files for further details. 

idastruct is authored by:
   Richard Johnson (rjohnson@idefense.com / rjohnson@nologin.org)


Licensing
---------

This software is released under GPLv2.  See the LICENSE file for additional
license details. 
