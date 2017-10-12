# Brucon workshop

## FOR RESEARCH PURPOSES ONLY
I will not be held responsible if it goes tits up for you!


## Description
This repository contains all files from the workshop, including some additional stuff such as anti-hooking.

All projects are build using Multi-threaded (/MT) flag, this makes sure you don't need the VCredist dll's. Also, when including third-party dll's such as boost, make sure to statically link them using #pragma comment(lib,"").

Second project is an example of anti-hooking, if you want the solution for that you can find it in unhook.h, the code you need to write needs to be in unhook.cpp.

This is the basic form of the injector which only works out-of-the box for Windows 10 version in the VM provided at Brucon, for other builds and windows 10 versions you will need to change the memory snippet for LdrpHandleTlsData and RtlInsertInvertedFunctionTable.
Also I did not perform any anti-malware evasion and anti-forensics, so you will need to figure that out yourself ;).

For windows 7,8 and 8.1 (and their server variants, which are the same) you will need to do some reverse engineering as you will need to change / patch a couple of things. I can tell you it's possible as I've done it in my demo version :).

Sky is the limit here, once you grasp the concepts on how windows works, there is not much you won't be able to do.
Improvise, Adapt, Overcome!

