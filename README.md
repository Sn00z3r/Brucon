# Brucon workshop

This repository contains all files from the workshop, including some additional stuff such as anti-hooking.

The main project is build using Multi-threaded (/MT) flag, this makes sure you don't need the VCredist dll's to run the application. Also, when including third-party dll's suich as boost, make sure to statically link them using #pragma comment(lib,"").

Second project is an example of anti-hooking, if you want the solution for that you can find it in unhook.h, the code you need to write needs to be in unhook.cpp.
