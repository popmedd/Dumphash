#pragma once

#ifndef INCLUDES_H
#define INCLUDES_H
#include <iostream>
#include <vector>
#include <random>
#include <windows.h>
#include <winevt.h>
#include <sddl.h>
#include <TlHelp32.h>
#include <processsnapshot.h>
#include <dbghelp.h>
#include <evntprov.h>
#include "enums.h"
#include "structs.h"
#include "syscalls.h"
#pragma comment(lib, "wevtapi.lib")
std::vector<SYSCALL_ENTRY> syscallTable;
#define LOG(text) std::cout << text << std::endl;
SYSTEM_HANDLE_INFORMATION* hInfo; //holds the handle information

#endif