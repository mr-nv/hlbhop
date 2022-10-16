#pragma once
#include <Windows.h>

#include "memory.h"

#undef ERROR
#define ERROR( err ) MessageBoxA( 0, err, "hlbhop", MB_OK )