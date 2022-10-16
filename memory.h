#pragma once
#include "main.h"

namespace memory
{
	DWORD Find( HMODULE module, const char* pattern );
	void Patch( void* address, unsigned char* bytes, unsigned int length );
}