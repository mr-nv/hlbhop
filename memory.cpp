#include "memory.h"

bool CompareData( const char* base, const char* pattern )
{
	for( ; *pattern; base++, pattern++ )
	{
		if( *pattern != '?' && *base != *pattern )
			return 0;
	}

	return *pattern == 0;
}

namespace memory
{
	DWORD Find( HMODULE module, const char* pattern )
	{
		const auto dos = ( PIMAGE_DOS_HEADER )module;
		const auto nt = ( PIMAGE_NT_HEADERS )( ( DWORD )module + dos->e_lfanew );
		const auto optional = nt->OptionalHeader;

		auto start = ( DWORD )module + optional.BaseOfCode;

		for( DWORD i = 0; i < optional.SizeOfCode; i++, start++ )
		{
			if( CompareData( ( const char* )start, pattern ) )
				return start;
		}

		return 0;
	}

	void Patch( void* address, unsigned char* bytes, unsigned int length )
	{
		DWORD prot;
		VirtualProtect( address, length, PAGE_EXECUTE_READWRITE, &prot );
		memcpy( address, bytes, length );
		VirtualProtect( address, length, prot, &prot );
	}
}