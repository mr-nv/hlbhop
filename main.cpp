#include "main.h"

bool PatchSpeedCap( HMODULE clientdll, HMODULE hldll )
{
	const char* patterns[ ] =
	{
		// first 2 are mine, others are stolen from bunnymodxt
		// idk and idc if they work
		"\x55\x8B\xEC\x83\xEC\x4C\x53\x56\x57\xA1????\xF3\x0F\x10\x05",
		"\x55\x8B\xEC\x83\xEC\x4C\x53\x56\x57\xA1????\xD9\x05",
		"\x51\x8B\x0D????\xD9\x81????\xD8\x0D????\xD9\x54",
		"\x55\x8B\xEC\x83\xEC\x0C\xA1????\xD9\x05????\xD8\x88\xF4",
		"\x55\x8B\xEC\x51\x8B\x0D????\xD9\x81\xF4\x01\x00\x00\xD8\x0D",
		"\x55\x8B\xEC\x51\x51\xA1????\x0F\x57\xC0\xF3\x0F\x10\x88",
		"\x55\x8B\xEC\x51\x8B\x0D????\xD9\x81\xF4\x01\x00\x00\xD8\x0D",
		"\x55\x8B\xEC\x83\xEC\x0C\x56\x8B\x35????\xD9\x86????\xDC\x0D",
		"\x55\x8B\xEC\x83\xEC\x4C\x53\x56\x57\xA1????\xD9\x80????\xDC\x0D",
		"\x55\x8B\xEC\x83\xEC\x08\xA1????\x0F\x57\xC0\xF3\x0F\x10\x88\xF4"
	};

	DWORD PM_PreventMegaBunnyJumpingClient = 0;
	DWORD PM_PreventMegaBunnyJumpingHL = 0;

	for( int i = 0; i < sizeof( patterns ) / sizeof( patterns[ 0 ] ); i++ )
	{
		PM_PreventMegaBunnyJumpingClient = memory::Find( clientdll, patterns[ i ] );
		PM_PreventMegaBunnyJumpingHL = memory::Find( hldll, patterns[ i ] );

		if( PM_PreventMegaBunnyJumpingClient && PM_PreventMegaBunnyJumpingHL )
			break;
	}

	if( !PM_PreventMegaBunnyJumpingClient )
	{
		ERROR( "Failed to find PM_PreventMegaBunnyJumping address inside client.dll" );
		return false;
	}

	if( !PM_PreventMegaBunnyJumpingHL )
	{
		ERROR( "Failed to find PM_PreventMegaBunnyJumping address inside hl.dll" );
		return false;
	}

	unsigned char ret[ 1 ] = { 0xC3 };
	memory::Patch( ( void* )PM_PreventMegaBunnyJumpingClient, ret, 1 );
	memory::Patch( ( void* )PM_PreventMegaBunnyJumpingHL, ret, 1 );

	return true;
}

bool PatchAutoJump( HMODULE clientdll, HMODULE hldll )
{
	const char* patterns[ ] =
	{
		"\x74\x05\xE9????\xA1????\xC7\x80",
		"\x74\x05\xE9????\x8B\x15????\xC7\x82",
		"\x0F\x85????\x89\x81"
	};

	DWORD clientptr = 0;
	DWORD hlptr = 0;

	for( int i = 0; i < sizeof( patterns ) / sizeof( patterns[ 0 ] ); i++ )
	{
		clientptr = memory::Find( clientdll, patterns[ i ] );
		hlptr = memory::Find( hldll, patterns[ i ] );

		if( clientptr && hlptr )
			break;
	}

	if( !clientptr )
	{
		ERROR( "Failed to find auto jump address inside client.dll" );
		return false;
	}

	if( !hldll )
	{
		ERROR( "Failed to find auto jump address inside hl.dll" );
		return false;
	}

	if( *( char* )clientptr == 0x0F )
	{
		unsigned char nop[ 6 ] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		memory::Patch( ( void* )clientptr, nop, 6 );
		memory::Patch( ( void* )hlptr, nop, 6 );
	}
	else if( *( char* )clientptr == 0x74 )
	{
		unsigned char jmp[ 1 ] = { 0xEB };
		memory::Patch( ( void* )clientptr, jmp, 1 );
		memory::Patch( ( void* )hlptr, jmp, 1 );
	}
	else
	{
		char error[ 1024 ];
		wsprintfA( error, "Unknown opcode in auto jump patch (0x%X)", *( char* )clientptr );
		ERROR( error );

		return false;
	}

	return true;
}

void Start( HINSTANCE mod )
{
	HMODULE clientdll = 0;
	HMODULE hldll = 0;

	do
	{
		clientdll = GetModuleHandleA( "client.dll" );
		hldll = GetModuleHandleA( "hl.dll" );

		Sleep( 1000 );
	}
	while( !clientdll || !hldll );

	bool speedcap = PatchSpeedCap( clientdll, hldll );
	bool autojump = PatchAutoJump( clientdll, hldll );

	if( !speedcap || !autojump )
		FreeLibraryAndExitThread( mod, 0 );
}

BOOL WINAPI DllMain( HINSTANCE mod, DWORD reason, void* reserved )
{
	if( reason == DLL_PROCESS_ATTACH )
	{
		const auto thread = CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )Start, mod, 0, 0 );
		if( thread )
		{
			CloseHandle( ( HANDLE )thread );
			return true;
		}
	}

	return false;
}