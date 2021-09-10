// hook.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

HANDLE hProcess = 0;

void __stdcall ntHook();
void __stdcall DIP();

DWORD GetPidByProcessName(WCHAR* name);
void JumpHook(DWORD* dst, DWORD* src);
LPVOID alloc();



int main()
{
    
	wchar_t processName[] = L"suddenattack.exe";
	DWORD pid = GetPidByProcessName(processName);

	if (pid == 0) {
		std::cout << "not find process";
		return 0;
	}

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);


	LPVOID pNtHook = alloc();
	WriteProcessMemory(hProcess, pNtHook, &ntHook, 1024, NULL);

	LPVOID pDIP = alloc();
	WriteProcessMemory(hProcess, pDIP, &DIP, 1024, NULL);

	
	int v = (DWORD)pNtHook + 0x48;
	WriteProcessMemory(hProcess, LPVOID((DWORD)pNtHook + 0x2B), &v, 4, NULL);

	v = (DWORD)pDIP + 3;
	WriteProcessMemory(hProcess, LPVOID((DWORD)pNtHook + 0x33), &v, 4, NULL);

	int ntEnterCriticalSection = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEnterCriticalSection");
	v = ntEnterCriticalSection + 5;
	JumpHook((DWORD*)((DWORD)pNtHook + 0x40), (DWORD*)v);

	int pDevice = (DWORD)pDIP + 0x200;
	int iStride = (DWORD)pDIP + 0x300;
	for (int i = 0; i < 1024; i++) {
		ReadProcessMemory(hProcess, LPVOID((DWORD)pDIP + i), &v, 4, NULL);
		if (v == 0x7FFFFFFF) {
			WriteProcessMemory(hProcess, LPVOID((DWORD)pDIP + i), &pDevice, 4, NULL);
		}
		if (v == 0x6FFFFFFF) {
			WriteProcessMemory(hProcess, LPVOID((DWORD)pDIP + i), &iStride, 4, NULL);
		}
	}

	JumpHook((DWORD*)ntEnterCriticalSection, (DWORD*)((DWORD)pNtHook + 3));
	CloseHandle(hProcess);

	std::cout << "hook suceess";

	//CrashRpt.MursumUT_PrintToErrorLog >> log file clear
	//CrashRpt.dll + A08F4 >> dd 0
}

void __stdcall ntHook() {
	__asm {
		mov eax, [esp]
		cmp dword ptr [eax + 0x0C], 0x00187B83
		jne origin

		mov eax, [esp + 0x48]
		cmp eax, 0x00401000
		jb origin
		cmp eax, 0x006A0000
		ja origin
		cmp dword ptr [eax - 0x04], 0x00000148
		jne origin

		mov eax, 0x7FFFFFFF
		mov [esp], eax

		mov eax, 0x7FFFFFFF
		mov [esp + 0x48], eax
		jmp cls1

		origin:
		_emit 0x55
		_emit 0x8B
		_emit 0xEC
		_emit 0xE9
		_emit 0x00
		_emit 0x00
		_emit 0x00
		_emit 0x00

		cls1:
		ret 0x0004

		cls2:
		pop ecx
		pop edi
		pop esi
		pop ebx
		leave
		ret 0x001C
	}
}


void __stdcall DIP() {
	__asm {
		push[ebp + 0x1C]
		mov eax, [esi]
		push[ebp + 0x18]
		push[ebp + 0x14]
		mov ecx, [eax]
		push[ebp + 0x10]
		push[ebp + 0x0C]
		push[ebp + 0x08]
		push eax
		pushad
		 /*
			  REPE MOVSD CPY

			  pDevice
			  Type
			  BaseVertexIndex
			  MinVertexIndex
			  NumVertices
			  startIndex
			  primCount
		*/
		lea esi, [esp + 0x20]
		mov edi, 0x7FFFFFFF // pDevice
		mov ecx, 8
		repe movsd

		// FullBright
		push 00 // FALSE
		push 0x00000089 // D3DRS_LIGHTING
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x000000E4] //SetRenderState


		// Stride Compare
		mov eax, 0x6FFFFFFF // iStride
		push eax
		add eax, 4
		push eax // iOffsetInBytes
		add eax, 4
		push eax // pStreamData
		push 00
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		mov ecx, [edi]
		push edi
		call dword ptr[ecx + 0x00000194] //GetStreamData
		mov eax, 0x6FFFFFFF // iStride
		mov eax, [eax]
		cmp eax, 68
		je ifStride
		cmp eax, 40
		je ifStride
		cmp eax, 44
		jne elseStride
		ifStride:
		// Character Wall Hack
		push 00 // ZB_FALSE
		push 07 // Zbuffer
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		mov eax, [edi]
		push edi
		call dword ptr[eax + 0x000000E4] // SetRenderState
			
		push 01 // D3DCMP_NEVER
		push 0x17 // D3DRS_ZFUNC
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		mov eax, [edi]
		push edi
		call dword ptr[eax + 0x000000E4] // SetRenderState

		// Chams
		push 0xFFFF0000 // HideColor
		push 0x3C // D3DRS_TEXTUREFACTOR
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x000000E4] // SetRenderState


		push 01
		push 02
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]

		push 03
		push 03
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]

		push 04
		push 01
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]

		push 03
		push 05
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]

		push 02
		push 04
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]

		// Hide
		mov eax, 0x7FFFFFFF // pDevice
		push [eax + 0x1C]
		push [eax + 0x18]
		push [eax + 0x14]
		push [eax + 0x10]
		push [eax + 0x0C]
		push [eax + 0x08]
		push [eax + 0x04]
		mov edi, [eax]
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x000000148]
		add esp, 4

		// Show
		push 01 // ZB_FALSE
		push 07 // Zbuffer
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		mov eax, [edi]
		push edi
		call dword ptr[eax + 0x000000E4] // SetRenderState
			
		push 04 // D3DCMP_LESSEQUAL
		push 0x17 // D3DRS_ZFUNC
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		mov eax, [edi]
		push edi
		call dword ptr[eax + 0x000000E4] // SetRenderState

		// Chams
		push 0xFF00FF00 // ShowColor
		push 0x3C // D3DRS_TEXTUREFACTOR
		mov edi, 0x7FFFFFFF // pDevice
		mov edi, [edi]
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x000000E4] // SetRenderState
		push 01
		push 02
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]
		push 03
		push 03
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]
		push 04
		push 01
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]
		push 03
		push 05
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]
		push 02
		push 04
		push 00
		push edi
		mov eax, [edi]
		call dword ptr[eax + 0x0000010C]
		elseStride:
		popad
		call dword ptr[ecx + 0x00000148]
		pop esi
		pop ebp
		ret 0x0018
	}
}

DWORD GetPidByProcessName(WCHAR* name) {
	PROCESSENTRY32W entry;
	memset(&entry, 0, sizeof(PROCESSENTRY32W));
	entry.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = 0;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(hSnapShot, &entry)) {
		do {
			if (!wcscmp(name, entry.szExeFile)) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapShot, &entry));
	}
	CloseHandle(hSnapShot);
	return pid;
}

void JumpHook(DWORD* dst, DWORD* src) {
	DWORD dOldProtect;
	VirtualProtectEx(hProcess, dst, 5, PAGE_EXECUTE_READWRITE, &dOldProtect);
	int v = 0xE9;
	WriteProcessMemory(hProcess, dst, &v, 1, NULL);
	v = (DWORD)src - (DWORD)dst - 5;
	WriteProcessMemory(hProcess, (DWORD*)((DWORD)dst + 1), &v, 4, NULL);
	VirtualProtectEx(hProcess, dst, 5, dOldProtect, &dOldProtect);
}


LPVOID alloc() {
	return VirtualAllocEx(hProcess, (LPVOID)NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}
