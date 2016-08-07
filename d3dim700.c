#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

	/* we need something to compare */
	if (!l_len || !s_len)
		return NULL;

	/* "s" must be smaller or equal to "l" */
	if (l_len < s_len)
		return NULL;

	/* special case where s_len == 1 */
	if (s_len == 1)
		return memchr(l, (int)*cs, l_len);

	/* the last position where it's possible to find "s" in "l" */
	last = (char *)cl + l_len - s_len;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && !memcmp(cur, cs, s_len))
			return cur;

	return NULL;
}

FARPROC D3DMalloc;
FARPROC D3DRealloc;
FARPROC D3DFree;
FARPROC Direct3DCreateDevice;
FARPROC CreateTexture;
FARPROC DestroyTexture;
FARPROC SetPriority;
FARPROC GetPriority;
FARPROC SetLOD;
FARPROC GetLOD;
FARPROC Direct3DCreate;
FARPROC FlushD3DDevices;
FARPROC PaletteUpdateNotify;
FARPROC PaletteAssociateNotify;
FARPROC SurfaceFlipNotify;
FARPROC D3DTextureUpdate;
FARPROC D3DBreakVBLock;
FARPROC Direct3D_HALCleanUp;

__declspec(naked) void _D3DMalloc() { __asm { jmp [D3DMalloc] } }
__declspec(naked) void _D3DRealloc() { __asm { jmp [D3DRealloc] } }
__declspec(naked) void _D3DFree() { __asm { jmp [D3DFree] } }
__declspec(naked) void _Direct3DCreateDevice() { __asm { jmp [Direct3DCreateDevice] } }
__declspec(naked) void _CreateTexture() { __asm { jmp [CreateTexture] } }
__declspec(naked) void _DestroyTexture() { __asm { jmp [DestroyTexture] } }
__declspec(naked) void _SetPriority() { __asm { jmp [SetPriority] } }
__declspec(naked) void _GetPriority() { __asm { jmp [GetPriority] } }
__declspec(naked) void _SetLOD() { __asm { jmp [SetLOD] } }
__declspec(naked) void _GetLOD() { __asm { jmp [GetLOD] } }
__declspec(naked) void _Direct3DCreate() { __asm { jmp [Direct3DCreate] } }
__declspec(naked) void _FlushD3DDevices() { __asm { jmp [FlushD3DDevices] } }
__declspec(naked) void _PaletteUpdateNotify() { __asm { jmp [PaletteUpdateNotify] } }
__declspec(naked) void _PaletteAssociateNotify() { __asm { jmp [PaletteAssociateNotify] } }
__declspec(naked) void _SurfaceFlipNotify() { __asm { jmp [SurfaceFlipNotify] } }
__declspec(naked) void _D3DTextureUpdate() { __asm { jmp [D3DTextureUpdate] } }
__declspec(naked) void _D3DBreakVBLock() { __asm { jmp [D3DBreakVBLock] } }
__declspec(naked) void _Direct3D_HALCleanUp() { __asm { jmp [Direct3D_HALCleanUp] } }

const BYTE wantedBytes[] = { 0xB8, 0x00, 0x08, 0x00, 0x00, 0x39 };

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason)
	{
		char szPath[MAX_PATH];
		HMODULE hD3DIm;
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNtHeader;
		DWORD dwCodeBase;
		DWORD dwCodeSize;
		DWORD dwPatchBase;
		DWORD dwOldProtect;

		DisableThreadLibraryCalls(hinstDLL);

		GetSystemDirectory(szPath, MAX_PATH);
		strcat(szPath, "\\d3dim700.dll");
		hD3DIm = LoadLibrary(szPath);

		pDosHeader = (PIMAGE_DOS_HEADER)hD3DIm;
		pNtHeader = (PIMAGE_NT_HEADERS)((char *)pDosHeader + pDosHeader->e_lfanew);
		dwCodeBase = (DWORD)hD3DIm + pNtHeader->OptionalHeader.BaseOfCode;
		dwCodeSize = pNtHeader->OptionalHeader.SizeOfCode;

		dwPatchBase = (DWORD)memmem((void *)dwCodeBase, dwCodeSize, wantedBytes, sizeof(wantedBytes));
		if (dwPatchBase)
		{
			dwPatchBase++;
			VirtualProtect((LPVOID)dwPatchBase, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(DWORD *)dwPatchBase = -1;
			VirtualProtect((LPVOID)dwPatchBase, 4, dwOldProtect, &dwOldProtect);
		}

		D3DMalloc = GetProcAddress(hD3DIm, "D3DMalloc");
		D3DRealloc = GetProcAddress(hD3DIm, "D3DRealloc");
		D3DFree = GetProcAddress(hD3DIm, "D3DFree");
		Direct3DCreateDevice = GetProcAddress(hD3DIm, "Direct3DCreateDevice");
		CreateTexture = GetProcAddress(hD3DIm, "CreateTexture");
		DestroyTexture = GetProcAddress(hD3DIm, "DestroyTexture");
		SetPriority = GetProcAddress(hD3DIm, "SetPriority");
		GetPriority = GetProcAddress(hD3DIm, "GetPriority");
		SetLOD = GetProcAddress(hD3DIm, "SetLOD");
		GetLOD = GetProcAddress(hD3DIm, "GetLOD");
		Direct3DCreate = GetProcAddress(hD3DIm, "Direct3DCreate");
		FlushD3DDevices = GetProcAddress(hD3DIm, "FlushD3DDevices");
		PaletteUpdateNotify = GetProcAddress(hD3DIm, "PaletteUpdateNotify");
		PaletteAssociateNotify = GetProcAddress(hD3DIm, "PaletteAssociateNotify");
		SurfaceFlipNotify = GetProcAddress(hD3DIm, "SurfaceFlipNotify");
		D3DTextureUpdate = GetProcAddress(hD3DIm, "D3DTextureUpdate");
		D3DBreakVBLock = GetProcAddress(hD3DIm, "D3DBreakVBLock");
		Direct3D_HALCleanUp = GetProcAddress(hD3DIm, "Direct3D_HALCleanUp");
	}
	return TRUE;
}
