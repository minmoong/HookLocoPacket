/*
 * Created on Sun Feb 25 2024
 *
 * Copyright (c) minmoong. Licensed under the MIT Licence.
 *
 * Title       | HookLocoPacket.dll
 * Description | Get KakaoTalk.exe packet's field through DLL injection.
 */

#define _CRT_SECURE_NO_WARNINGS

#define BSON_STATIC

#include <stdio.h>
#include <bson.h>
#include <windows.h>

// Kakaotalk.exe에서 후킹할 어셈블리어 코드
BYTE g_bTargetPattern[] = {
    0xFF, 0x75, 0x10,            // PUSH DWORD PTR SS:[EBP+10]
    0x8B, 0xCF,                  // MOV ECX, EDI
    0xFF, 0x75, 0x0C,            // PUSH DWORD PTR SS:[EBP+C]
    0xFF, 0x75, 0x08,            // PUSH DWORD PTR SS:[EBP+8]
    0xE8, 0x7B, 0x9F, 0x02, 0x00 // CALL kakaotalk.XXXXXXXX
};

HMODULE g_hModuleKakao = NULL;
HANDLE g_hProcessKakao = NULL;
DWORD g_dwReturnAddress = NULL;
DWORD g_dwOriginalCallAddress = NULL;

LPCSTR szSendSignature = "\033[1;34m[Send Packet]\033[0m \n";
LPCSTR szPacketIdFormat = "Packet ID: %d \n";
LPCSTR szStatusCodeFormat = "Status Code: %hd \n";
LPCSTR szMethodFormat = "Method: %.11s \n";
LPCSTR szBodyTypeFormat = "Body Type: 0x%hhx \n";
LPCSTR szBodyLengthFormat = "Body Length: %d \n";

DWORD WINAPI ThreadProc(LPVOID lpParam);
DWORD FindPattern();
void HookSend();
void PrintBodyContents(BYTE* bBody, DWORD dwSize);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        system("chcp 65001");
        system("cls");

        // GetModuleHandleA 함수의 반환값은
        // 내부적으로 KakaoTalk.exe의 PE image의 base address를 의미함
        g_hModuleKakao = GetModuleHandleA("KakaoTalk.exe");
        g_hProcessKakao = GetCurrentProcess();

        // Kakaotalk.exe의 실행 흐름을 방해하지 않도록 별도의 쓰레드 생성
        if (!CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL)) {
            printf("CreateThread failed. Error: %d \n", GetLastError());
            break;
        }

        break;
    case DLL_PROCESS_DETACH:
        FreeConsole();
        break;
    }
    return TRUE;
}

DWORD WINAPI ThreadProc(LPVOID lpParam) {
    // 패턴 찾기
    DWORD dwTargetAddress = FindPattern();

    if (!dwTargetAddress) {
        printf("Target address not found. \n");
        return 1;
    }

    // 후킹 후 리턴할 주소 저장
    g_dwReturnAddress = dwTargetAddress + sizeof(g_bTargetPattern);

    // 원래 CALL 명령의 절대 주소 저장
    g_dwOriginalCallAddress = g_dwReturnAddress + 0x00029F7B;

    // CALL 명령어 덮어 씌우기
    DWORD dwJmpAddress = (DWORD)HookSend - g_dwReturnAddress;
    g_bTargetPattern[11] = 0xE9;
    memcpy(g_bTargetPattern + 12, &dwJmpAddress, sizeof(DWORD));

    if (!WriteProcessMemory(
        g_hProcessKakao,
        (LPVOID)dwTargetAddress,
        g_bTargetPattern,
        sizeof(g_bTargetPattern),
        NULL
    )) {
        printf("WriteProcessMemory failed. Error: %d \n", GetLastError());
        return 1;
    }

    return 0;
}

DWORD FindPattern() {
    // 미리 알아낸 KakaoTalk.exe의 PE image의 size
    DWORD dwImageSize = 0x3E4E000;

    BYTE* buffer = (BYTE*)malloc(dwImageSize);
    if (!ReadProcessMemory(
        g_hProcessKakao,
        (LPCVOID)g_hModuleKakao,
        buffer,
        dwImageSize,
        NULL
    )) {
        printf("ReadProcessMemory failed. Error: %d \n", GetLastError());
        free(buffer);
        return 0;
    }

    for (DWORD i = 0; i < dwImageSize - sizeof(g_bTargetPattern); i++) {
        if (memcmp((BYTE*)(buffer + i), g_bTargetPattern, sizeof(g_bTargetPattern)) == 0) {
            free(buffer);
            return (DWORD)g_hModuleKakao + i;
        }
    }

    free(buffer);
    return 0;
}

void __declspec(naked) HookSend() {
    __asm {
        pushad

        mov ebx, [ebp + 8]

        push szSendSignature
        call printf
        add esp, 4

        push [ebx]
        push szPacketIdFormat
        call printf
        add esp, 8

        push [ebx + 4]
        push szStatusCodeFormat
        call printf
        add esp, 8

        add ebx, 6
        push ebx
        sub ebx, 6
        push szMethodFormat
        call printf
        add esp, 8

        push [ebx + 17]
        push szBodyTypeFormat
        call printf
        add esp, 8

        push [ebx + 18]
        push szBodyLengthFormat
        call printf
        add esp, 8

        push [ebx + 18]
        add ebx, 22
        push ebx
        sub ebx, 22
        call PrintBodyContents
        add esp, 8

        popad

        mov eax, g_dwOriginalCallAddress
        call eax

        jmp g_dwReturnAddress
    }
}

void PrintBodyContents(BYTE* bBody, DWORD dwSize) {
    bson_t* bson;
    CHAR* json;

    bson = bson_new_from_data(bBody, dwSize);
    json = bson_as_json(bson, NULL);

    printf("Body Contents: %s \n", json);

    printf("\n");

    bson_free(json);
    bson_destroy(bson);
}
