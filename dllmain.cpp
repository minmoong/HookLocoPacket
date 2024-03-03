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

// KakaoTalk.exe에서 후킹할 어셈블리어 코드 (Send)
BYTE g_sendTargetPattern[] = {
    0xFF, 0x75, 0x10,            // PUSH DWORD PTR SS:[EBP+10]
    0x8B, 0xCF,                  // MOV ECX, EDI
    0xFF, 0x75, 0x0C,            // PUSH DWORD PTR SS:[EBP+C]
    0xFF, 0x75, 0x08,            // PUSH DWORD PTR SS:[EBP+8]
    0xE8, 0x7B, 0x9F, 0x02, 0x00 // CALL kakaotalk.XXXXXXXX
};

// KakaoTalk.exe에서 후킹할 어셈블리어 코드 (Recv)
BYTE g_recvTargetPattern[] = {
    0xE8, 0xBC, 0x6E, 0xF0, 0xFF, // CALL kakaotalk.XXXXXXXX        ; 복호화 함수 호출
    0x8B, 0x44, 0x24, 0x28,       // MOV EAX, DWORD PTR SS:[ESP+28]
    0x83, 0xC4, 0x20,             // ADD ESP, 20
    0x89, 0x46, 0x3C,             // MOV DWORD PTR DS:[ESI+3C], EAX
    0xB8, 0x01, 0x00, 0x00, 0x00  // MOV EAX, 1
};

HMODULE g_moduleKakao   = NULL;
HANDLE g_processKakao   = NULL;
DWORD g_sendRetAddr     = NULL;
DWORD g_recvRetAddr     = NULL;
DWORD g_sendOrgCallAddr = NULL;

LPCSTR g_sendSignature    = "\033[1;32m" "[Send]" "\033[0m" "\n";
LPCSTR g_recvSignature    = "\033[1;33m" "[Recv]" "\033[0m" "\n";
LPCSTR g_packetIdFormat   = "Packet ID: %d \n";
LPCSTR g_statusCodeFormat = "Status Code: %hd \n";
LPCSTR g_methodFormat     = "Method: %.11s \n";
LPCSTR g_bodyTypeFormat   = "Body Type: 0x%hhx \n";
LPCSTR g_bodyLengthFormat = "Body Length: %d \n";

DWORD WINAPI ThreadProc(LPVOID);
DWORD FindPattern(BYTE*, DWORD);
BOOL SendHook();
BOOL RecvHook();
void SendPacketPrintRoutine();
void RecvPacketPrintRoutine();
void PrintLocoPacket(BYTE*);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        system("chcp 65001");
        system("cls");

        // GetModuleHandleA 함수의 반환값은
        // 내부적으로 KakaoTalk.exe의 PE image의 base address를 의미함
        g_moduleKakao = GetModuleHandleA("KakaoTalk.exe");
        g_processKakao = GetCurrentProcess();

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
    if (!SendHook()) {
        printf("SendHook failed. \n");
        return 1;
    }

    if (!RecvHook()) {
        printf("RecvHook failed. \n");
        return 1;
    }
}

DWORD FindPattern(BYTE* targetPattern, DWORD size) {
    // 미리 알아낸 KakaoTalk.exe의 PE image의 size
    DWORD imageSize = 0x3E4E000;

    BYTE* buffer = (BYTE*)malloc(imageSize);
    if (!ReadProcessMemory(
        g_processKakao,
        (LPCVOID)g_moduleKakao,
        buffer,
        imageSize,
        NULL
    )) {
        printf("ReadProcessMemory failed. Error: %d \n", GetLastError());
        free(buffer);
        return 0;
    }

    for (DWORD i = 0; i < imageSize - size; i++) {
        if (memcmp((BYTE*)(buffer + i), targetPattern, size) == 0) {
            free(buffer);
            return (DWORD)g_moduleKakao + i;
        }
    }

    free(buffer);
    return 0;
}

BOOL SendHook() {
    // 패턴 찾기
    DWORD targetSize = sizeof(g_sendTargetPattern);
    DWORD targetAddress = FindPattern(g_sendTargetPattern, targetSize);

    if (!targetAddress) {
        printf("Target address not found. \n");
        return FALSE;
    }

    // 후킹 후 리턴할 주소 저장
    g_sendRetAddr = targetAddress + targetSize;

    // 원래 CALL 명령의 절대 주소 저장
    g_sendOrgCallAddr = g_sendRetAddr + 0x00029F7B;

    // CALL 명령어 덮어 씌우기
    DWORD jmpAddress = (DWORD)SendPacketPrintRoutine - g_sendRetAddr;
    g_sendTargetPattern[11] = 0xE9;
    memcpy(g_sendTargetPattern + 12, &jmpAddress, sizeof(DWORD));

    if (!WriteProcessMemory(
        g_processKakao,
        (LPVOID)targetAddress,
        g_sendTargetPattern,
        targetSize,
        NULL
    )) {
        printf("WriteProcessMemory failed. Error: %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL RecvHook() {
    // 패턴 찾기
    DWORD targetSize = sizeof(g_recvTargetPattern);
    DWORD targetAddress = FindPattern(g_recvTargetPattern, targetSize);

    if (!targetAddress) {
        printf("Target address not found. \n");
        return FALSE;
    }

    // 후킹 후 리턴할 주소 저장
    g_recvRetAddr = targetAddress + targetSize;

    // 명령어 덮어 씌우기
    DWORD jmpAddress = (DWORD)RecvPacketPrintRoutine - g_recvRetAddr;
    g_recvTargetPattern[15] = 0xE9;
    memcpy(g_recvTargetPattern + 16, &jmpAddress, sizeof(DWORD));

    if (!WriteProcessMemory(
        g_processKakao,
        (LPVOID)targetAddress,
        g_recvTargetPattern,
        targetSize,
        NULL
    )) {
        printf("WriteProcessMemory failed. Error: %d \n", GetLastError());
        return FALSE;
    }
}

void PrintLocoPacket(BYTE* locoPacket) {
    printf(g_packetIdFormat, *(DWORD*)locoPacket);
    printf(g_statusCodeFormat, *(WORD*)(locoPacket + 4));
    printf(g_methodFormat, locoPacket + 6);
    printf(g_bodyTypeFormat, *(locoPacket + 17));
    printf(g_bodyLengthFormat, *(DWORD*)(locoPacket + 18));

    bson_t* bson;
    CHAR* json;

    bson = bson_new_from_data(locoPacket + 22, *(DWORD*)(locoPacket + 18));
    json = bson_as_json(bson, NULL);

    printf("Body Contents: %s \n", json);

    printf("\n");

    bson_free(json);
    bson_destroy(bson);
}

void __declspec(naked) SendPacketPrintRoutine() {
    __asm {
        pushad

        mov ebx, [ebp + 8]

        push g_sendSignature
        call printf
        add esp, 4

        push ebx
        call PrintLocoPacket
        add esp, 4

        popad

        mov eax, g_sendOrgCallAddr
        call eax

        jmp g_sendRetAddr
    }
}

void __declspec(naked) RecvPacketPrintRoutine() {
    __asm {
        cmp [esp - 8], 0
        jne $+31

        pushad

        push g_recvSignature
        call printf
        add esp, 4

        push ebx
        call PrintLocoPacket
        add esp, 4

        popad

        mov eax, 1

        jmp g_recvRetAddr
    }
}
