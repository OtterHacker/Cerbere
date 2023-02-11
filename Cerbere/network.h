#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
void sendBytes(char* server, char* port, PBYTE content, int contentSize);
