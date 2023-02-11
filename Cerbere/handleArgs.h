
#pragma once

typedef struct _Args {
	char* key;
	char* value;
} Args;


int handleArgs(int argc, char** argv, Args** args);
size_t strpos(char element, char* string);
int Args_hasKey(Args* args, char* key);
void Args_getKey(Args* args, char* key, char** value);
