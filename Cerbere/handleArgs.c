#include "handleArgs.h"
#include <windows.h>
#include <stdio.h>

size_t strpos(char element, char* string) {
	size_t result = -1;
	for (int i = 0; i < strlen(string); i++) {
		if (string[i] == element) {
			return i;
		}
	}
	return result;
}

int handleArgs(int argc, char** argv, Args** args) {
	*args = calloc(argc, sizeof(Args));
	if (!(*args)) {
		printf("[x] Failed to allocate args structure\n");
		exit(-1);
	}
	for (int i = 1; i < argc; i++) {
		if (strlen(argv[i]) > 0 && argv[i][0] == '/') {
			size_t pos = strpos(':', argv[i]);
			int isSwitch = pos == -1;
			if (pos == -1) { pos = strlen(argv[i]); }
			(*args)[i - 1].key = calloc(pos, sizeof(char));
			if (!(*args)[i - 1].key) {
				printf("[x] Failed to allocate args key element\n");
				exit(-1);
			}
			CopyMemory((*args)[i - 1].key, &argv[i][1], pos - 1);

			if (isSwitch) {continue;}

			(*args)[i - 1].value = calloc(strlen(argv[i]) - pos, sizeof(char));
			if (!(*args)[i - 1].value) {
				printf("[x] Failed to allocate args value element\n");
				exit(-1);
			}
			CopyMemory((*args)[i - 1].value, &argv[i][pos + 1], strlen(argv[i]) - pos - 1);
		}
	}
}

int Args_hasKey(Args* args, char* key) {
	Args* currentArg = args;
	while(currentArg->key){
		if (strcmp(currentArg->key, key) == 0) {
			return 1;
		}
		currentArg += 1;
	}
	return 0;
}

void Args_getKey(Args* args, char* key, char** value) {
	Args* currentArg = args;
	while (currentArg->key) {
		if (strcmp(currentArg->key, key) == 0) {
			*value = calloc(strlen(currentArg->value)+1, sizeof(char));
			CopyMemory(*value, currentArg->value, strlen(currentArg->value));
			return;
		}
		currentArg += 1;
	}
}