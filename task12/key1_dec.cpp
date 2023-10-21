#include <windows.h>
#include <iostream>

void key_check()
{
	unsigned char enc1[48] = {
		0x2A, 0x23, 0x33, 0x37, 0x28, 0x5B, 0x40, 0x41, 0x46, 0x2B, 0x20, 0x2E,
		0x20, 0x20, 0x5F, 0x59, 0x42, 0x40, 0x33, 0x21, 0x2D, 0x3D, 0x37, 0x57,
		0x5D, 0x5B, 0x43, 0x35, 0x39, 0x2C, 0x3E, 0x2A, 0x40, 0x55, 0x5F, 0x5A,
		0x70, 0x73, 0x75, 0x6D, 0x6C, 0x6F, 0x72, 0x65, 0x6D, 0x69, 0x70, 0x73
	};
	unsigned char key[16] = {
		0x6D, 0x75, 0x73, 0x70, 0x69, 0x6D, 0x65, 0x72, 0x73, 0x70, 0x69, 0x6D,
		0x65, 0x72, 0x6F, 0x6C
	};
	char key1[] = "remipsumloremipsumloremipsumlo";
	for (int i = 0; i < sizeof(enc1); ++i)
	{
		unsigned char c = *((BYTE*)key1 + ((i + 8) % strlen(key1))) ^ *((BYTE*)enc1 + i);
		printf("%c", c);
	}
	printf("\n");
}
