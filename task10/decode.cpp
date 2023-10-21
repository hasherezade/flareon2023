#include <iostream>
#include <cstring>

unsigned char secret[] = {
	//0x2E, 0x00, 
	0x1B, 0xD5, 0x78, 0xC3, 0x2F, 0x7C, 0xC2, 0xDA, 0x75, 0x2E,
	0x78, 0x32, 0xD6, 0x7B, 0xD8, 0x23, 0x7D, 0xD9, 0x8A, 0x31, 0x3D, 0x86,
	0xCC, 0x2C, 0x81, 0x2D, 0x7C, 0xC4, 0xD6, 0x74, 0x3F, 0x27, 0x82, 0xF6,
	0x57, 0x34, 0xD8, 0x60, 0xC7, 0xE9, 0x32, 0xD0, 0xB1, 0x07, 0x21, 0x8F
};

void decode(unsigned char* buf, size_t len)
{
	unsigned char prev = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = buf[i] + prev;
		buf[i] = c;
		prev = c;
	}
}

void decrypt(unsigned char *buf, size_t buf_size, char *key, size_t key_size)
{
	for (size_t i = 0; i < buf_size; i++) {
		buf[i] ^= key[i % key_size];
	}
}

void printbuf(unsigned char *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		unsigned char c = buf[i];
		printf("%02x = %c\n", c, c);
	}
	printf("---\n");
}


void variant4()
{
//decode(decrypt(decode(secret), decode(key)));
	char key[] = "p/q2-q4!";
	decode((unsigned char*)key, strlen(key));
	
	unsigned char backup[sizeof(secret)];
	::memcpy(backup, secret, sizeof(secret));
	decode(backup, sizeof(backup));
	
	decrypt(backup, sizeof(backup), key, strlen(key));
	std::cout << "Decrypted:" << std::endl;
	printbuf(backup, sizeof(secret));
	
	std::cout << "Decoded:" << std::endl;
	decode(backup, sizeof(backup));
	printbuf(backup, sizeof(backup));
}

void variant3()
{
//decode(decrypt(decode(secret), key));
	char key[] = "p/q2-q4!";
	
	unsigned char backup[sizeof(secret)];
	::memcpy(backup, secret, sizeof(secret));
	decode(backup, sizeof(backup));
	
	decrypt(backup, sizeof(backup), key, strlen(key));
	std::cout << "Decrypted:" << std::endl;
	printbuf(backup, sizeof(secret));
	
	std::cout << "Decoded:" << std::endl;
	decode(backup, sizeof(backup));
	printbuf(backup, sizeof(backup));
}

void variant2()
{
//decode(decrypt(secret, decode(key)));
	char key[] = "p/q2-q4!";
	decode((unsigned char*)key, strlen(key));
	
	unsigned char backup[sizeof(secret)];
	::memcpy(backup, secret, sizeof(secret));
	
	decrypt(backup, sizeof(backup), key, strlen(key));
	std::cout << "Decrypted:" << std::endl;
	printbuf(backup, sizeof(backup));
	
	std::cout << "Decoded:" << std::endl;
	decode(backup, sizeof(backup));
	printbuf(backup, sizeof(backup));
}

void variant1()
{
//decode(decrypt(secret, key));
	char key[] = "p/q2-q4!";

	unsigned char backup[sizeof(secret)];
	::memcpy(backup, secret, sizeof(secret));
	
	decrypt(backup, sizeof(backup), key, strlen(key));
	std::cout << "Decrypted:" << std::endl;
	printbuf(backup, sizeof(backup));
	
	std::cout << "Decoded:" << std::endl;
	decode(backup, sizeof(backup));
	printbuf(backup, sizeof(backup));
}


int main(int argc, char *argv[])
{
	variant1();
	variant2();
	variant3();
	variant4();
	
	return 0;
}