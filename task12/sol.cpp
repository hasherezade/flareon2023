//hvm.exe FLARE2023FLARE2023FLARE2023FLARE2023 zBYpTBUWJvf9MUH4KtcYv7sdUVUPcjOCiU5G5i63bb+LLBZsAmEk9YlNMplv5SiN

#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>

using namespace std;

uint64_t kChunks1[] = {
	0xF52461025F241CB9,
	0xA318FAFA780C846D,
	0x780C846DF5246102,
	0x5F241CB9A318FAFA,
	0xA318FAFA780C846D,
	0xF52461025F241CB9,
	0x5F241CB9A318FAFA,
	0x780C846DF5246102
};

const size_t chunks_count = sizeof(kChunks1) / sizeof(kChunks1[0]);

void encrypt(uint64_t* iChunks, size_t input_chunks)
{
	int cntr = 0;
	for (int j = 0; j + 1 < input_chunks; j += 2) {
		int i = j + 1;
		uint64_t prev0 = iChunks[i];
		uint64_t prev1 = iChunks[j];

		for (int k = 0; k < chunks_count; k++) {
			uint64_t res0 = prev0 ^ kChunks1[k];
			uint64_t res = res0 ^ prev1;
			prev0 = prev1;
			prev1 = res;
		}

		printf("%d) %lX %lX\n", cntr++, prev1, prev0);
		iChunks[i] = prev0;
		iChunks[j] = prev1;
	}
}

void decrypt(uint64_t* iChunks, size_t input_chunks)
{
	int cntr = 0;
	for (int j = input_chunks - 1; j > 0; j -= 2) {
		int i = j - 1;
		uint64_t prev1 = iChunks[i];
		uint64_t prev0 = iChunks[j];

		for (int k = chunks_count - 1; k >= 0; k--) {
			uint64_t res0 = prev1 ^ kChunks1[k];
			uint64_t res = res0 ^ prev0;
			prev1 = prev0;
			prev0 = res;
		}

		printf("%d) %lX %lX\n", cntr++, prev0, prev1);
		iChunks[i] = prev1;
		iChunks[j] = prev0;
	}
}

void enc_dec_test1()
{
	char input_buf[49] = "ABCD1234567890DEADBEEF66ABCD1234567890DEADBEEF66";
	size_t input_chunks = sizeof(input_buf) / 8;
	uint64_t* iChunks = (uint64_t*)input_buf;

	encrypt(iChunks, input_chunks);
	printf("OUT1: %s\n", input_buf);
	decrypt(iChunks, input_chunks);
	printf("OUT2: %s\n", input_buf);
}


bool enc_dec_test_flare()
{
	char flare_buf[] = "FLARE2023FLARE2023FLARE2023FLARE2023";
	const size_t inp_size = 48;
	char input_buf[inp_size] = { 0 };
	::memcpy(input_buf, flare_buf, sizeof(flare_buf));

	size_t input_chunks = inp_size / 8;
	uint64_t* iChunks = (uint64_t*)input_buf;

	decrypt(iChunks, input_chunks);

	printf("Buf size: %d\n", inp_size);
	printf("---\n");
	for (int i = 0; i < inp_size; i++) {
		unsigned char c = input_buf[i];
		printf("%02x ", c);
	}
	printf("\n---\n");
	bool is_ok = false;
	if ((inp_size & 7) == 0) {
		is_ok = true;
	}
	else {
		printf("Wrong output size: %d!\n", inp_size);
	}

	encrypt(iChunks, input_chunks);

	printf("OUT1: %s\n", input_buf);
	if (::memcmp(input_buf, flare_buf, sizeof(flare_buf) != 0)) {
		return false;
	}
	printf("Passed!\n");
	return is_ok;
}

int main()
{
	enc_dec_test_flare();
	return 0;
}

