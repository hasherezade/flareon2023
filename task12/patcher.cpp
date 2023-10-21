#include <windows.h>

#include <string>
#include <sstream>
#include <iostream>

#include <vector>

using namespace std;

BYTE* g_FullBuf = nullptr;

vector<string> enum_files(string folder)
{
	vector<string> names;
	string search_path = folder + "/*.*";
	WIN32_FIND_DATAA fd;
	HANDLE hFind = ::FindFirstFileA(search_path.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				names.push_back(fd.cFileName);
			}
		} while (::FindNextFileA(hFind, &fd));
		::FindClose(hFind);
	}
	return names;
}


BYTE* load_file(const char* filename, size_t& buf_size)
{
	FILE* fp = nullptr;
	fopen_s(&fp, filename, "rb");
	if (!fp) return nullptr;

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);

	fseek(fp, 0, SEEK_SET);

	BYTE* buf = (BYTE*)::calloc(size, 1);
	if (!buf) return nullptr;

	buf_size = fread(buf, 1, size, fp);
	fclose(fp);
	std::cout << "Loaded: " << buf_size << " bytes\n";
	return buf;
}

bool save_file(const char* filename, BYTE* buf, size_t buf_size)
{
	FILE* fp = nullptr;
	fopen_s(&fp, filename, "wb");
	if (!fp) return false;

	fwrite(buf, 1, buf_size, fp);
	fclose(fp);
	return true;
}

size_t patch_out(BYTE *buf, size_t buf_size)
{
	size_t patches = 0;
	for (size_t i = 0; i < buf_size; ++i) {
		if (buf[i] == 0xC3) {
			size_t x = i;
			if (buf[x - 1] == 0x3 && buf[x - 2] == 0xE6 && buf[x - 0x12] == 0x49) {
				::memset(buf + x - 0x12, 0x90, 0x12);
				patches++;
			}
		}
	}
	return patches;
}

bool patch_files()
{
	string main_dir = "C:\\unpacked\\";
	string inp_file = main_dir + "hvm1_00000000001C0000.bin";
	size_t buf_size = 0;
	BYTE* g_FullBuf = load_file(inp_file.c_str(), buf_size);
	if (!g_FullBuf) {
		std::cerr << "Failed to load!\n";
		return false;
	}
	string pieces_dir = "C:\\unpacked\\pieces\\";
	vector<string>names = enum_files(pieces_dir);
	
	/*
	bp at RVA = 0x1C3E
	command:
	$address=rdx;$size=rax;savedata C:\\unpacked\\{address}_{size}.bin,$address,$size;run
	*/
	for (auto itr = names.begin(); itr != names.end(); ++itr) {
		string base_name = *itr;
		string name = pieces_dir + base_name;
		std::cout << base_name << "\n";

		unsigned int x;
		std::stringstream ss;
		ss << std::hex << base_name;
		ss >> x;
		x &= 0x0FFFF;
		printf("Hex pos: %x\n", x);

		size_t piece_size = 0;
		BYTE* piece = load_file(name.c_str(), piece_size);
		if (!piece) {
			std::cerr << "Failed to load piece\n";
			continue;
		}
		if (g_FullBuf[x - 1] == 0x3 && g_FullBuf[x - 2] == 0xE4 && g_FullBuf[x - 0x12] == 0x49) {
			::memset(g_FullBuf + x - 0x12, 0x90, 0x12);
		}
		::memcpy(g_FullBuf + x, piece, piece_size);
		free(piece);
	}

	size_t patches = patch_out(g_FullBuf, buf_size);
	std::cout << "applied: " << patches << "\n";
	string out_file = main_dir + "hvm1_00000000001C0000_patched3.bin";
	if (save_file(out_file.c_str(), g_FullBuf, buf_size)) {
		std::cout << "Saved patched!\n";
		return true;
	}
	return false;
}

int main()
{
	patch_files();
	return 0;
}
