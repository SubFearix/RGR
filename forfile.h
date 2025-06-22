
#ifndef FORFILE_H
#define FORFILE_H
#include <cstdint>
#include <string>
#include <vector>
using namespace std;

bool is_binary_data(const vector<uint8_t>& data);

void write_encrypted(const string &filename, const vector<uint64_t> &data);
vector<uint64_t> read_encrypted(const string &filename);
void write_binary(const string &filename, const vector<uint8_t> &data);
vector<uint8_t> read_binary(const string &filename);
bool directoryExists(const string& path);
void writeConfig(const string& newDir);
string readConfig();
#endif //FORFILE_H
