#include <fstream>
#include <stdexcept>
#include <vector>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include "forfile.h"
using namespace std;

void write_encrypted(const string &filename, const vector<uint64_t> &data) {
    ofstream file(filename, ios::binary);
    if (!file) throw runtime_error("Failed to open file for writing");
    file.write(reinterpret_cast<const char*>(data.data()), data.size() * sizeof(uint64_t));
}

vector<uint64_t> read_encrypted(const string &filename) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file) throw runtime_error("Failed to open file " + filename + " for reading");

    const auto size = file.tellg();
    file.seekg(0);
    vector<uint64_t> result(size / sizeof(uint64_t));
    file.read(reinterpret_cast<char*>(result.data()), size);
    return result;
}

void write_binary(const string &filename, const vector<uint8_t> &data) {
    ofstream file(filename, ios::binary);
    if (!file) throw runtime_error("Failed to open file for writing");
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

vector<uint8_t> read_binary(const string &filename) {
    ifstream file(filename, ios::binary);
    if (!file) throw runtime_error("Failed to open file " + filename + " for reading");
    return vector<uint8_t>(
        istreambuf_iterator<char>(file),
        istreambuf_iterator<char>()
    );
}

string readConfig() {
    ifstream configFile("config.txt");
    string currentDir;
    if (configFile.is_open()) {
        getline(configFile, currentDir);
        configFile.close();
    } else {
        char buffer[FILENAME_MAX];
        if (getcwd(buffer, FILENAME_MAX) != nullptr) {
            currentDir = string(buffer);
            ofstream outConfig("config.txt");
            outConfig << currentDir;
            outConfig.close();
        } else {
            cerr << "Ошибка получения текущей директории" << endl;
            currentDir = ".";
        }
    }
    return currentDir;
}

void writeConfig(const string& newDir) {
    ofstream configFile("config.txt");
    if (configFile.is_open()) {
        configFile << newDir;
        configFile.close();
    } else {
        cerr << "Ошибка записи в конфигурационный файл" << endl;
    }
}

bool is_binary_data(const vector<uint8_t>& data) {
    const size_t check_size = min(data.size(), static_cast<size_t>(512));

    for (size_t i = 0; i < check_size; i++) {
        uint8_t byte = data[i];

        if (byte == 0 || (byte < 32 && byte != '\n' && byte != '\r' && byte != '\t')) {
            return true;
        }
    }
    return false;
}

bool directoryExists(const string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR);
}