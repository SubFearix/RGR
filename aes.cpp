#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <random>
#include <clocale>
#include <algorithm>
#include "aes.h"
#include "forfile.h"

using namespace std;

const unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const unsigned char invSbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

const unsigned char Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

void generateRandomKeyAndIV(vector<unsigned char>& key, vector<unsigned char>& iv) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    key.resize(16);
    iv.resize(16);

    for (int i = 0; i < 16; i++) {
        key[i] = static_cast<unsigned char>(dis(gen));
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
}

void KeyExpansion(const unsigned char key[16], unsigned char expandedKey[176]) {
    for (int i = 0; i < 16; i++) {
        expandedKey[i] = key[i];
    }

    for (int i = 4; i < 44; i++) {
        unsigned char temp[4];
        for (int j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i-1)*4 + j];
        }

        if (i % 4 == 0) {
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }

            temp[0] ^= Rcon[i/4];
        }

        for (int j = 0; j < 4; j++) {
            expandedKey[i*4 + j] = expandedKey[(i-4)*4 + j] ^ temp[j];
        }
    }
}

void SubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

void InvSubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = invSbox[state[i]];
    }
}

void ShiftRows(unsigned char state[16]) {
    unsigned char temp;

    // Вторую строку сдвигаем на 1 байт влево
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Третью строку сдвигаем на 2 байта влево
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Четвертую строку сдвигаем на 3 байта влево
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

void InvShiftRows(unsigned char state[16]) {
    unsigned char temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

unsigned char gfMultiply(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    unsigned char hiBitSet;

    for (int i = 0; i < 8; i++) {
        if (b & 1) { // Младший бит единица?
            result ^= a; // Прибавляем а к результату (в поле Галуа сложение это XOR)
        }

        hiBitSet = (a & 0x80); // Установлен ли самый левый старший бит?
        a <<= 1; // Логический сдвиг влево на 1 бит (умножение многочлена на x)
        if (hiBitSet) {
            a ^= 0x1b; // XOR (вычитание) с неприводимым многочленом x^8 + x^4 + x^3 + x + 1 (0x1B) (гарантируем, что a всегда остается 8 битным числом)
        }
        b >>= 1; // Переход к следующему биту
    }

    return result;
}

void MixColumns(unsigned char state[16]) {
    unsigned char temp[16];

    for (int i = 0; i < 4; i++) {
        temp[i*4 + 0] = static_cast<unsigned char>(gfMultiply(0x02, state[i * 4 + 0]) ^ gfMultiply(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^
            state[i * 4 + 3]);
        temp[i*4 + 1] = static_cast<unsigned char>(state[i * 4 + 0] ^ gfMultiply(0x02, state[i * 4 + 1]) ^ gfMultiply(0x03, state[i * 4 + 2]) ^
            state[i * 4 + 3]);
        temp[i*4 + 2] = static_cast<unsigned char>(state[i * 4 + 0] ^ state[i * 4 + 1] ^ gfMultiply(0x02, state[i * 4 + 2]) ^ gfMultiply(
            0x03, state[i * 4 + 3]));
        temp[i*4 + 3] = static_cast<unsigned char>(gfMultiply(0x03, state[i * 4 + 0]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gfMultiply(
            0x02, state[i * 4 + 3]));
    }

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

void InvMixColumns(unsigned char state[16]) {
    unsigned char temp[16];

    for (int i = 0; i < 4; i++) {
        temp[i*4 + 0] = static_cast<unsigned char>(gfMultiply(0x0e, state[i * 4 + 0]) ^ gfMultiply(0x0b, state[i * 4 + 1]) ^
            gfMultiply(0x0d, state[i * 4 + 2]) ^ gfMultiply(0x09, state[i * 4 + 3]));
        temp[i*4 + 1] = static_cast<unsigned char>(gfMultiply(0x09, state[i * 4 + 0]) ^ gfMultiply(0x0e, state[i * 4 + 1]) ^
            gfMultiply(0x0b, state[i * 4 + 2]) ^ gfMultiply(0x0d, state[i * 4 + 3]));
        temp[i*4 + 2] = static_cast<unsigned char>(gfMultiply(0x0d, state[i * 4 + 0]) ^ gfMultiply(0x09, state[i * 4 + 1]) ^
            gfMultiply(0x0e, state[i * 4 + 2]) ^ gfMultiply(0x0b, state[i * 4 + 3]));
        temp[i*4 + 3] = static_cast<unsigned char>(gfMultiply(0x0b, state[i * 4 + 0]) ^ gfMultiply(0x0d, state[i * 4 + 1]) ^
            gfMultiply(0x09, state[i * 4 + 2]) ^ gfMultiply(0x0e, state[i * 4 + 3]));
    }

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

void AddRoundKey(unsigned char state[16], const unsigned char roundKey[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

void AESEncryptBlock(unsigned char state[16], const unsigned char expandedKey[176]) {
    AddRoundKey(state, expandedKey);

    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + round*16);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + 10*16);
}

void AESDecryptBlock(unsigned char state[16], const unsigned char expandedKey[176]) {
    AddRoundKey(state, expandedKey + 10*16);
    InvShiftRows(state);
    InvSubBytes(state);

    for (int round = 9; round > 0; round--) {
        AddRoundKey(state, expandedKey + round*16);
        InvMixColumns(state);
        InvShiftRows(state);
        InvSubBytes(state);
    }

    AddRoundKey(state, expandedKey);
}

vector<unsigned char> Padding(const vector<unsigned char>& data) {
    size_t pad_len = 16 - (data.size() % 16);
    vector<unsigned char> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<unsigned char>(pad_len));
    return padded;
}

vector<unsigned char> Unpadding(const vector<unsigned char>& data) {
    if (data.empty()) return data;

    size_t pad_len = data.back();
    if (pad_len == 0 || pad_len > 16) return data;

    for (size_t i = data.size() - pad_len; i < data.size(); i++) {
        if (data[i] != pad_len) {
            return data;
        }
    }

    return vector<unsigned char>(data.begin(), data.end() - pad_len);
}

void XORBlocks(const unsigned char a[16], const unsigned char b[16], unsigned char result[16]) {
    for (int i = 0; i < 16; i++) {
        result[i] = a[i] ^ b[i];
    }
}

vector<unsigned char> AES128_CBC_Encrypt(const vector<unsigned char>& plaintext,
                                        const vector<unsigned char>& key,
                                        const vector<unsigned char>& iv) {
    if (key.size() != 16 || iv.size() != 16) {
        throw runtime_error("Некорректный ключ или вектор инициализации");
    }

    unsigned char expandedKey[176];
    KeyExpansion(key.data(), expandedKey);

    vector<unsigned char> padded = Padding(plaintext);

    vector<unsigned char> ciphertext;
    unsigned char previousBlock[16];
    copy(iv.begin(), iv.end(), previousBlock);

    for (size_t i = 0; i < padded.size(); i += 16) {
        unsigned char block[16];
        copy_n(padded.begin() + i, 16, block);

        XORBlocks(block, previousBlock, block);

        AESEncryptBlock(block, expandedKey);

        copy_n(block, 16, previousBlock);
        ciphertext.insert(ciphertext.end(), block, block + 16);
    }

    return ciphertext;
}

vector<unsigned char> AES128_CBC_Decrypt(const vector<unsigned char>& ciphertext,
                                        const vector<unsigned char>& key,
                                        const vector<unsigned char>& iv) {
    if (key.size() != 16 || iv.size() != 16) {
        throw runtime_error("Некорректный ключ или вектор инициализации");
    }

    unsigned char expandedKey[176];
    KeyExpansion(key.data(), expandedKey);

    vector<unsigned char> plaintext;
    unsigned char previousBlock[16];
    copy(iv.begin(), iv.end(), previousBlock);

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        unsigned char block[16];
        copy_n(ciphertext.begin() + i, 16, block);

        unsigned char ciphertextBlock[16];
        copy_n(block, 16, ciphertextBlock);
        AESDecryptBlock(block, expandedKey);

        XORBlocks(block, previousBlock, block);

        plaintext.insert(plaintext.end(), block, block + 16);
        copy_n(ciphertextBlock, 16, previousBlock);
    }
    vector<unsigned char> unpadded = Unpadding(plaintext);

    return unpadded;
}

void aesCipherFunc(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &iv_f, const string &cipher)
{
    setlocale(LC_ALL, "ru_RU.UTF-8");
    // Генерация ключа и IV
    vector<unsigned char> key, iv;
    generateRandomKeyAndIV(key, iv);

    string cipherFile;
    string keyFile;
    string ivFile;
    if (!isHand)
    {
        size_t dotPos = inputFile.find('.');
        string name = inputFile.substr(0, dotPos);
        keyFile = keys_f + name;
        ivFile = iv_f + name;
        cipherFile = cipher + name;
    }
    else
    {
        keyFile = keys_f;
        ivFile = iv_f;
        cipherFile = cipher;
    }

    const vector<unsigned char> plaintext = read_binary(inputFile);

    write_binary(keyFile, key);
    write_binary(ivFile, iv);
    if (isVisible)
    {
       cout << "\nКлюч сохранен в " + keyFile << endl;
       cout << "Вектор инициализации сохранен в " + ivFile << endl;
    }
    vector<unsigned char> ciphertext = AES128_CBC_Encrypt(plaintext, key, iv);
    write_binary(cipherFile, ciphertext);
    if (isVisible) cout << "\nЗашифрованные данные сохранены в " + cipherFile << endl;
}

void aesDecipherFunc(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string &keys_f, const string &iv_f, const string& inputFile){
    setlocale(LC_ALL, "ru_RU.UTF-8");
    string keyFile;
    string ivFile;
    string decipherFile;
    string cipherFile;

    if (!isHand)
    {
        size_t reshPos = cipher.find('#');
        string name = cipher.substr(reshPos + 1);
        keyFile = keys_f + name;
        ivFile = iv_f + name;
        cipherFile = cipher;
        decipherFile = decipher;
    }
    else
    {
        keyFile = keys_f;
        ivFile = iv_f;
        cipherFile = cipher;
        decipherFile = decipher;
    }

    const vector<unsigned char> loadedKeyForDecrypt = read_binary(keyFile);
    const vector<unsigned char> loadedIVForDecrypt = read_binary(ivFile);
    const vector<unsigned char> ciphertext = read_binary(cipherFile);

    const vector<unsigned char> decrypted = AES128_CBC_Decrypt(ciphertext, loadedKeyForDecrypt, loadedIVForDecrypt);
    write_binary(decipherFile, decrypted);
    if (isVisible) cout << "\nРасшифрованные данные сохранены в " + decipherFile << endl;
}