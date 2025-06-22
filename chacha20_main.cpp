#include "chacha20_main.h"
#include <vector>
#include <cstdint>
#include <clocale>
#include <iostream>
#include <random>

#include "forfile.h"
using namespace std;

void ChaCha20Block(unsigned char key[32], unsigned char nonce[12], uint32_t count, unsigned char output[64])
{
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        reinterpret_cast<uint32_t*>(key)[0], reinterpret_cast<uint32_t*>(key)[1], reinterpret_cast<uint32_t*>(key)[2], reinterpret_cast<uint32_t*>(key)[3],
        reinterpret_cast<uint32_t*>(key)[4], reinterpret_cast<uint32_t*>(key)[5], reinterpret_cast<uint32_t*>(key)[6], reinterpret_cast<uint32_t*>(key)[7],
        count, reinterpret_cast<uint32_t*>(nonce)[0], reinterpret_cast<uint32_t*>(nonce)[1], reinterpret_cast<uint32_t*>(nonce)[2]
    };

    uint32_t stateCopy[16];
    for (int i = 0; i < 16; ++i) {
        stateCopy[i] = state[i];
    }
    for (int i = 0; i < 10; i++)
    {
        QR(stateCopy[0], stateCopy[4], stateCopy[8], stateCopy[12]);
        QR(stateCopy[1], stateCopy[5], stateCopy[9], stateCopy[13]);
        QR(stateCopy[2], stateCopy[6], stateCopy[10], stateCopy[14]);
        QR(stateCopy[3], stateCopy[7], stateCopy[11], stateCopy[15]);

        QR(stateCopy[0], stateCopy[5], stateCopy[10], stateCopy[15]);
        QR(stateCopy[1], stateCopy[6], stateCopy[11], stateCopy[12]);
        QR(stateCopy[2], stateCopy[7], stateCopy[8], stateCopy[13]);
        QR(stateCopy[3], stateCopy[4], stateCopy[9], stateCopy[14]);
    }

    for (int j = 0; j < 16; j++)
    {
        reinterpret_cast<uint32_t*>(output)[j] = stateCopy[j] + state[j];
    }
}

void QR(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
{
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8)  | (d >> 24);
    c += d; b ^= c; b = (b << 7)  | (b >> 25);
}

void ChaCha20Encrypt(unsigned char key[32], unsigned char nonce[12], const unsigned char* in, unsigned char* out, const size_t size)
{
    uint8_t block[64];
    size_t xored = 0;
    uint32_t count = 0;

    while (xored < size) {
        ChaCha20Block(key, nonce, count, block);
        count++;

        size_t toXOR = (size - xored) > 64 ? 64 : (size - xored);
        for (size_t i = 0; i < toXOR; i++) {
            out[xored + i] = in[xored + i] ^ block[i];
        }

        xored += toXOR;
    }
}

void generateRandomKeyAndNonce(vector<unsigned char>& key, vector<unsigned char>& nonce) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    key.resize(32);
    nonce.resize(12);

    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
    for (int i = 0; i < 12; i++) {
        nonce[i] = static_cast<unsigned char>(dis(gen));
    }
}


void chacha20CipherFunc(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &nonce_f, const string &cipher)
{
    setlocale(LC_ALL, "ru_RU.UTF-8");
    vector<unsigned char> key, nonce;
    generateRandomKeyAndNonce(key, nonce);

    string cipherFile;
    string keyFile;
    string nonceFile;
    if (!isHand)
    {
        size_t dotPos = inputFile.find('.');
        string name = inputFile.substr(0, dotPos);
        keyFile = keys_f + name;
        nonceFile = nonce_f + name;
        cipherFile = cipher + name;
    }
    else
    {
        keyFile = keys_f;
        nonceFile = nonce_f;
        cipherFile = cipher;
    }

    const vector<unsigned char> plaintext = read_binary(inputFile);
    size_t size = plaintext.size();

    write_binary(keyFile, key);
    write_binary(nonceFile, nonce);
    if (isVisible)
    {
       cout << "\nКлюч сохранен в " + keyFile << endl;
       cout << "Одноразовый номер сохранен в " + nonceFile << endl;
    }
    vector<unsigned char> ciphertext(size);
    ChaCha20Encrypt(key.data(), nonce.data(), plaintext.data(), ciphertext.data(), size);
    write_binary(cipherFile, ciphertext);
    if (isVisible) cout << "\nЗашифрованные данные сохранены в " + cipherFile << endl;
}

void chacha20DecipherFunc(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string &keys_f, const string &nonce_f, const string& inputFile){
    setlocale(LC_ALL, "ru_RU.UTF-8");
    string keyFile;
    string nonceFile;
    string decipherFile;
    string cipherFile;

    if (!isHand)
    {
        size_t reshPos = cipher.find('#');
        string name = cipher.substr(reshPos + 1);
        keyFile = keys_f + name;
        nonceFile = nonce_f + name;
        cipherFile = cipher;
        decipherFile = decipher;
    }
    else
    {
        keyFile = keys_f;
        nonceFile = nonce_f;
        cipherFile = cipher;
        decipherFile = decipher;
    }

    vector<unsigned char> loadedKeyForDecrypt = read_binary(keyFile);
    vector<unsigned char> loadedNonceForDecrypt = read_binary(nonceFile);
    vector<unsigned char> ciphertext = read_binary(cipherFile);

    size_t size = ciphertext.size();
    vector<unsigned char> decrypted(size);


    ChaCha20Encrypt(loadedKeyForDecrypt.data(), loadedNonceForDecrypt.data(), ciphertext.data(), decrypted.data(), size);
    write_binary(decipherFile, decrypted);
    if (isVisible) cout << "\nРасшифрованные данные сохранены в " + decipherFile << endl;
}