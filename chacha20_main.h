#ifndef CHACHA20_H
#define CHACHA20_H
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

void ChaCha20Encrypt(unsigned char key[32], unsigned char nonce[12], const unsigned char* in, unsigned char* out, size_t size);
void QR(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d);
void ChaCha20Block(unsigned char key[32], unsigned char nonce[12], uint32_t count, unsigned char output[64]);
void generateRandomKeyAndNonce(vector<unsigned char>& key, vector<unsigned char>& nonce);
void chacha20CipherFunc(const string &inputFile, bool isHand, bool isVisible, const string &keys_f="chacha20_keys#", const string &nonce_f="chacha20_nonce#", const string &cipher="chacha20_encrypted#");
void chacha20DecipherFunc(const string& cipher, bool isHand, bool isVisible, const string& decipher="chacha20_decrypted#", const string &keys_f="chacha20_keys#", const string &nonce_f="chacha20_nonce#", const string& inputFile=".");
#endif //CHACHA20_H
