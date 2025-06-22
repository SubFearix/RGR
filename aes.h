#ifndef AES_H
#define AES_H
#include <vector>
using namespace std;
void generateRandomKeyAndIV(vector<unsigned char>& key, vector<unsigned char>& iv);
void KeyExpansion(const unsigned char key[16], unsigned char expandedKey[176]);
void SubBytes(unsigned char state[16]);
void InvSubBytes(unsigned char state[16]);
void ShiftRows(unsigned char state[16]);
void InvShiftRows(unsigned char state[16]);
unsigned char gfMultiply(unsigned char a, unsigned char b);
void MixColumns(unsigned char state[16]);
void InvMixColumns(unsigned char state[16]);
void AddRoundKey(unsigned char state[16], const unsigned char roundKey[16]);
void AESEncryptBlock(unsigned char state[16], const unsigned char expandedKey[176]);
void AESDecryptBlock(unsigned char state[16], const unsigned char expandedKey[176]);
vector<unsigned char> Padding(const vector<unsigned char>& data);
vector<unsigned char> Unpadding(const vector<unsigned char>& data);
void XORBlocks(const unsigned char a[16], const unsigned char b[16], unsigned char result[16]);
vector<unsigned char> AES128_CBC_Encrypt(const vector<unsigned char>& plaintext,
                                        const vector<unsigned char>& key,
                                        const vector<unsigned char>& iv);
vector<unsigned char> AES128_CBC_Decrypt(const vector<unsigned char>& ciphertext,
                                        const vector<unsigned char>& key,
                                        const vector<unsigned char>& iv);
void aesCipherFunc(const string &inputFile, bool isHand, bool isVisible, const string &keys_f="aes_keys#", const string &iv_f="aes_iv#", const string &cipher="aes_encrypted#");
void aesDecipherFunc(const string& cipher, bool isHand, bool isVisible, const string& decipher = "aes_decrypted#", const string &keys_f="aes_keys#", const string &iv_f="aes_iv#", const string& inputFile=".");


#endif //AES_H
