#ifndef RSA_MAIN_H
#define RSA_MAIN_H
#include <cstdint>
#include <vector>
#include <string>
using namespace std;
#define RSA_API __attribute__((visibility("default")))

uint64_t mod_pow(uint64_t a, uint64_t x, uint64_t p);
bool isPrime(uint64_t n);
uint64_t generate_prime(uint64_t min, uint64_t max);
tuple<int64_t, int64_t, int64_t> extEvklid(vector<int64_t>& r, vector<int64_t>& x, vector<int64_t>& y);
uint64_t mod_inverse(uint64_t a, uint64_t m);
void generate_keys(uint64_t &mod, uint64_t &e, uint64_t &d);
vector<uint64_t> encrypt(const vector<uint8_t> &data, uint64_t e, uint64_t mod);
vector<uint8_t> decrypt(const vector<uint64_t> &data, uint64_t d, uint64_t mod);
#ifdef __cplusplus
extern "C" {
#endif
RSA_API void rsaCipherFunc(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &cipher);
RSA_API void rsaDecipherFunc(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string& keys, const string& inputFile);
#ifdef __cplusplus
}
#endif
#endif //RSA_MAIN_H
