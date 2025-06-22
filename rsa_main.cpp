#define RSA_EXPORTS
#include <iostream>
#include <clocale>
#include "rsa_main.h"
#include <fstream>
#include <cmath>
#include <random>
#include <tuple>
#include "forfile.h"

using namespace std;

uint64_t mod_pow(uint64_t a, uint64_t x, const uint64_t p) {
    uint64_t res = 1;
    a %= p;
    while (x > 0) {
        if (x % 2 == 1)
            res = (res * a) % p;
        a = (a * a) % p;
        x /= 2;
    }
    return res;
}

bool isPrime(const uint64_t n) {
	if (n <= 1) {
	    return false;
	}
	if (n % 2 == 0) {
	    return false;
	}
	for (uint64_t i = 3; i <= sqrt(n); i += 2) {
	    if (n % i == 0) {
	        return false;
	    }
	}
	return true;
}

uint64_t generate_prime(const uint64_t min, const uint64_t max) {
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<uint64_t> dist(min, max);

    uint64_t num;
    do {
        num = dist(gen);
    } while (!isPrime(num));

    return num;
}

tuple <int64_t, int64_t, int64_t> extEvklid(vector<uint64_t>& r, vector<int64_t>& x, vector<int64_t>& y){
	int64_t i = 1;
	while (r[i] != 0) {
        const uint64_t q = r[i - 1] / r[i];
        r.push_back(r[i-1] - q * r[i]);
        x.push_back(x[i-1] - q * x[i]);
        y.push_back(y[i-1] - q * y[i]);
        i++;
    }
	return make_tuple(r[i-1], x[i-1], y[i-1]);
}

uint64_t mod_inverse(const uint64_t a, const uint64_t m) {
	vector <uint64_t> r = {m, a};
	vector <int64_t> u = {1, 0};
	vector <int64_t> v = {0, 1};
	const tuple <uint64_t, int64_t, int64_t> res = extEvklid(r, u, v);
	if (get<0>(res) != 1){
		cout<< "Обратного элемента d не существует!"<<endl;
		return 0;
	}
	int64_t inverse = get<2>(res);
	if (inverse < 0) {
		inverse += m;
	}
	return inverse % m;
}

void generate_keys(uint64_t &mod, uint64_t &e, uint64_t &d) {
    const uint64_t p = generate_prime(10000, 50000);
    const uint64_t q = generate_prime(10000, 50000);

    mod = p * q;
    const uint64_t phi = (p - 1) * (q - 1);

    e = 65537;
    d = mod_inverse(e, phi);
}

vector<uint64_t> encrypt(const vector<uint8_t> &data, const uint64_t e, const uint64_t mod) {
    vector<uint64_t> result;
    for (const uint8_t byte: data) {
        result.push_back(mod_pow(byte, e, mod));
    }
    return result;
}

vector<uint8_t> decrypt(const vector<uint64_t> &data, const uint64_t d, const uint64_t mod) {
    vector<uint8_t> result;
    for (const uint64_t num: data) {
        result.push_back(static_cast<uint64_t>(mod_pow(num, d, mod)));
    }
    return result;
}

void rsaCipherFunc(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &cipher)
{
    setlocale(LC_ALL, "ru_RU.UTF-8");

    uint64_t mod, e, d;
    generate_keys(mod, e, d);

    string cipherFile;
    string keysFile;
    if (!isHand)
    {
        size_t dot_pos = inputFile.find('.');
        string name = inputFile.substr(0, dot_pos);
        keysFile = keys_f + name;
        cipherFile = cipher + name;
    }
    else
    {
        keysFile = keys_f;
        cipherFile = cipher;
    }

    vector<uint64_t> keys = {e, d, mod};
    write_encrypted(keysFile, keys);

    const string encrypted_file = cipherFile;
    ifstream in(inputFile, ios::binary | ios::ate);
    if (!in) {
        throw runtime_error("Невозможно открыть файл: " + inputFile);
    }
    const auto size = in.tellg();
    in.seekg(0);
    vector<uint8_t> plaintext(size);
    in.read(reinterpret_cast<char*>(plaintext.data()), size);

    vector<uint64_t> encrypted = encrypt(plaintext, e, mod);
    write_encrypted(encrypted_file, encrypted);
    cout << "Шифрование окончено!\n";
    if (isVisible) cout << "Зашифрованные данные записаны в " << encrypted_file << endl << "Ключи записаны в " << keysFile << endl;
}

void rsaDecipherFunc(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string& keys, const string& inputFile)
{
    setlocale(LC_ALL, "ru_RU.UTF-8");
    string keysFile;
    string decipherFile;
    string cipherFile;

    if (!isHand)
    {
        size_t reshPos = cipher.find('#');
        size_t dotPos = cipher.find('.');
        string name = cipher.substr(reshPos + 1, dotPos);
        keysFile = keys + name;
        cipherFile = cipher;
        decipherFile = decipher;
    }
    else
    {
        keysFile = keys;
        cipherFile = cipher;
        decipherFile = decipher;
    }

    uint64_t d = read_encrypted(keysFile)[1];
    uint64_t mod = read_encrypted(keysFile)[2];

    const string encrypted_file = cipherFile;
    const string decrypted_file = decipherFile;

    vector<uint64_t> encrypted_data = read_encrypted(encrypted_file);
    vector<uint8_t> decrypted = decrypt(encrypted_data, d, mod);
    if (is_binary_data(decrypted)) {
        write_binary(decrypted_file, decrypted);
    } else {
        ofstream out(decrypted_file);
        out << string(decrypted.begin(), decrypted.end());
    }
    if (isVisible) cout << "Расшифрованный файл: " << decrypted_file << endl;
    cout << "Дешифрование окончено!\n";
}
