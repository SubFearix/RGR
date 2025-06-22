#include <iostream>
#include <fstream>
#include <clocale>
#include <dlfcn.h>
#include <unistd.h>
#include "forfile.h"
#include <string>

using namespace std;

typedef void (*aesCipherFunc)(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &iv_f, const string &cipher);
typedef void (*aesDecipherFunc)(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string &keys_f, const string &iv_f, const string& inputFile);

typedef void (*chacha20CipherFunc)(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &nonce_f, const string &cipher);
typedef void (*chacha20DecipherFunc)(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string &keys_f, const string &nonce_f, const string& inputFile);

typedef void (*rsaCipherFunc)(const string &inputFile, bool isHand, bool isVisible, const string &keys_f, const string &cipher);
typedef void (*rsaDecipherFunc)(const string& cipher, bool isHand, bool isVisible, const string& decipher, const string& keys, const string& inputFile);

enum class Ciphers {EXIT, RSA, AES, CHACHA20, UNKNOWN};


Ciphers Algs(const int& choice) {
    switch(choice) {
    case 0: return Ciphers::EXIT;
    case 1: return Ciphers::RSA;
    case 2: return Ciphers::AES;
    case 3: return Ciphers::CHACHA20;
    default: return Ciphers::UNKNOWN;
    }
}

enum class Scenes {EXIT, CIPANDDECIPFILE, CIPFILE, DECIPFILE, CIPANDDECIPCONSOLE, CIPCONSOLE, UNKNOWN};

Scenes Methods(const int& choice) {
    switch(choice) {
    case 0: return Scenes::EXIT;
    case 1: return Scenes::CIPANDDECIPFILE;
    case 2: return Scenes::CIPFILE;
    case 3: return Scenes::DECIPFILE;
    case 4: return Scenes::CIPANDDECIPCONSOLE;
    case 5: return Scenes::CIPCONSOLE;
    default: return Scenes::UNKNOWN;
    }
}

void printAlgMenu() {
    cout << "╔══════════════════════════════════════╗\n";
    cout << "║              АЛГОРИТМЫ               ║\n";
    cout << "║              ШИФРОВАНИЯ              ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ 1. RSA                               ║\n";
    cout << "║ 2. AES-128 CBC                       ║\n";
    cout << "║ 3. ChaCha20                          ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ 0. Выход                             ║\n";
    cout << "╚══════════════════════════════════════╝\n";
    cout << "Выберите алгоритм (1-3) или выход (0): ";
}

void printFileMenu() {
    cout << "╔══════════════════════════════════════╗\n";
    cout << "║            РЕЖИМЫ СОЗДАНИЯ           ║\n";
    cout << "║                ФАЙЛОВ                ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ 1. Полуавтоматический (рекомендуется)║\n";
    cout << "║ 2. Ручной                            ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ 0. Выход                             ║\n";
    cout << "╚══════════════════════════════════════╝\n";
    cout << "Выберите режим создания файлов (1,2) или выход (0): ";
}

void printScenMenu() {
    cout << "╔═════════════════════════════════════════════════════════════════╗\n";
    cout << "║                             СЦЕНАРИИ                            ║\n";
    cout << "║                            ШИФРОВАНИЯ                           ║\n";
    cout << "╠════════════════════════════════╦════════════════════════════════╣\n";
    cout << "║           Для файлов           ║           Для консоли          ║\n";
    cout << "╠════════════════════════════════╬════════════════════════════════╣\n";
    cout << "║ 1. Шифрование + дешифрование   ║ 4. Шифрование + дешифрование   ║\n";
    cout << "║ 2. Только шифрование           ║ 5. Только шифрование           ║\n";
    cout << "║ 3. Только дешифрование         ║                                ║\n";
    cout << "╠════════════════════════════════╩════════════════════════════════╣\n";
    cout << "║ 0. Выход                                                        ║\n";
    cout << "╚═════════════════════════════════════════════════════════════════╝\n";
    cout << "Выберите сценарий шифрования (1-5) или выход (0): ";
}

string setupWorkingDirectory() {
    string currentDir = readConfig();
    cout << "╔══════════════════════════════════════╗\n";
    cout << "║      НАСТРОЙКА РАБОЧЕЙ ДИРЕКТОРИИ    ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ Текущая рабочая директория:          ║\n";
    cout << "║ " << currentDir << string(36 - currentDir.length(), ' ') << " ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ 1. Оставить текущую                  ║\n";
    cout << "║ 2. Изменить                          ║\n";
    cout << "╠══════════════════════════════════════╣\n";
    cout << "║ 0. Выход                             ║\n";
    cout << "╚══════════════════════════════════════╝\n";
    cout << "Выберите действие (1,2) или выход (0): ";

    int choiceDir;
    cin >> choiceDir;
    if (cin.fail()) {
        cin.clear();
        throw runtime_error("Ошибка ввода. Ожидается число.");
    }

    switch(choiceDir) {
        case 1:
            system("clear");
            return currentDir;
        case 2: {
            system("clear");
            cout << "Введите новую рабочую директорию: ";
            cin.ignore();
            string newDir;
            getline(cin, newDir);
            if (directoryExists(newDir)) {
                writeConfig(newDir);
                return newDir;
            } else {
                throw runtime_error("Ошибка: директория " + newDir + " не существует");
            }
        }
        case 0:
            cout << "Вы вышли из программы. До скорой встречи!" << endl;
            exit(0);
        default:
            throw runtime_error("Неверный выбор");
    }
}

int main()
{
    setlocale(LC_ALL, "ru_RU.UTF-8");
    try
    {

		char initialDirBuffer[FILENAME_MAX];
		string initialProgramDir;
		if (getcwd(initialDirBuffer, FILENAME_MAX) != nullptr) {
		    initialProgramDir = string(initialDirBuffer);
		} else {
		    cerr << "Ошибка: не удалось получить начальную директорию программы. Используется текущая." << endl;
		    initialProgramDir = ".";
		}

		string workingDataDir = setupWorkingDirectory();
		printAlgMenu();
		bool isHand = false;
		bool isVisible = true;

        int choiceAlg;
        cin >> choiceAlg;
        if (cin.fail()){
            throw runtime_error("Ошибка ввода. Ожидается число.");
        }
        system("clear");
        switch(Algs(choiceAlg)) {
            case Ciphers::RSA:
                {
                	void* handle = dlopen("./librsa.so", RTLD_LAZY);
					if (!handle) {
						cerr << "Ошибка загрузки librsa.so. Программа не может обнаружить библиотеку" << endl;
						return 1;
					}
					rsaCipherFunc rsaCipherPtr = (rsaCipherFunc)dlsym(handle, "rsaCipherFunc");
					rsaDecipherFunc rsaDecipherPtr = (rsaDecipherFunc)dlsym(handle, "rsaDecipherFunc");
					if (!rsaCipherPtr || !rsaDecipherPtr) {
						cerr << "Ошибка получения адреса функции RSA: " << dlerror() << endl;
						dlclose(handle);
						return 1;
					}
                    printScenMenu();
                    int choiceScen;
                    cin >> choiceScen;
                    if (cin.fail()){
                        throw runtime_error("Ошибка ввода. Ожидается число.");
                    }
                    system("clear");
                    switch(Methods(choiceScen)) {
                        case Scenes::CIPANDDECIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            rsaCipherPtr(inputFile, isHand, isVisible, "rsa_keys#", "rsa_encrypted#");
                                            size_t dot_pos = inputFile.find('.');
                                            string name = inputFile.substr(0, dot_pos);
                                            rsaDecipherPtr("rsa_encrypted#" + name, isHand, isVisible, "rsa_decrypted#" + name, "rsa_keys#", inputFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            cout << "Введите название файла для ключей: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                             if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            rsaCipherPtr(inputFile, isHand, isVisible, keysFile, cipherFile);
                                            rsaDecipherPtr(cipherFile, isHand, isVisible, decipherFile, keysFile, inputFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::CIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                isHand = false;
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                             if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            rsaCipherPtr(inputFile, isHand, isVisible, "rsa_keys#", "rsa_encrypted#");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            cout << "Введите название файла для ключей: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                             if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            rsaCipherPtr(inputFile, isHand, isVisible, keysFile, cipherFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::DECIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                isHand = false;
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                             if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            rsaDecipherPtr(cipherFile, isHand, isVisible, decipherFile, "rsa_keys#", ".");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название файла с ключами: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                             if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            rsaDecipherPtr(cipherFile, isHand, isVisible, decipherFile, keysFile, ".");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::CIPANDDECIPCONSOLE:
                            {
                                cin.ignore();
                                if (chdir(workingDataDir.c_str()) != 0) {
    								cerr << "Не удалось перейти в: " << workingDataDir << endl;
    								break;
								}
                                string lines;
                                string line;
                                cout << "Введите текст (Ctrl+D для завершения):\n";
                                while (getline(cin, line)) {
                                    lines += line + "\n";
                                }
                                ofstream fileIn("console");
                                fileIn << lines;
                                fileIn.close();
                                rsaCipherPtr("console", false, false, "rsa_keys#", "rsa_encrypted#");
                                rsaDecipherPtr("rsa_encrypted#console", false, false, "rsa_decrypted#console", "rsa_keys#", "console");
                                ifstream fileOut("rsa_decrypted#console");
                                fileOut.seekg(0);
                                cout << "Расшифрованный ввод:" << endl;
                                while (getline(fileOut, line)) {
                                    cout << line << endl;
                                }
                                if (chdir(initialProgramDir.c_str()) != 0) {
									cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
									break;
								}
                                break;
                            }
                        case Scenes::CIPCONSOLE:
                            {
                                cin.ignore();
                                string lines;
                                string line;
                                if (chdir(workingDataDir.c_str()) != 0) {
    								cerr << "Не удалось перейти в: " << workingDataDir << endl;
    								break;
								}
                                cout << "Введите текст (Ctrl+D для завершения):\n";
                                while (getline(cin, line)) {
                                    lines += line + "\n";
                                }
                                ofstream fileIn("console");
                                fileIn << lines;
                                fileIn.close();
                                rsaCipherPtr("console", false, true, "rsa_keys#", "rsa_encrypted#");
                                if (chdir(initialProgramDir.c_str()) != 0) {
									cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
									break;
								}
                                break;
                            }
                        case Scenes::EXIT:
                            {
                                cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                if (handle) dlclose(handle);
                                return 1;
                            }
                        default: {if (handle) dlclose(handle); throw runtime_error("Такого метода не существует");}
                    }
                    if (handle) dlclose(handle);
                    break;
                }
            case Ciphers::AES:
                {
                	void* handle = dlopen("./libaes.so", RTLD_LAZY);
					if (!handle) {
						cerr << "Ошибка загрузки libaes.so. Программа не может обнаружить библиотеку" << endl;
						return 1;
					}
					// Получаем указатели на функции
					aesCipherFunc aesCipherPtr = (aesCipherFunc)dlsym(handle, "aesCipherFunc");
					aesDecipherFunc aesDecipherPtr = (aesDecipherFunc)dlsym(handle, "aesDecipherFunc");
					if (!aesCipherPtr || !aesDecipherPtr) {
						cerr << "Ошибка получения адреса функции AES: " << dlerror() << endl;
						dlclose(handle);
						return 1;
					}
                    printScenMenu();
                    int choiceScen;
                    cin >> choiceScen;
                    if (cin.fail()){
                        throw runtime_error("Ошибка ввода. Ожидается число.");
                    }
                    system("clear");
                    switch(Methods(choiceScen)) {
                        case Scenes::CIPANDDECIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            aesCipherPtr(inputFile, isHand, isVisible, "aes_keys#", "aes_iv#", "aes_encrypted#");
                                            size_t dot_pos = inputFile.find('.');
                                            string name = inputFile.substr(0, dot_pos);
                                            aesDecipherPtr("aes_encrypted#" + name, isHand, isVisible, "aes_decrypted#" + name, "aes_keys#", "aes_iv#", inputFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            cout << "Введите название файла для ключа: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название файла для вектора инициализации: ";
                                            string ivFile;
                                            cin >> ivFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            aesCipherPtr(inputFile, isHand, isVisible, keysFile, ivFile, cipherFile);
                                            aesDecipherPtr(cipherFile, isHand, isVisible, decipherFile, keysFile, ivFile, inputFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::CIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                isHand = false;
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            aesCipherPtr(inputFile, isHand, isVisible, "aes_keys#", "aes_iv#", "aes_encrypted#");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            cout << "Введите название файла для ключа: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название файла для вектора инициализации: ";
                                            string ivFile;
                                            cin >> ivFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            aesCipherPtr(inputFile, isHand, isVisible, keysFile, ivFile, cipherFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::DECIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                isHand = false;
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            aesDecipherPtr(cipherFile, isHand, isVisible, decipherFile, "aes_keys#", "aes_iv#", "aes_encrypted#");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название файла с ключом: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название файла с вектором инициализации: ";
                                            string ivFile;
                                            cin >> ivFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            aesDecipherPtr(cipherFile, isHand, isVisible, decipherFile, keysFile, ivFile, ".");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::CIPANDDECIPCONSOLE:
                            {
                                cin.ignore();
                                string lines;
                                string line;
                                if (chdir(workingDataDir.c_str()) != 0) {
    								cerr << "Не удалось перейти в: " << workingDataDir << endl;
    								break;
								}
                                cout << "Введите текст (Ctrl+D для завершения):\n";
                                while (getline(cin, line)) {
                                    lines += line + "\n";
                                }
                                ofstream fileIn("console");
                                fileIn << lines;
                                fileIn.close();
                                aesCipherPtr("console", false, false, "aes_keys#", "aes_iv#", "aes_encrypted#");
                                aesDecipherPtr("aes_encrypted#console", false, false, "aes_decrypted#console", "aes_keys#", "aes_iv#", ".");
                                ifstream fileOut("aes_decrypted#console");
                                fileOut.seekg(0);
                                cout << "Расшифрованный ввод:" << endl;
                                while (getline(fileOut, line)) {
                                    cout << line << endl;
                                }
                                if (chdir(initialProgramDir.c_str()) != 0) {
									cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
									break;
											}
                                break;
                            }
                        case Scenes::CIPCONSOLE:
                            {
                                cin.ignore();
                                string lines;
                                string line;
                                if (chdir(workingDataDir.c_str()) != 0) {
    								cerr << "Не удалось перейти в: " << workingDataDir << endl;
    								break;
								}
                                cout << "Введите текст (Ctrl+D для завершения):\n";
                                while (getline(cin, line)) {
                                    lines += line + "\n";
                                }
                                ofstream fileIn("console");
                                fileIn << lines;
                                fileIn.close();
                                aesCipherPtr("console", false, true, "aes_keys#", "aes_iv#", "aes_encrypted#");
                                if (chdir(initialProgramDir.c_str()) != 0) {
									cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
									break;
								}
                                break;
                            }
                        case Scenes::EXIT:
                            {
                                cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                if (handle) dlclose(handle);
                                return 1;
                            }
                        default: {if (handle) dlclose(handle); throw runtime_error("Такого метода не существует");}
                    }
                    if (handle) dlclose(handle);
                    break;
                }
            case Ciphers::CHACHA20:
                {
                	void* handle = dlopen("./libchacha20.so", RTLD_LAZY);
					if (!handle) {
						cerr << "Ошибка загрузки libchacha20.so. Программа не может обнаружить библиотеку" << endl;
						return 1;
					}
					// Получаем указатели на функции
					chacha20CipherFunc chacha20CipherPtr = (chacha20CipherFunc)dlsym(handle, "chacha20CipherFunc");
					chacha20DecipherFunc chacha20DecipherPtr = (chacha20DecipherFunc)dlsym(handle, "chacha20DecipherFunc");
					if (!chacha20CipherPtr || !chacha20DecipherPtr) {
						cerr << "Ошибка получения адреса функции ChaCha20: " << dlerror() << endl;
						dlclose(handle);
						return 1;
					}
                    printScenMenu();
                    int choiceScen;
                    cin >> choiceScen;
                    if (cin.fail()){
                        throw runtime_error("Ошибка ввода. Ожидается число.");
                    }
                    system("clear");
                    switch(Methods(choiceScen)) {
                        case Scenes::CIPANDDECIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            chacha20CipherPtr(inputFile, isHand, isVisible, "chacha20_keys#", "chacha20_nonce#", "chacha20_encrypted#");
                                            size_t dot_pos = inputFile.find('.');
                                            string name = inputFile.substr(0, dot_pos);
                                            chacha20DecipherPtr("chacha20_encrypted#" + name, isHand, isVisible, "chacha20_decrypted#" + name, "chacha20_keys#", "chacha20_nonce#", inputFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            cout << "Введите название файла для ключа: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название файла для одноразового номера: ";
                                            string nonceFile;
                                            cin >> nonceFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            chacha20CipherPtr(inputFile, isHand, isVisible, keysFile, nonceFile, cipherFile);
                                            chacha20DecipherPtr(cipherFile, isHand, isVisible, decipherFile, keysFile, nonceFile, inputFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::CIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                isHand = false;
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            chacha20CipherPtr(inputFile, isHand, isVisible, "chacha20_keys#", "chacha20_nonce#", "chacha20_encrypted#");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название исходного файла: ";
                                            string inputFile;
                                            cin >> inputFile;
                                            cout << "Введите название файла для ключа: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название файла для одноразового номера: ";
                                            string nonceFile;
                                            cin >> nonceFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            chacha20CipherPtr(inputFile, isHand, isVisible, keysFile, nonceFile, cipherFile);
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::DECIPFILE:
                            {
                                printFileMenu();
                                int choiceReg;
                                cin >> choiceReg;
                                if (cin.fail()){
                                    throw runtime_error("Ошибка ввода. Ожидается число.");
                                }
                                system("clear");
                                isHand = false;
                                switch (choiceReg) {
                                    case 1:
                                        {
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            chacha20DecipherPtr(cipherFile, isHand, isVisible, decipherFile, "chacha20_keys#", "chacha20_nonce#", ".");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 2:
                                        {
                                            isHand = true;
                                            cout << "Введите название файла с ключом: ";
                                            string keysFile;
                                            cin >> keysFile;
                                            cout << "Введите название файла с одноразовым номером: ";
                                            string nonceFile;
                                            cin >> nonceFile;
                                            cout << "Введите название зашифрованного файла: ";
                                            string cipherFile;
                                            cin >> cipherFile;
                                            cout << "Введите название файла для расшифрованных данных: ";
                                            string decipherFile;
                                            cin >> decipherFile;
                                            if (chdir(workingDataDir.c_str()) != 0) {
    											cerr << "Не удалось перейти в: " << workingDataDir << endl;
    											break;
											}
                                            chacha20DecipherPtr(cipherFile, isHand, isVisible, decipherFile, keysFile, nonceFile, ".");
                                            if (chdir(initialProgramDir.c_str()) != 0) {
												cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
												break;
											}
                                            break;
                                        }
                                    case 0:
                                        {
                                            cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                            return 1;
                                        }
                                    default: {throw runtime_error("Такого режима создания не существует");}
                                }
                                break;
                            }
                        case Scenes::CIPANDDECIPCONSOLE:
                            {
                                cin.ignore();
                                string lines;
                                string line;
                                if (chdir(workingDataDir.c_str()) != 0) {
    								cerr << "Не удалось перейти в: " << workingDataDir << endl;
    								break;
								}
                                cout << "Введите текст (Ctrl+D для завершения):\n";
                                while (getline(cin, line)) {
                                    lines += line + "\n";
                                }
                                ofstream fileIn("console");
                                fileIn << lines;
                                fileIn.close();
                                chacha20CipherPtr("console", false, false, "chacha20_keys#", "chacha20_nonce#", "chacha20_encrypted#");
                                chacha20DecipherPtr("chacha20_encrypted#console", false, false, "chacha20_decrypted#console", "chacha20_keys#", "chacha20_nonce#", ".");
                                ifstream fileOut("chacha20_decrypted#console");
                                fileOut.seekg(0);
                                cout << "Расшифрованный ввод:" << endl;
                                while (getline(fileOut, line)) {
                                    cout << line << endl;
                                }
                                if (chdir(initialProgramDir.c_str()) != 0) {
									cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
									break;
								}
                                break;
                            }
                        case Scenes::CIPCONSOLE:
                            {
                                cin.ignore();
                                string lines;
                                string line;
                                if (chdir(workingDataDir.c_str()) != 0) {
    								cerr << "Не удалось перейти в: " << workingDataDir << endl;
    								break;
								}
                                cout << "Введите текст (Ctrl+D для завершения):\n";
                                while (getline(cin, line)) {
                                    lines += line + "\n";
                                }
                                ofstream fileIn("console");
                                fileIn << lines;
                                fileIn.close();
                                chacha20CipherPtr("console", false, true, "chacha20_keys#", "chacha20_nonce#", "chacha20_encrypted#");
                                if (chdir(initialProgramDir.c_str()) != 0) {
									cerr << "Не удалось вернуться в: " << initialProgramDir << endl;
									break;
								}
                                break;
                            }
                        case Scenes::EXIT:
                            {
                                cout << "Вы вышли из программы. До скорой встречи!" << endl;
                                if (handle) dlclose(handle);
                                return 1;
                            }
                        default: {if (handle) dlclose(handle); throw runtime_error("Такого метода не существует");}
                    }
                    if (handle) dlclose(handle);
                    break;
                }
            case Ciphers::EXIT:
                {
                    cout << "Вы вышли из программы. До скорой встречи!" << endl;
                    return 1;
                }
            default: {throw runtime_error("Такого алгоритма не существует");}
        }
    } catch (const exception& error){
        cerr << "Ошибка: "<< error.what() << endl;
        cin.clear();
    }
    return 0;
}