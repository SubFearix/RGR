CXX = g++
CXXFLAGS = -std=c++17 -fPIC -Wall -g

BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)
LIB_DIR = $(BUILD_DIR)

EXEC = $(BIN_DIR)/cipher_app

LIB_AES = $(LIB_DIR)/libaes.so
LIB_CHACHA20 = $(LIB_DIR)/libchacha20.so
LIB_RSA = $(LIB_DIR)/librsa.so

OBJ_AES = aes.o
OBJ_CHACHA20 = chacha20_main.o
OBJ_RSA = rsa_main.o
OBJ_FORFILE = forfile.o
OBJ_MAIN = main.o

.PHONY: all clean

all: $(BUILD_DIR) $(EXEC) $(LIB_AES) $(LIB_CHACHA20) $(LIB_RSA)

$(BUILD_DIR):
	mkdir -p $(BIN_DIR) $(LIB_DIR)

LDFLAGS_LIB = -shared
LDFLAGS_MAIN = -ldl -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR)

$(EXEC): $(OBJ_MAIN) $(LIB_AES) $(LIB_CHACHA20) $(LIB_RSA) $(OBJ_FORFILE)
	$(CXX) $(CXXFLAGS) $(OBJ_MAIN) $(OBJ_FORFILE) -o $@ -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) $(LDFLAGS_MAIN)

$(LIB_AES): $(OBJ_AES) $(OBJ_FORFILE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS_LIB) $(OBJ_AES) $(OBJ_FORFILE) -o $@

$(LIB_CHACHA20): $(OBJ_CHACHA20) $(OBJ_FORFILE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS_LIB) $(OBJ_CHACHA20) $(OBJ_FORFILE) -o $@

$(LIB_RSA): $(OBJ_RSA) $(OBJ_FORFILE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS_LIB) $(OBJ_RSA) $(OBJ_FORFILE) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(OBJ_MAIN) $(OBJ_AES) $(OBJ_CHACHA20) $(OBJ_RSA) $(OBJ_FORFILE)
	rm -f aes_keys#* aes_iv#* aes_encrypted#* aes_decrypted#*
	rm -f chacha20_keys#* chacha20_nonce#* chacha20_encrypted#* chacha20_decrypted#*
	rm -f rsa_keys#* rsa_encrypted#* rsa_decrypted#*
	rm -f console
