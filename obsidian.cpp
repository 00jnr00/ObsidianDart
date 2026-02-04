#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <termios.h>
#include <unistd.h>
#include <cstring>
#include <limits>
#include <vector>

namespace {
constexpr unsigned char kFileMagic[] = {'O', 'B', 'D', '1'};
constexpr size_t kSaltSize = 16;
constexpr size_t kIvSize = 16;
constexpr int kPbkdf2Iterations = 100000;
constexpr size_t kKeySize = 32;

bool isInteractiveInput() {
    return isatty(fileno(stdin));
}

std::string getOutputFilenameForDecrypt(const std::string& filename) {
    const std::string suffix = ".enc";
    if (filename.size() > suffix.size() &&
        filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return filename.substr(0, filename.size() - suffix.size());
    }
    return filename + ".dec";
}

bool deriveKey(const std::string& passphrase,
               const unsigned char* salt,
               std::vector<unsigned char>& key) {
    key.resize(kKeySize);
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(),
                          static_cast<int>(passphrase.size()),
                          salt,
                          static_cast<int>(kSaltSize),
                          kPbkdf2Iterations,
                          EVP_sha256(),
                          static_cast<int>(key.size()),
                          key.data()) != 1) {
        return false;
    }
    return true;
}
} // namespace

void hideInput() {
    struct termios oflags, nflags;
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &nflags);
}

void showInput() {
    struct termios oflags, nflags;
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &nflags);
}

// Function to handle errors
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt file
void encryptFile(const std::string& filename, const std::string& passphrase) {
    // Open file for reading
    std::ifstream inputFile(filename, std::ios::binary);
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file for reading" << std::endl;
        return;
    }

    // Open file for writing
    std::ofstream outputFile(filename + ".enc", std::ios::binary);
    if (!outputFile.is_open()) {
        std::cerr << "Error opening file for writing" << std::endl;
        return;
    }

    unsigned char salt[kSaltSize];
    unsigned char iv[kIvSize];
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        std::cerr << "Error generating salt or IV" << std::endl;
        return;
    }

    std::vector<unsigned char> key;
    if (!deriveKey(passphrase, salt, key)) {
        std::cerr << "Error deriving key" << std::endl;
        return;
    }

    // Set up AES encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        handleErrors();
    }

    outputFile.write(reinterpret_cast<const char*>(kFileMagic), sizeof(kFileMagic));
    outputFile.write(reinterpret_cast<const char*>(salt), sizeof(salt));
    outputFile.write(reinterpret_cast<const char*>(iv), sizeof(iv));

    // Read and encrypt file
    unsigned char inputBuffer[EVP_MAX_BLOCK_LENGTH];
    unsigned char outputBuffer[EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    while ((bytesRead = inputFile.read((char*)inputBuffer, EVP_MAX_BLOCK_LENGTH).gcount()) > 0) {
        int outputLength = 0;
        if (EVP_EncryptUpdate(ctx, outputBuffer, &outputLength, inputBuffer, bytesRead) != 1) {
            handleErrors();
        }
        outputFile.write((char*)outputBuffer, outputLength);
    }

    // Handle last block
    int outputLength = 0;
    if (EVP_EncryptFinal_ex(ctx, outputBuffer, &outputLength) != 1) {
        handleErrors();
    }
    outputFile.write((char*)outputBuffer, outputLength);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Close files
    inputFile.close();
    outputFile.close();

    // Delete original file
    if (std::remove(filename.c_str()) != 0) {
        std::cerr << "Error deleting original file" << std::endl;
    }
}

bool decryptFile(const std::string& filename, const std::string& passphrase) {
    std::ifstream inputFile(filename, std::ios::binary);
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file for reading" << std::endl;
        return false;
    }

    unsigned char magic[sizeof(kFileMagic)];
    unsigned char salt[kSaltSize];
    unsigned char iv[kIvSize];
    inputFile.read(reinterpret_cast<char*>(magic), sizeof(magic));
    inputFile.read(reinterpret_cast<char*>(salt), sizeof(salt));
    inputFile.read(reinterpret_cast<char*>(iv), sizeof(iv));
    if (!inputFile || std::memcmp(magic, kFileMagic, sizeof(kFileMagic)) != 0) {
        std::cerr << "Invalid file header" << std::endl;
        return false;
    }

    std::vector<unsigned char> key;
    if (!deriveKey(passphrase, salt, key)) {
        std::cerr << "Error deriving key" << std::endl;
        return false;
    }

    std::ofstream outputFile(getOutputFilenameForDecrypt(filename), std::ios::binary);
    if (!outputFile.is_open()) {
        std::cerr << "Error opening file for writing" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        handleErrors();
    }

    unsigned char inputBuffer[EVP_MAX_BLOCK_LENGTH];
    unsigned char outputBuffer[EVP_MAX_BLOCK_LENGTH];
    int bytesRead;
    while ((bytesRead = inputFile.read((char*)inputBuffer, EVP_MAX_BLOCK_LENGTH).gcount()) > 0) {
        int outputLength = 0;
        if (EVP_DecryptUpdate(ctx, outputBuffer, &outputLength, inputBuffer, bytesRead) != 1) {
            handleErrors();
        }
        outputFile.write((char*)outputBuffer, outputLength);
    }

    int outputLength = 0;
    if (EVP_DecryptFinal_ex(ctx, outputBuffer, &outputLength) != 1) {
        handleErrors();
    }
    outputFile.write((char*)outputBuffer, outputLength);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

std::string readPassphrase() {
    if (isInteractiveInput()) {
        hideInput();
    }
    std::string passphrase;
    std::cout << "Enter passphrase: ";
    std::getline(std::cin, passphrase);
    if (passphrase.empty() && std::cin) {
        std::getline(std::cin, passphrase);
    }
    if (isInteractiveInput()) {
        showInput();
        std::cout << std::endl;
    }
    return passphrase;
}

int main(int argc, char* argv[]) {
    std::string action;
    std::string filename;

    if (argc >= 3) {
        action = argv[1];
        filename = argv[2];
    } else {
        int choice;
        std::cout << "1. Encrypt file" << std::endl;
        std::cout << "2. Decrypt file" << std::endl;
        std::cout << "Enter your choice: ";
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        if (choice == 1) {
            action = "encrypt";
            filename = "passwords.wf";
        } else if (choice == 2) {
            action = "decrypt";
            filename = "passwords.wf.enc";
        } else {
            std::cerr << "Invalid choice" << std::endl;
            return 1;
        }
    }

    std::string passphrase = readPassphrase();
    if (passphrase.empty()) {
        std::cerr << "Passphrase cannot be empty" << std::endl;
        return 1;
    }

    if (action == "encrypt") {
        std::cout << "Encrypting file..." << std::endl;
        encryptFile(filename, passphrase);
    } else if (action == "decrypt") {
        std::cout << "Decrypting file..." << std::endl;
        if (decryptFile(filename, passphrase)) {
            if (std::remove(filename.c_str()) != 0) {
                std::cerr << "Error deleting encrypted file" << std::endl;
            }
        }
    } else {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <filename>" << std::endl;
        return 1;
    }

    return 0;
}
