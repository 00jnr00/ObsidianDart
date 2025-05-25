#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <termios.h>
#include <unistd.h>

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
void encryptFile(const std::string& filename, const unsigned char* key) {
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

    // Set up AES encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        handleErrors();
    }

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

// Function to decrypt file
void decryptFile(const std::string& filename, const unsigned char* key) {
    // Open file for reading
    std::ifstream inputFile(filename, std::ios::binary);
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file for reading" << std::endl;
        return;
    }

    // Open file for writing
    std::ofstream outputFile(filename.substr(0, filename.size() - 4), std::ios::binary);
    if (!outputFile.is_open()) {
        std::cerr << "Error opening file for writing" << std::endl;
        return;
    }

    // Set up AES decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        handleErrors();
    }

    // Read and decrypt file
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

    // Handle last block
    int outputLength = 0;
    if (EVP_DecryptFinal_ex(ctx, outputBuffer, &outputLength) != 1) {
        handleErrors();
    }
    outputFile.write((char*)outputBuffer, outputLength);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Close files
    inputFile.close();
    outputFile.close();
}

int main() {
    hideInput();
    // Get encryption key from user
    unsigned char key[32];
    std::cout << "Enter 32-character encryption key: ";
    std::cin >> (char*)key;
    showInput();
    std::cout << std::endl; // Add this line to print a newline
    int choice;
    std::cout << "1. Encrypt file" << std::endl;
    std::cout << "2. Decrypt file" << std::endl;
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    switch (choice) {
        case 1:
            // Encrypt file
            std::cout << "Encrypting file..." << std::endl;
            encryptFile("passwords.wf", key);
            break;
        case 2:
            // Decrypt file
            std::cout << "Decrypting file..." << std::endl;
            decryptFile("passwords.wf.enc", key);
            // Delete encrypted file
            if (std::remove("passwords.wf.enc") != 0) {
                std::cerr << "Error deleting encrypted file" << std::endl;
            }
            break;
        default:
            std::cerr << "Invalid choice" << std::endl;
            break;
    }

    return 0;
}
