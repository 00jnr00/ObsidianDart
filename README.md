# ObsidianDart

ObsidianDart is a minimal, command-line cryptography utility intended for the secure local storage of sensitive, text-based information such as passwords or credentials.

The program is written in C++ for Linux systems and leverages system-provided cryptographic libraries—specifically OpenSSL—to perform AES-256 encryption and decryption. By relying on pre-packaged, well-audited tooling, ObsidianDart avoids unnecessary complexity while maintaining strong cryptographic primitives.

ObsidianDart operates entirely through the terminal and encrypts or decrypts a file located in the working directory (e.g., `passwords.wf`). The file format is user-defined and may use tab- or comma-separated values, allowing the decrypted output to be easily parsed or opened in external applications.

This project is intentionally lightweight and narrowly scoped. It is not a full password manager, but rather a simple local encryption tool designed to minimize attack surface by avoiding cloud services, background daemons, or large software stacks.

ObsidianDart is open source.

## Build Notes

ObsidianDart depends on OpenSSL. On some systems, explicit linking may be required when compiling.

Example:

```bash
g++ obsidiandart.cpp -o obsidiandart -lssl -lcrypto
