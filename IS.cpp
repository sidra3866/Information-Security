#include <iostream>
#include <openssl/sha.h>
#include <cstring>
#include <string>

// Function to generate a random salt
std::string generateSalt(int size) {
    std::string saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string salt;
    
    for (int i = 0; i < size; ++i) {
        int index = rand() % saltChars.length();
        salt += saltChars[index];
    }
    
    return salt;
}

// Function to hash a password with salt using SHA-256
std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string saltedPassword = salt + password;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, saltedPassword.c_str(), saltedPassword.length());
    SHA256_Final(hash, &sha256);
    
    char hashedPassword[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sprintf(&hashedPassword[i * 2], "%02x", hash[i]);
    
    return std::string(hashedPassword);
}

int main() {
    // Get the password from the user
    std::string password;
    std::cout << "Enter your password: ";
    std::cin >> password;
    
    // Generate a random salt
    std::string salt = generateSalt(16);
    
    // Hash the password with salt
    std::string hashedPassword = hashPassword(password, salt);
    
    // Output the salt and hashed password
    std::cout << "Salt: " << salt << std::endl;
    std::cout << "Hashed Password: " << hashedPassword << std::endl;
    
    return 0;
}