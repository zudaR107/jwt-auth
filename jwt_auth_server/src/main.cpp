#include "SHA256.h"
#include <iostream>

int main() {
    std::string input = "mypassword";
    std::string hashed = SHA256::hash(input);

    std::cout << "SHA256(\"" << input << "\") = " << hashed << "\n";
    return 0;
}
