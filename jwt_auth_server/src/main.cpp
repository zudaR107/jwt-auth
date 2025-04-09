#include "Base64URL.h"
#include <iostream>

int main() {
    std::string raw = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    std::string encoded = Base64URL::encode(raw);
    std::cout << encoded << std::endl;
}
