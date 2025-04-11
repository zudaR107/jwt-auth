#include "../include/HttpServer.h"
#include "../include/Database.h"
#include "../include/KeyStorage.h"

int main() {
    Database::init("users.db");

    RSAPublicKey pubKey;
    RSAPrivateKey privKey;
    if (!KeyStorage::loadKeys(pubKey, privKey)) {
        std::cout << "[main] Ключи не найдены, создаю заново...\n";
        RSA::generate_keys(pubKey, privKey, 256);
        KeyStorage::saveKeys(pubKey, privKey);
    }

    HttpServer::start(8080);
    return 0;
}

