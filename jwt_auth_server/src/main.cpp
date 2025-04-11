#include "HttpServer.h"
#include "Database.h"
#include "KeyStorage.h"

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

