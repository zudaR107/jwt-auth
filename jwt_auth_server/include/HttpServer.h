#pragma once
#include "extern/httplib.h"

class HttpServer {
public:
    static void start(int port = 8080);
};
