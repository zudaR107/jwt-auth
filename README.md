# JWT Auth Server

A native C++ implementation of a full-featured JWT authentication server with no external cryptographic libraries.  
Implements custom **RSA**, **SHA-256**, **BigInt**, and full JWT processing, including access/refresh tokens, signing, and verification.

---

## Features

- JWT authentication using RSA digital signatures (RS256)
- Access + Refresh token system
- Custom implementations of:
  - Arbitrary-precision integer arithmetic (`BigInt`)
  - Cryptographic hash function (`SHA-256`)
  - Asymmetric encryption (`RSA`)
- SQLite user database
- Token blacklist for logout handling
- CURL and Swagger-based testing
- Minimal web frontend for demonstration

---

## Project Structure

```
jwt-auth/
├── jwt_auth_server/        # C++ server source code
│   ├── include/            # Header files
│   ├── src/                # Source files
│   ├── build/              # Build artifacts (after compilation)
│   ├── Doxyfile            # Doxygen config
│   ├── CMakeList.txt       # Cmake build
│   ├── test_jwt_server.sh  # Script for testing from console
│   └── docs/               # LaTeX documentation (from Doxygen)
├── jwt_web_client/         # Minimal web frontend (HTML+JS)
│   ├── swagger/            # Swagger UI bundle + OpenAPI spec
│   ├── app.js              # Simple Web Client 
│   ├── index.html          # Main page
│   └── style.css           # Style for html
├── README.md
└── LICENSE
```

---

## Build & Run

### Requirements

- C++17 compiler
- CMake 3.10+
- SQLite3

### Build

```bash
cd jwt_auth_server
mkdir build && cd build
cmake ..
make
```

### Run the Server

```bash
./jwt_auth_server
```

Default port: `8080`

---

## Frontend (Demo UI + Swagger)

### Launch web client (port 3000)

```bash
cd jwt_web_client
python3 -m http.server 3000
```

Then open:

- http://localhost:3000 — Minimal frontend UI
- http://localhost:3000/swagger/dist — Swagger UI

---

## Testing

You can test the API via:

- `curl` — see `test_jwt_server.sh` for complete testing script
- Swagger UI — interactive documentation
- `index.html` - for testing from Web client

### Swagger token usage

- Use **access token** for: `GET /secure/data`
- Use **refresh token** for: `POST /refresh` and `POST /logout`

> Insert the raw token only — Swagger automatically adds `Bearer`.

---

## API Documentation

- Full OpenAPI 3.0 specification:  
  `jwt_web_client/swagger/openapi.yaml`

- Generate PDF docs from Doxygen:

```bash
cd jwt_auth_server
doxygen Doxyfile
cd docs/latex
make
```

---

## Routes Overview

| Method | Endpoint         | Description                          |
|--------|------------------|--------------------------------------|
| POST   | `/register`      | Register a new user                  |
| POST   | `/login`         | Log in and receive JWT tokens        |
| POST   | `/refresh`       | Refresh access token                 |
| GET    | `/secure/data`   | Access protected resource (requires access token) |
| POST   | `/logout`        | Revoke refresh token (blacklist)     |

---

## Disclaimer

This project is for **educational purposes only**.  
Cryptographic code (RSA, SHA256) is implemented from scratch and **must not** be used in production.

---

## License

MIT License

