# raw

`raw` is a modern C++ utility library that provides a clean abstraction layer over popular open-source libraries like **Boost** and **OpenSSL**, with plans to expand support for additional libraries and services.

---

## ✨ Features

- 🔐 **Cryptography**
  - SHA-256 hashing
  - RSA signature utilities (WIP)
- 🔢 **Encoding**
  - Base64 encoding/decoding
  - URL form encoding
  - Custom string transformations
- 🔗 **HTTP**
  - A flexible HTTPS client built on top of Boost.Beast and OpenSSL
  - Supports RESTful workflows
  - Includes a working Google Drive client with OAuth2 support
  - JWT wrapper class for easy signatures and header/sub data retrieval
- 🧩 **Type Utilities**
  - Type-safe conversions
  - String ↔ numeric mapping
  - Custom formatting helpers (i.e. JSON string ↔ unordered_map)

---

## 📦 Namespaces

The library is organized into the following namespaces for modularity and clarity:

- `raw::cryptography` – for hashing, signing, and other crypto tools
- `raw::encode` – for Base64, form encoding, and more
- `raw::http` – for HTTPS client functionality (currently includes Google Drive support)
- `raw::types` – for type conversion and lightweight utilities

---

## 🧱 Dependencies

- [Boost.Beast](https://www.boost.org/doc/libs/release/libs/beast/)
- [Boost.Asio](https://www.boost.org/doc/libs/release/doc/html/boost_asio.html)
- [OpenSSL](https://www.openssl.org/)
- For easy builds these should be installed. May need some tweaking.

Future versions may integrate:

- mcu templates for various chips
- and who knows what else

---

## 🚀 Getting Started

### Requirements

- C++17 or higher
- Boost (1.75+ recommended)
- OpenSSL (1.1+)

### Build Example

```bash
cmake -S . -B build
cmake --build build -j
sudo cmake --install build (optional)
