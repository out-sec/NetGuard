# Development Guide

This guide provides a comprehensive overview of the NetGuard codebase and instructions for setting up a development environment to contribute to the project.

## Codebase Overview
NetGuard is a modular C++-based Network Intrusion Detection System (NIDS) that processes network packets and applies rule-based detection. The system is designed to parse and analyze network traffic using custom parsing logic implemented in C++, without relying on external packet capture libraries.

- **config/**: Manages network interface settings or input sources.
- **docs/**: Contains project documentation.
- **include/**: Header files defining interfaces, parsing functions etc.

- **rules/**: Defines detection rules.
- **src/**: Source files implementing the logic.

- **tests/**: Unit and integration tests.

### Key Components
- **Main Workflow**: `main.cpp` initializes the system, reads configurations from `config/interface.cfg`, sets up packet processing, and coordinates parsing and rule application.
- **Packet Parsing**: The `parsing/` directory handles protocol-specific parsing, extracting fields for rule evaluation.
- **Rule Processing**: The `rules/` directory defines detection logic, applied to parsed packets to identify threats.
- **Utilities**: The `utils/` directory provides helper functions, such as Ethernet frame decoding and byte manipulation.

### Assumptions
- NetGuard handles packet capture internally, possibly using raw sockets or reading from files, without external libraries.
- The system is primarily developed for Unix-like environments but may be portable to Windows.

## Development Setup
### Prerequisites
- **Operating System**: Linux (recommended)
- **Compiler**: GCC 9+, Clang 10+, or MSVC 2019+ with C++17 support.
- **CMake**: Version 3.14+.
- **Git**: For version control.

### Setup Instructions
1. **Clone the Repository**:
   ```
   git clone https://github.com/out-sec/NetGuard.git
   cd NetGuard
   ```
2. **Install Dependencies**:
   - On Ubuntu:
     ```
     sudo apt-get install cmake g++
     ```

3. **Build the Project**:
   ```
   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make -j$(nproc)
   ```
4. **Run the Application**:
   ```
   ./netguard
   ```
   Note: Depending on configuration, certain operations (e.g., accessing network interfaces) may require elevated privileges.

### Running Tests
- Unit tests are located in `tests/`. Build and run tests with:
  ```
  cd build
  ctest
  ```
- If no tests exist, consider adding a testing framework like Google Test (`gtest`) for unit and integration testing.

## Coding Standards
- **Language**: Use C++17 features where appropriate.
- **Style**: Follow the Google C++ Style Guide:
  - 2-space indentation
  - Clear, descriptive function and variable names (e.g., `parseEthernetFrame`, `httpRules`)
  - Use block comments for complex logic; avoid inline comments
- **Documentation**: Add Doxygen-compatible comments to all functions and classes in header files.
- **Error Handling**: Use exceptions or error codes consistently, logging errors to `stderr` or a log file.
- **Modularity**: Keep components loosely coupled (e.g., parsers should not depend on specific rule implementations).

## Adding New Protocols
To add support for a new protocol (e.g., DNS):
1. Create a new header in `include/parsing/` (e.g., `dns.h`) defining the parser interface.
2. Implement the parser in `src/parsing/` (e.g., `dns.cpp`).
3. Update `main.cpp` to integrate the new parser.
4. Add corresponding rules in `rules/protocols/` (e.g., `dns.rules`).
5. Document the parser in `docs/parser_development.md`.

## Known Limitations
- Limited protocol support (Ethernet, IP, TCP, UDP, ICMP, HTTP).
- No automated tests currently included.
- No CI/CD pipeline for automated builds and testing.

## Future Improvements
- Add support for additional protocols (see checklist in `README.md`).
- Implement a logging system for detected intrusions.
- Develop a configuration UI or CLI for rule and interface management.
- Set up a CI/CD pipeline using GitHub Actions.

## Resources
- [CMake Documentation](https://cmake.org/documentation/)
- [C++ Reference](https://en.cppreference.com/w/)
- [Project Design](docs/design.md)

For questions, open an issue on [GitHub](https://github.com/out-sec/NetGuard/issues) or contact the maintainers at [contact@out-sec.org](mailto:contact@out-sec.org).