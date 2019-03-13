# SmtpAuth

This is a library which implements SMTP Service Extension for
Authentication [RFC 4954](https://tools.ietf.org/html/rfc4954).

## Usage

The `SmtpAuth::Client` class implements the `Smtp::Client::Extension` interface
in order to extend the SMTP client to support authentication using Simple
Authentication and Security Layer (SASL), which is defined in [RFC
4422](https://tools.ietf.org/html/rfc4422).

## Supported platforms / recommended toolchains

This is a portable C++11 application which depends only on the C++11 compiler,
the C and C++ standard libraries, and other C++11 libraries with similar
dependencies, so it should be supported on almost any platform.  The following
are recommended toolchains for popular platforms.

* Windows -- [Visual Studio](https://www.visualstudio.com/) (Microsoft Visual
  C++)
* Linux -- clang or gcc
* MacOS -- Xcode (clang)

## Building

This library is not intended to stand alone.  It is intended to be included in
a larger solution which uses [CMake](https://cmake.org/) to generate the build
system and build applications which will link with the library.

There are two distinct steps in the build process:

1. Generation of the build system, using CMake
2. Compiling, linking, etc., using CMake-compatible toolchain

### Prerequisites

* [Base64](https://github.com/rhymu8354/Base64.git) - a library which
  implements encoding and decoding data using the Base64 algorithm, which
  is defined in [RFC 4648](https://tools.ietf.org/html/rfc4648).
* [CMake](https://cmake.org/) version 3.8 or newer
* C++11 toolchain compatible with CMake for your development platform (e.g.
  [Visual Studio](https://www.visualstudio.com/) on Windows)
* [Sasl](https://github.com/rhymu8354/Sasl.git) - a library which implements
  the Simple Authentication and Security Layer protocol.
* [Smtp](https://github.com/rhymu8354/Smtp.git) - a library which implements
  the Simple Mail Transport Protocol.
* [SystemAbstractions](https://github.com/rhymu8354/SystemAbstractions.git) - a
  cross-platform adapter library for system services whose APIs vary from one
  operating system to another

### Build system generation

Generate the build system using [CMake](https://cmake.org/) from the solution
root.  For example:

```bash
mkdir build
cd build
cmake -G "Visual Studio 15 2017" -A "x64" ..
```

### Compiling, linking, et cetera

Either use [CMake](https://cmake.org/) or your toolchain's IDE to build.
For [CMake](https://cmake.org/):

```bash
cd build
cmake --build . --config Release
```
