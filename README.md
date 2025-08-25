# About Kakusu

Kakusu is a header-only cryptographic toolkit for C++. It may be built and used
either stand-alone with a C++17 compiler, or integrated with runtimes such as
the Busuto C++ project, and soon with Hitycho for HPX applications.

Kakusu makes use of a backend crypto toolkit that can be selected at compile
time. Cryupto backends currently includes either OpenSSL / Libressl, Wolfssl,
LibSodium, and minicrypt. Not all features may be available with every backend,
but where features are in common, the Kakusu api remains the same. This means
you can build with the crypto backend that best matches your needs, or even
change the backend being used, without having to change application code.

The decision to make Busuto the successor to ModernCLI, and the fact that
Kakusu can be compiled stand-alone with it's own implimentation of byte\_array,
is why the backported byte\_array was removed from ModernCLI. Hitycho does also
have a C++17 implimentation of byte\_array and friends, so I will likely
adapt that for Hitycho rather than the built-in one, much like was done for
Busuto.

## Dependencies

Kakusu depends on a crypto backend, such as openssl, wolfssl, minicrypt, or
sodium. It can be built entirely stand-alone, or as an extension library for
Busuto applications. Kakusu minimally requires a C++17 compiler. It may not
have any system dependencies that influence it's use, such as requiring Posix
systems, like Busuto does, so it may even compile stand-alone on MSVC.

## Distributions

Distributions of this package are provided as detached source tarballs made
from a tagged release from our public github repository or by building the dist
target. These stand-alone detached tarballs can be used to make packages for
many GNU/Linux systems, and for BSD ports. They may also be used to build and
install the software directly on a target platform.

The latest public release source tarball can be produced by an auto-generated
tarball from a tagged release in the projects public git repository at
https://github.com/dyfet/kakusu. Busuto can also be easily vendored in other
software using git modules from this public repo. I also package Busuto for
Alpine Linux. There is no reason this cannot easily be packaged for use on
other distributions where HPX is supported.

## Licensing

Busuto Copyright (C) 2025 David Sugar <tychosoft@gmail.comSug>,

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of <C-F11>MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

NOTE: As primarily a header based library where functional code residing in
headers that are either directly called or instancianted and called by user
applications, it is strongly believed any use of this library constitutes and
efffectively produces a derivitive or combined work, per the GPL, and this is
intentional. As the sole copyright holder I can also offer other forms of
commercial licensing under different tterms.

## Participation

This project is offered as free (as in freedom) software for public use and has
a public project page at https://www.github.com/dyfet/kakusu which has an issue
tracker where you can submit public bug reports and a public git repository.
Patches and merge requests may be submitted in the issue tracker or thru email.
Other details about participation may be found in CONTRIBUTING.md.

## Testing

There is a testing program for each backend. These run simple tests that will
be expanded to improve code coverage over time. The test programs are the only
build target making this library by itself, and the test programs in this
package work with the cmake ctest framework. They may also be used as simple
examples of how a given header works. There is also a **lint** target that can
be used to verify code changes.

