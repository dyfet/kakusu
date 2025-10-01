# About Kakusu

Kakusu is a header-only cryptographic toolkit for C++. It may be built and used
either stand-alone with a C++17 compiler, or integrated with runtimes such as
the Busuto C++ project, and with Hitycho for HPX applications.

Kakusu makes use of a backend crypto toolkit that can be selected at compile
time. Cryupto backends currently includes either OpenSSL / Libressl, Wolfssl,
LibSodium, and minicrypt. Not all features may be available with every backend,
but where features are in common, the Kakusu api remains the same. This means
you can build with the crypto backend that best matches your needs, or even
change the backend being used, without having to change application code.

The decision to make Busuto the successor to ModernCLI, and the fact that
Kakusu can be compiled stand-alone with it's own implimentation of byte\_array,
is why the backported byte\_array was removed from ModernCLI. Hitycho also has
have a C++17 implimentation of byte\_array and friends.

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

This package has recently been re-licensed as Apache 2.0. It had been licensed
as GPL 3.0 prior to release 0.2.1. The net effect for all existing use cases is
the same, It can be combined with any GPL 3.0 (or later) licensed code
effectively as GPL 3.0 in a combined work, and it's use with any GPL 2.0 or
later work effectively makes the combined work GPL 3.0, just like before.

The net effect of combining this work with another Apache 2.0 licensed work of
course is a combined work on Apache 2.0 terms. While Kakusu is at the moment
entirely stand-alone, this will likely change as well as how and where one may
acquire Kakusu and how or where one might be able to receive commercial support
in the near future, but it will remain Apache licensed. The API had also been
better aligned for C++ embedded uses as of the 2.0 release.

While all other back-ends are Apache licensing compatible, the inclusion and
use of Wolfcrypt as a back-end forces any combined work or product made with
the wolfcrypt back-end to be licensed as GPL 3.0 or later as well. The GPL is
very good for end-user products, but horrible for frameworks like Kakusu
because it then imposes itself on other people's works. It is very possible the
woldcrypt back-end will be dropped from mainline headers in the future, and
perhaps appear as an optional header to prevent accidental use.

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

