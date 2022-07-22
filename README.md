# Async AIA chasing

This project is based on [`aia`](https://pypi.org/project/aia/), which didn't quite satisfy my requirements.
The differences are:
* This library is async ([`anyio`](https://pypi.org/project/anyio/)-based)
* Uses [`PyOpenSSL`](https://pypi.org/project/pyOpenSSL/) instead of calling `openssl` in a subprocess. In particularly, this adds the support for Mac (because `aia` uses some options for `openssl` that the Mac version of it does not support).
* Has an optional support for self-signed certificates.
* Caching is made the user's responsibility.

The package is currently not published, since it turned out that I do not need this functionality.
If someone does, and wants this package cleaned up and put on PyPI, please open an issue.
