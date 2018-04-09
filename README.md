# Header rewriting proxy

This is a little experiment in HTTP proxying and
[HSM](https://en.wikipedia.org/wiki/Hardware_security_module) access
using the [PKCS#11 API](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

## About: The experiment

The goal is to build a proxy that can rewrite a HTTP header.
The incoming header is encrypted and has the following form:

```
{"encryptedKey":"base64string","data":"base64string" }
```

The proxy will decrypt the `encryptedKey` with a HSM (using
[softhsm](https://github.com/opendnssec/SoftHSMv2) for testing) using RSA,
then use the resulting key as an AES key to decrypt the data.

Once decypted, the proxy will put the data in the original header forwarding to
the upstream service.

The two questions I'm trying to answer are:

* Can I build a header rewriting forward HTTP proxy? - ✅
* Can I integrate with a PKCS #11 compatible HSM from go for RSA decryption - ✅

## Setup

To set up for the HSM integration, you'll need to install [softhsm](https://github.com/opendnssec/SoftHSMv2)
and import the test fixture key.

### Install softhsm (OS X)

Using [Homebrew](https://brew.sh/), install softhsm with

```
$ brew install softhsm
```

You can check you were successful by running

```
$ softhsm2-util --show-slots
```

you should also have a shared library with the [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html) interface at `/urs/local/lib/softhsm/libsofthsm2.so`.

### Initialise a new token and private key

In order to store a private key in the HSM, you'll need to initialise a token

```
$ softhsm2-util --init-token --slot 0 --label "Test Token"
```

The proxy currently assumes you use `1234` as your pin (see [proxy.go](./proxy.go))

Finally, you can import the pk8 key from `crypto/fixtures` into your newly created
token

```
$ softhsm2-util --import crypto/fixtures/rsa.pk8 --no-public-key --slot 0 --label proxykey --id 01
```

## Test

Now you should be able to run tests!

```
$ make install
$ go test ./...
```

These should pass (fingers crossed 👀).

Then you can build and run the proxy with `make`. You should see output like this:

```
2018/04/09 11:30:14 Try this in an X-Hello header:
{"encryptedKey":"HYqXxVzIWhV3/ze8iapH40YUra7W4dmt3gxuZfu9WkudsXtMd6oFoFbj5RoJDHaRc7ou4LXMWquII4FQAGZXIT3GAAdRsI7+CXnAqvogpifVI34n90MXDHbyK0WCGhVbv2LfGGjXhYhvnpaISwBzEHAiXCEBCeSlrT+4YB0xIYJ3ldIkpV0q15ABHf0mHiI6Hz3rfC52s2bnXRkrxdvCmpb6eBQheIFHsSpjliWtn0PyVHIBpILLZWaW21JwZppyMKK/OPR8yWCbI5nfTdFmZJXxqSf1rX+565aZBi2kjJZKSO8u0E6z7Wm6qtEOKNXIGGa1YDdbLKKQVaGmjLmchA==","data":"o90yoFAXEFbYnn11+zGtzpfE81gXHsYZPi+zE7g7"}

2018/04/09 11:30:14 proxy listening on 3128
```

This is an example encrypted payload you can test with. You can test the running proxy with

```
curl --proxy http://localhost:3128/ -H 'X-Hello: {"encryptedKey":"HYqXxVzIWhV3/ze8iapH40YUra7W4dmt3gxuZfu9WkudsXtMd6oFoFbj5RoJDHaRc7ou4LXMWquII4FQAGZXIT3GAAdRsI7+CXnAqvogpifVI34n90MXDHbyK0WCGhVbv2LfGGjXhYhvnpaISwBzEHAiXCEBCeSlrT+4YB0xIYJ3ldIkpV0q15ABHf0mHiI6Hz3rfC52s2bnXRkrxdvCmpb6eBQheIFHsSpjliWtn0PyVHIBpILLZWaW21JwZppyMKK/OPR8yWCbI5nfTdFmZJXxqSf1rX+565aZBi2kjJZKSO8u0E6z7Wm6qtEOKNXIGGa1YDdbLKKQVaGmjLmchA==","data":"o90yoFAXEFbYnn11+zGtzpfE81gXHsYZPi+zE7g7"}' http://localhost:8080/
```

In the proxy log output, you should see:

```
GET /
> Accept-Encoding: gzip
> User-Agent: curl/7.54.0
> Accept: */*
> X-Hello: Client said: Hello world!!!
```

So what just happened? As well as the proxy, the service runs a simple logging HTTP listener for debugging on port 8080,
we made a request to it sending it an encrypted message produced using the public key corresponsing to the private key
we just imported into the softhsm. The request was made through the proxy, which pickd up the message and decrypted it
on the fly, using the HSM. 💥
