# Header rewriting proxy

This is a little experiment in HTTP proxying and
[HSM](https://en.wikipedia.org/wiki/Hardware_security_module) access.

## The experiment

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

* Can I build a header rewriting forward HTTP proxy?
* Can I integrate with a PKCS #11 compatible HSM from go for
  RSA decryption
