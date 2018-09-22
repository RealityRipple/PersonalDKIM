# PersonalDKIM
Add a DKIM header to your outgoing messages.

#### Supports
 * Thunderbird [38.0.1 - 60.*]

## Building
Simply download the contents of the repository and pack the contents (sans git data) into a .zip file. Then, rename the file to .xpi and drag into the browser.

## Download
You can grab the latest release from the [Official Web Site](//realityripple.com/Software/Mozilla-Extensions/PersonalDKIM/).

## Caveats
Unfortunately, there are currently multiple issues with PersonalDKIM's implementation.
> First off, the message body is not hashed in the case of HTML or mixed content messages (including plain-text with attachments). Additionally, the message type can not be determined in versions of Thunderbird below 52. For these messages, the body length to be hashed is set to "0". Thunderbird does not provide a fully formatted mail body during the send process.

> Secondly, many headers are not set in time for the signing process. Particularly the Date, Message-ID, and MIME headers. This means that the signed header list is limited to the To, From, and Subject entries in most cases.

> Third, replay attacks may be possible in situations where the body is not hashed, because the Date and Message-ID headers have not been set. The use of SPF is **highly** recommended to help combat this vulnerability.

> Fourth, Thunderbird does not like appending headers over a certain size, which means that 2048-bit and larger keys will not work as expected. The resulting signature is simply too long when large keys are used.

> Finally, at present, your Private Key is stored plainly in the Thunderbird config, not as a certificate. As far as I know, the certificates used for DKIM can not be imported into the Certificate Management system. Passwords are stored via Thunderbird's Password Manager, so if you're worried about security, please use a PKCS#5 or PKCS#8 encrypted key. You may also wish to use the `master password` feature.

The main thing I want to get across is that this extension is **not** secure. Do not use this extension for anything that requires cryptographic robustness, and do not reuse the Private Key for _anything_ else.

## Generating Keys
The optimal key format is a 1024-bit SHA-2 RSA key in PKCS#1 or PKCS#8. The reason is that RSA is the only standard mentioned in the DKIM specification, so it has the widest chance of being recognized by DKIM verification tools around the world. The reason for the bit-size, as is mentioned in the fourth caveat above, is simply that Thunderbird doesn't like long header data. Anything less than 1024 bits is not considered secure, and 2048 is too much, and who knows what might happen if you try to make a 1536-bit key?

The best method for generating keys is probably OpenSSL, as always. You can use PuTTYgen, but you'll have to convert the Public Key for the DNS record and export the Private Key as an OpenSSH key (PKCS rather than PuTTY's own PPK format).

The final output should always be in PEM format, not DER.

```SH
openssl genrsa -out priv.pem 1024
openssl rsa -in priv.pem -pubout -out pub.pem
```

The contents of `pub.pem` will be used in your DNS record:

```DNS
selector._domainkey.host.tld 3600 IN TXT
  "v=DKIM1; k=rsa; p=[base64 contents of pub.pem]"
```

The `selector` value will be a kind of ID to mean that this key is being used, so make sure it's something unique. You'll use this value in the PersonalDKIM options.

The `host.tld` value is your domain name, of course. It should be the same domain name as your E-Mail address uses, but there are cases when it doesn't have to be.

If you're not using an RSA key, set the `k` value to the algorithm you used for key generation.

The `p` value will be the contents of your `pub.pem` file, or at least the contents that are Base64-encoded and surrounded by the dashed PEM header and footer. Make sure no lingering new lines are retained when making your DNS record.

The contents of `priv.pem` should not be modified. This file is the one you'll select as your Private Key in the PersonalDKIM options. If you want to protect the key, convert it to a PKCS#5 or encrypted PKCS#8 key.

##### PKCS#5:
```SH
openssl rsa -des3 -in priv.pem -out spriv5.pem
```

#### PKCS#8:
```SH
openssl pkcs8 -topk8 -v2 des3 -v2prf hmacWithSHA1 -in priv.pem -out spriv8.pem
```

At present, hmacWithSHA256 is not supported.

You can generate EC or DSA keys with OpenSSL in the same manner and convert them the same way.
