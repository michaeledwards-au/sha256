# sha256

So, I didn't want to call the SubtleCrypto API digest function asynchronously for my own reasons, so I implemented a synchronous digester myself from the SHA-256 specs.

Just vanilla JS here, and I have tested it in the browser, Deno and NodeJs. Not thoroughly, but have tested enough test vectors to satisfy myself that it is operating correctly.

I have optimised as best as I can, made someone else can make it better.

I have commented the crap out of it, I don't usually comment code and instead use better variable naming and smaller functions with appropriate naming. But because speed is important with stuff like this, I went big.

## Syntax

```
digest_sha256(data);
```

### Parameters

```data```

This is a ```Uint8Array``` object containing the data to be digested.

### Return value

Not a promise, a ```Uint8Array``` object containing the digest;

## Example

This example encodes a message, then calulates its SHA-256 digest, then logs the digest as a hex string.

```
const data = (new TextEncoder()).encode("i really dont like promises");
const digest = digest_sha256(data);

const hex = digest.reduce(function (hex, byte) { return hex+(byte<0x10?"0":"")+byte.toString(16); }, "");
console.log(hex);

// OUTPUT:
// 34ac58cafae9456c6e66fbe68bcef8da7a40624b8795896a26e1db37a65e919f
```


