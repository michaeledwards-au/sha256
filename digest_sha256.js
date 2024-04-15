
function digest_sha256(data) {

  // intialise round constants  
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,   
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // reset hash values
  var h = [ 
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,     
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  
  // length in bits of original data respresented as big endian 64-bits long integer stored in 
  // an 8-bit array (bytes * 8 then split into big endian bytes)
  const L = new Uint8Array([
    (data.length/0x20000000000000)&0xff,
    (data.length/0x200000000000)&0xff,
    (data.length/0x2000000000)&0xff,
    (data.length/0x20000000)&0xff,
    (data.length>>>21)&0xff,
    (data.length>>>13)&0xff,
    (data.length>>>5)&0xff,
    (data.length<<3)&0xff
  ]);
  
  // padding needed to fit 512-bit (64 byte) chunk sizing such that the length of (data + 
  // 0x80 + K + L) is a multiple of 512-bits (64 bytes)
  const K = new Uint8Array(64-((data.length+9)%64));
    
  // apply padding to data
  const padded = new Uint8Array([...data, 0x80, ...K, ...L]);
    
  // split data into 512-bit (64 byte) chunks
  const chunks = []; 
    
  for (var i = 0; i<padded.length; i+=64) {
    chunks.push(new Uint8Array([...(padded.slice(i, i+64))]));
  }
    
  // compress each chunk
  chunks.forEach(function (chunk) {
      
    // initial a chunk 32-bit word schedule
    const w = new Uint32Array(64);
    
    // copy chunk into first 16 32-bit words of schedule
    for (var i = 0; i<64; i+=4) {
      w[i>>2] = (chunk[i]<<24)^(chunk[i+1]<<16)^(chunk[i+2]<<8)^chunk[i+3];
    }
    
    // expand chunk to fill remainder of schedule
    for (var i = 16; i<64; i++) {
      const s0w = w[i-15];
      const s1w = w[i-2];
      const s0 = ((s0w>>>7)|(s0w<<25))^((s0w>>>18)|(s0w<<14))^(s0w>>>3);
      const s1 = ((s1w>>>17)|(s1w<<15))^((s1w>>>19)|(s1w<<13))^(s1w>>>10);
      w[i] = (w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    
    // initialise chunk hashes
    var c = [...h];
    
    // perform 64 rounds of compression on chunk hashes
    for (var i = 0; i<64; i++) {
      
      // calculate a round of compression on chunk hashes
      const c1 = c[4];
      const s1 = ((c1>>>6)|(c1<<26))^((c1>>>11)|(c1<<21))^((c1>>>25)|(c1<<7));
      const ch = (c1&c[5])^((~c1)&c[6]);
      const t1 = (c[7]+s1+ch+k[i]+w[i])>>>0;
      const c0 = c[0];
      const s0 = ((c0>>>2)|(c0<<30))^((c0>>>13)|(c0<<19))^((c0>>>22)|(c0<<10));
      const mj = (c0&c[1])^(c0&c[2])^(c[1]&c[2]);
      const t2 = (s0+mj)>>>0;
  
      // update chunk hashes for round
      c = [ (t1+t2)>>>0, c0, c[1], c[2], (c[3]+t1)>>>0, c1, c[5], c[6] ];  
    }
    
    // update hashes with compressed chunk hashes
    h = [ h[0]+c[0], h[1]+c[1], h[2]+c[2], h[3]+c[3], h[4]+c[4], h[5]+c[5], h[6]+c[6], h[7]+c[7], ]; 
  });

  // concatenate final hash values into digest split into 8-bit array
  return new Uint8Array([
    h[0]>>>24, h[0]>>>16&0xff, h[0]>>>8&0xff, h[0]&0xff,
    h[1]>>>24, h[1]>>>16&0xff, h[1]>>>8&0xff, h[1]&0xff,
    h[2]>>>24, h[2]>>>16&0xff, h[2]>>>8&0xff, h[2]&0xff,
    h[3]>>>24, h[3]>>>16&0xff, h[3]>>>8&0xff, h[3]&0xff,
    h[4]>>>24, h[4]>>>16&0xff, h[4]>>>8&0xff, h[4]&0xff,
    h[5]>>>24, h[5]>>>16&0xff, h[5]>>>8&0xff, h[5]&0xff,
    h[6]>>>24, h[6]>>>16&0xff, h[6]>>>8&0xff, h[6]&0xff,
    h[7]>>>24, h[7]>>>16&0xff, h[7]>>>8&0xff, h[7]&0xff,
  ]);
}
