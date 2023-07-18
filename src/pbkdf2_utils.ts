// 6e5 is 600,000
const ITERATIONS = 6e5;

export function stringToBytes(str: string): ArrayBuffer {
  return new Uint8Array(
    window
      .atob(str)
      .match(/[\s\S]/g)!
      .map((c) => c.charCodeAt(0))
  );
}

export function bytesToString(bytes: ArrayBuffer): string {
  let array = Array.from(new Uint8Array(bytes));
  return window.btoa(array.map((b) => String.fromCharCode(b)).join(""));
}

export async function keysFromPassword(
  salt: ArrayBuffer,
  password: string,
  iterations = ITERATIONS
) {
  let enc = new TextEncoder().encode(String(password).normalize("NFKC"));
  let basekey = await crypto.subtle.importKey("raw", enc, "PBKDF2", false, [
    "deriveBits",
  ]);

  const params = { name: "PBKDF2", hash: "SHA-512", salt, iterations };
  let keys = await crypto.subtle.deriveBits(
    params,
    basekey,
    256 /* 256bit key => 32 bytes */ + 128 /* 128bit iv => 16bytes */
  );

  let iv = new Uint8Array(keys.slice(32));

  let key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(keys.slice(0, 32)),
    { name: "AES-GCM" },
    false,
    ["decrypt", "encrypt"]
  );

  return { key: key, iv: iv };
}

interface EncryptComponents {
  password: string;
  iterations?: number;
}
export async function encrypt(
  { password, iterations = ITERATIONS }: EncryptComponents,
  plaintext: string
) {
  // let salt = new Uint8Array(32);
  let salt = crypto.getRandomValues(new Uint8Array(32));

  let aesParams = await keysFromPassword(salt, password, iterations);

  let ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: aesParams.iv },
    aesParams.key,
    new TextEncoder().encode(plaintext)
  );

  return { salt: bytesToString(salt), ciphertext: bytesToString(ciphertext) };
}

interface DecryptComponents {
  salt: string;
  iterations?: number;
  ciphertext: string;
}
export async function decrypt(
  { salt, ciphertext, iterations = ITERATIONS }: DecryptComponents,
  password: string
) {
  let aesParams = await keysFromPassword(
    stringToBytes(salt),
    password,
    iterations
  );

  let plaintext = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: aesParams.iv },
    aesParams.key,
    new Uint8Array(stringToBytes(ciphertext))
  );

  return new TextDecoder().decode(plaintext);
}
