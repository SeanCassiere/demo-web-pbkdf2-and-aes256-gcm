export const deriveKeyAndIv = async (
  password: BufferSource,
  salt: BufferSource,
  iterations = 100000
) => {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    password,
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const keyLength = 32;
  const ivLength = 16;
  const numBits = (keyLength + ivLength) * 8;
  const derivedBytes = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-512",
      salt,
      iterations,
    },
    passwordKey,
    numBits
  );
  const key = await crypto.subtle.importKey(
    "raw",
    derivedBytes.slice(0, keyLength),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
  const iv = derivedBytes.slice(keyLength, keyLength + ivLength);
  return {
    key,
    iv,
  };
};

export const encrypt = async (
  password: BufferSource,
  salt: BufferSource,
  plainText: BufferSource
) => {
  const { key, iv } = await deriveKeyAndIv(password, salt);
  return crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    plainText
  );
};

export const decrypt = async (
  password: BufferSource,
  salt: BufferSource,
  cipher: BufferSource
) => {
  const { key, iv } = await deriveKeyAndIv(password, salt);
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    cipher
  );
};

export const utf8ToUint8Array = (input: string) =>
  new TextEncoder().encode(String(input).normalize("NFKC"));

export const arrayBufferToUtf8 = (input: ArrayBuffer) =>
  new TextDecoder().decode(new Uint8Array(input));

export const arrayBufferToHex = (input: ArrayBuffer) => {
  const newInput = new Uint8Array(input);
  const output = [];
  for (let i = 0; i < newInput.length; ++i) {
    output.push(newInput[i].toString(16).padStart(2, "0"));
  }
  return output.join("");
};
