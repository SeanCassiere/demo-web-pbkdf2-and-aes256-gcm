// 6e5 is 600,000
const ITERATIONS = 6e5;

async function keysFromPassword(
  salt: ArrayBuffer,
  password: string,
  iterations = ITERATIONS
) {
  let enc = new TextEncoder().encode(password);
  let basekey = await crypto.subtle.importKey("raw", enc, "PBKDF2", false, [
    "deriveBits",
  ]);

  let keys = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-512",
      salt: salt,
      iterations,
    },
    basekey,
    256 /* key */ + 128 /* iv */
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
async function encrypt(
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
async function decrypt(
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

function bytesToString(bytes: ArrayBuffer): string {
  let array = Array.from(new Uint8Array(bytes));
  return window.btoa(array.map((b) => String.fromCharCode(b)).join(""));
}

function stringToBytes(str: string): ArrayBuffer {
  return new Uint8Array(
    window
      .atob(str)
      .match(/[\s\S]/g)!
      .map((c) => c.charCodeAt(0))
  );
}

async function runProcess(
  { password, plaintext }: { password: string; plaintext: string },
  count: number,
  iterations: number = ITERATIONS
): Promise<void> {
  console.log(`${count}. iterations:`, iterations);
  console.log(`${count}. blob at start\n`, { plaintext });

  const encrypted = await encrypt({ password, iterations }, plaintext);
  console.log(`${count}. encrypted\n`, encrypted);

  try {
    let decrypted = await decrypt(
      { salt: encrypted.salt, ciphertext: encrypted.ciphertext, iterations },
      password
    );

    if (decrypted !== plaintext) {
      alert(`${count}. encrypt() failed`);
    }

    console.log(`${count}. decrypted\n`, { plaintext: decrypted });
  } catch (error) {
    console.error(`${count}. error\n`, error);
  }
  console.log("\n\n---\n\n");
}

export async function test_encryption(): Promise<void> {
  let password = "password";

  await runProcess(
    {
      password,
      plaintext: JSON.stringify({ foo: "bar" }),
    },
    1
  );

  await runProcess(
    {
      password,
      plaintext: JSON.stringify({ foo: "bar" }),
    },
    2,
    1e5
  );

  await runProcess(
    {
      password,
      plaintext: JSON.stringify({ foo: "bar", baz: "gee" }),
    },
    3
  );
}
