const sha256Form = document.querySelector(
  "#sha256-hasher"
) as HTMLFormElement | null;

const formInput = document.querySelector(
  "#sha256-input"
) as HTMLInputElement | null;

const formOutput = document.querySelector(
  "#sha256-output"
) as HTMLInputElement | null;

if (!sha256Form || !formInput || !formOutput) {
  throw new Error("#sha256-hasher, #sha256-input, #sha256-output not found");
}

// function that takes a string and returns a sha256 hash
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
async function sha256(message: string) {
  const msgUint8 = new TextEncoder().encode(message); // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8); // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(""); // convert bytes to hex string
  return hashHex;
}

sha256Form.addEventListener("submit", async (evt) => {
  evt.preventDefault();

  const input = formInput.value;
  const hashed = await sha256(input);
  formOutput.value = hashed;
});
