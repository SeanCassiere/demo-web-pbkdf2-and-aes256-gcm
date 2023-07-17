import { encrypt, decrypt } from "./pbkdf2_utils";

// capture input form
const enc_formNode = document.querySelector("#pbkdf2-enc") as HTMLFormElement;

const enc_passwordNode = document.querySelector(
  "#pbkdf2-enc-password"
) as HTMLInputElement;
const enc_roundsNode = document.querySelector(
  "#pbkdf2-enc-rounds"
) as HTMLInputElement;
const enc_dataNode = document.querySelector(
  "#pbkdf2-enc-data"
) as HTMLTextAreaElement;
const enc_displayCipherNode = document.querySelector(
  "#pbkdf2-enc-output-data"
) as HTMLTextAreaElement;
const enc_displaySaltNode = document.querySelector(
  "#pbkdf2-enc-output-salt"
) as HTMLTextAreaElement;

// capture output form
const dec_formNode = document.querySelector("#pbkdf2-dec") as HTMLFormElement;

const dec_cipherNode = document.querySelector(
  "#pbkdf2-dec-cipher-input"
) as HTMLTextAreaElement;
const dec_saltNode = document.querySelector(
  "#pbkdf2-dec-salt-input"
) as HTMLTextAreaElement;
const dec_passwordNode = document.querySelector(
  "#pbkdf2-dec-password-input"
) as HTMLInputElement;
const dec_roundsNode = document.querySelector(
  "#pbkdf2-dec-rounds-input"
) as HTMLInputElement;
const dec_displayNode = document.querySelector(
  "#pbkdf2-dec-display"
) as HTMLTextAreaElement;

enc_formNode.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  const date = new Date();
  console.log(
    "Encryption form submitted",
    date.toDateString(),
    date.toLocaleTimeString()
  );

  const password = enc_passwordNode.value;
  const rounds = Number(enc_roundsNode.value);
  const plaintext = enc_dataNode.value;

  const encrypted = await encrypt({ password, iterations: rounds }, plaintext);

  // display output values
  enc_displayCipherNode.value = encrypted.ciphertext;
  enc_displaySaltNode.value = encrypted.salt;

  // setting up the decryption form
  dec_passwordNode.value = password;
  dec_roundsNode.value = rounds.toString();
  dec_cipherNode.value = encrypted.ciphertext;
  dec_saltNode.value = encrypted.salt;
});

dec_formNode.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  const date = new Date();
  console.log(
    "Decryption form submitted",
    date.toDateString(),
    date.toLocaleTimeString()
  );

  const password = dec_passwordNode.value;
  const rounds = Number(dec_roundsNode.value);
  const ciphertext = dec_cipherNode.value;
  const salt = dec_saltNode.value;

  try {
    const decrypted = await decrypt(
      { salt, ciphertext, iterations: rounds },
      password
    );

    dec_displayNode.value = decrypted;
  } catch (error) {
    alert("Decryption failed");
  }
});
