import { encrypt } from "./pbkdf2_utils";
import { sha256 } from "./sha_256_utils";
import type { MakeBlob, Store } from "./parse";

// related to the parent store
const storeParentNode = document.querySelector(
  "#maker-store-parent"
) as HTMLDivElement;
const storeNode = document.querySelector("#maker-store") as HTMLPreElement;
let storeParent: Store | null = null;

function writeStoreToDOM() {
  storeNode.innerHTML = JSON.stringify(storeParent, null, 2);
  return;
}

// related to the parent output
const outputParentNode = document.querySelector(
  "#maker-output-parent"
) as HTMLDivElement;
const outputNode = document.querySelector("#maker-output") as HTMLPreElement;
const outputCopyNode = document.querySelector(
  "#maker-output-copy"
) as HTMLButtonElement;

outputCopyNode.addEventListener("click", () => {
  navigator.clipboard.writeText(outputNode.innerHTML);
});

function writeOutputToDOM(obj: MakeBlob) {
  outputNode.innerHTML = btoa(JSON.stringify(obj));
  return;
}

// raw store
const rawStoreParentNode = document.querySelector(
  "#maker-raw-store-parent"
) as HTMLDivElement;
const rawStoreNode = document.querySelector(
  "#maker-raw-store"
) as HTMLPreElement;
const rawStoreCounterNode = document.querySelector(
  "#maker-raw-store-counter"
) as HTMLSpanElement;
let rawStore: string = "";

function writeRawStoreToDOM() {
  rawStoreNode.innerHTML = JSON.stringify(rawStore, null, 2);
  rawStoreCounterNode.innerHTML = `${rawStore.length.toString()} items`;
  return;
}

const defaultOutputValue: Omit<MakeBlob, "store"> = {
  p_hash: "",
  p_hash_type: "sha256",
  pbkdf_iterations: 6e6,
  store_encode_steps: ["base64", "json_stringify"],
  store_encryption_type: "aes_256_gcm_using_pbkdf2",
};
// write to dom on startup
document.addEventListener("DOMContentLoaded", () => {
  const cryptoInWindow = "crypto" in window;

  if (!cryptoInWindow) {
    alert("Crypto is not in window");
    return;
  }

  writeStoreToDOM();
  writeRawStoreToDOM();
  writeOutputToDOM({
    ...defaultOutputValue,
    store: btoa(JSON.stringify(storeParent)),
  });
});

// related to the maker form
const form = document.querySelector("#maker-form") as HTMLFormElement;
const submitButtonNode = document.querySelector(
  "#maker-submit"
) as HTMLButtonElement;
const passwordNode = document.querySelector(
  "#maker-password"
) as HTMLInputElement;
const passwordCopyNode = document.querySelector(
  "#maker-password-copy"
) as HTMLButtonElement;
passwordCopyNode.addEventListener("click", () => {
  navigator.clipboard.writeText(passwordNode.value);
});

form.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  submitButtonNode.disabled = true;

  const password = form.password.value;
  const iterations = parseInt(form.iterations.value) ?? 1e6;
  const plaintext = form.plaintext.value;

  const passwordHash = await sha256(password);
  const encrypted = await encrypt({ password, iterations }, plaintext);

  rawStore = plaintext;
  storeParent = { c: encrypted.ciphertext, s: encrypted.salt };

  rawStoreParentNode.style.display = "block";
  storeParentNode.style.display = "block";
  outputParentNode.style.display = "block";

  writeStoreToDOM();
  writeRawStoreToDOM();
  writeOutputToDOM({
    p_hash: passwordHash,
    p_hash_type: "sha256",
    pbkdf_iterations: iterations,
    store: btoa(JSON.stringify(storeParent)),
    store_encode_steps: ["base64", "json_stringify"],
    store_encryption_type: "aes_256_gcm_using_pbkdf2",
  });
  submitButtonNode.disabled = false;
});

form.addEventListener("reset", () => {
  storeParent = null;
  rawStore = "";

  writeStoreToDOM();
  writeOutputToDOM({
    ...defaultOutputValue,
    store: btoa(JSON.stringify(storeParent)),
  });

  storeParentNode.style.display = "none";
  rawStoreParentNode.style.display = "none";
  outputParentNode.style.display = "none";
});
