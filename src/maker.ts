import { encrypt } from "./pbkdf2_utils";
import { sha256 } from "./sha_256_utils";

// related to the parent store
type StoreItem = { c: string; s: string };
const storeParentNode = document.querySelector(
  "#maker-store-parent"
) as HTMLDivElement;
const storeNode = document.querySelector("#maker-store") as HTMLPreElement;
let storeParent: StoreItem[] = [];

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

function writeOutputToDOM(obj: {
  p_hash: string;
  p_hash_enc_type: "sha256";

  store: string;
  store_enc_steps: (
    | "base64"
    | "json_stringify"
    | "aes_256_gcm_using_pbkdf2"
    | "none"
  )[];

  pbkdf_iterations: number;
}) {
  outputNode.innerHTML = btoa(JSON.stringify(obj));
  return;
}

const defaultOutputValue: Omit<
  Parameters<typeof writeOutputToDOM>[0],
  "store"
> = {
  p_hash: "",
  p_hash_enc_type: "sha256",
  pbkdf_iterations: 6e6,
  store_enc_steps: ["base64", "json_stringify"],
};
// write to dom on startup
document.addEventListener("DOMContentLoaded", () => {
  const cryptoInWindow = "crypto" in window;

  if (!cryptoInWindow) {
    alert("Crypto is not in window");
    return;
  }

  writeStoreToDOM();
  writeOutputToDOM({
    ...defaultOutputValue,
    store: btoa(JSON.stringify(storeParent)),
  });
});

// related to the maker form
const form = document.querySelector("#maker-form") as HTMLFormElement;
const passwordNode = document.querySelector(
  "#maker-password"
) as HTMLInputElement;
const iterationsNode = document.querySelector(
  "#maker-iterations"
) as HTMLInputElement;

form.addEventListener("submit", async (evt) => {
  evt.preventDefault();

  const password = form.password.value;
  const iterations = parseInt(form.iterations.value) ?? 1e6;
  const plaintext = form.plaintext.value;

  passwordNode.disabled = true;
  iterationsNode.disabled = true;

  const passwordHash = await sha256(password);
  const encrypted = await encrypt({ password, iterations }, plaintext);

  storeParent.push({ c: encrypted.ciphertext, s: encrypted.salt });

  storeParentNode.style.display = "block";
  outputParentNode.style.display = "block";

  writeStoreToDOM();
  writeOutputToDOM({
    p_hash: passwordHash,
    p_hash_enc_type: "sha256",
    pbkdf_iterations: iterations,
    store: btoa(JSON.stringify(storeParent)),
    store_enc_steps: ["base64", "json_stringify", "aes_256_gcm_using_pbkdf2"],
  });
});

form.addEventListener("reset", () => {
  passwordNode.disabled = false;
  iterationsNode.disabled = false;

  storeParent = [];

  writeStoreToDOM();
  writeOutputToDOM({
    ...defaultOutputValue,
    store: btoa(JSON.stringify(storeParent)),
  });

  storeParentNode.style.display = "none";
  outputParentNode.style.display = "none";
});
