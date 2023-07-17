import "./index.css";

import "./sha_256_form";
import "./pbkdf2_enc";
import { test_encryption } from "./encryption_test";

const app = document.querySelector("#app");

if (!app) {
  throw new Error("#app not found");
}

document.addEventListener("DOMContentLoaded", () => {
  if (!window.crypto) {
    app.innerHTML += `
    <p class="text-red-500">Web Crypto API not supported</p>
    `;
  } else {
    app.innerHTML = `
      <h1 class="text-2xl font-medium">Web Crypto Tests 🔐</h1>
    `;
  }

  test_encryption();
});
