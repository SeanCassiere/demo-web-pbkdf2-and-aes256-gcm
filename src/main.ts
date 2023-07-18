import "./index.css";

import "./maker";
import "./importer";

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
      <h1 class="text-2xl font-medium">🔐 PBKDF2 + AES256-GCM Stores</h1>
    `;
  }
});
