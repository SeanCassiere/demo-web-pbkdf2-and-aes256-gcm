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
    <h1 class="text-2xl font-medium [text-wrap:balance] text-red-500">🚨 Web Crypto API is not supported!</h1>
    `;
  } else {
    app.innerHTML = `
    <h1 class="text-2xl font-medium [text-wrap:balance]">🔐 PBKDF2 + AES256-GCM Stores</h1>
    `;
  }
});
