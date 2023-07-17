import "./index.css";

import "./sha_256_form";

const app = document.querySelector("#app");

if (!app) {
  throw new Error("#app not found");
}

document.addEventListener("DOMContentLoaded", () => {
  app.innerHTML = `
    <h1 class="text-2xl font-medium">Web Crypto Tests 🔐</h1>
  `;
});
