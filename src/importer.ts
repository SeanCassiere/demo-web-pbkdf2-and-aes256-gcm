import { decrypt } from "./pbkdf2_utils";
import { sha256 } from "./sha_256_utils";
import {
  MakeBlobSchema,
  type MakeBlob,
  StoreSchema,
  type Store,
} from "./parse";

async function decryptStore(
  store: Store,
  meta: {
    encryption_type: MakeBlob["store_encryption_type"];
    pbkdf_iterations: MakeBlob["pbkdf_iterations"];
  },
  password: string
): Promise<string> {
  switch (meta.encryption_type) {
    case "aes_256_gcm_using_pbkdf2": {
      return await decrypt(
        {
          iterations: meta.pbkdf_iterations,
          salt: store.s,
          ciphertext: store.c,
        },
        password
      );
    }
    default: {
      throw new Error(
        `"${meta.encryption_type}" store_encryption_type not supported`
      );
    }
  }
}

function storeDecode(
  step: MakeBlob["store_encode_steps"][number],
  input: any
): any {
  switch (step) {
    case "base64": {
      return window.atob(input);
    }
    case "json_stringify": {
      return JSON.parse(input);
    }
    default: {
      throw new Error(`"${step}" store_enc_step not supported`);
    }
  }
}

async function decodeStore(blob: MakeBlob) {
  let decodedStore: any = blob.store;

  for (let idx = 0; idx < blob.store_encode_steps.length; idx++) {
    const step = blob.store_encode_steps[idx];
    decodedStore = storeDecode(step, decodedStore);
  }

  const storeSchemaResult = await StoreSchema.safeParseAsync(decodedStore);

  if (storeSchemaResult.success === false) {
    throw new Error("store does not match schema");
  }

  return storeSchemaResult.data;
}

async function checkPasswords(candidatePassword: string, blob: MakeBlob) {
  switch (blob.p_hash_type) {
    case "sha256": {
      const hash = await sha256(candidatePassword);
      if (hash === blob.p_hash) {
        return;
      }
      throw new Error("password does not match");
    }
    default: {
      throw new Error("password hash type not supported");
    }
  }
}

async function rehydrateBlob(password: string, blob: string) {
  let parsedInitialBase64: object | null = null;
  try {
    parsedInitialBase64 = JSON.parse(blob);
  } catch (error) {
    throw new Error("invalid blob");
  }
  if (!parsedInitialBase64) {
    throw new Error("invalid blob");
  }

  const makeBlobSchemaResult = await MakeBlobSchema.safeParseAsync(
    parsedInitialBase64
  );

  if (makeBlobSchemaResult.success === false) {
    throw new Error("blob does not match schema");
  }
  const makeBlob = makeBlobSchemaResult.data;

  await checkPasswords(password, makeBlob);

  const decoded_store = await decodeStore(makeBlob);

  const store = await decryptStore(
    decoded_store,
    {
      encryption_type: makeBlob.store_encryption_type,
      pbkdf_iterations: makeBlob.pbkdf_iterations,
    },
    password
  );

  return store;
}

// related to the actual import form
const resultNodeParent = document.querySelector(
  "#import-result-parent"
) as HTMLDivElement;
const resultNode = document.querySelector("#import-result") as HTMLPreElement;
const resultTimeNode = document.querySelector(
  "#import-result-time"
) as HTMLSpanElement;

const form = document.querySelector("#import-form") as HTMLFormElement;
const submitButton = document.querySelector(
  "#import-submit"
) as HTMLButtonElement;

form.addEventListener("submit", async (evt) => {
  evt.preventDefault();
  submitButton.disabled = true;
  resultNodeParent.style.display = "hidden";

  const password = form.password.value;
  const blob = form.blob.value;

  try {
    const startTime = new Date();

    const result = await rehydrateBlob(password, blob);

    const endTime = new Date();
    const timeDiff = endTime.getTime() - startTime.getTime();
    const seconds = timeDiff / 1000;
    console.log(`Decryption took ${seconds} seconds`);

    resultNode.textContent = JSON.stringify(result, null, 2);
    resultTimeNode.textContent = `${seconds.toString()} seconds`;
    resultNodeParent.style.display = "block";
  } catch (error) {
    if (error instanceof Error) {
      alert("Error: " + error.message);
    } else {
      alert("Unknown error occurred, check the console.");
      console.error("Error", error);
    }
  }
  submitButton.disabled = false;
});
