import { z } from "zod";

export const MakeBlobSchema = z.object({
  p_hash: z.string(),
  p_hash_type: z.enum(["sha256"]),

  store: z.string(),
  store_encode_steps: z.array(z.enum(["base64", "json_stringify"])),
  store_encryption_type: z.enum(["aes_256_gcm_using_pbkdf2"]),

  pbkdf_iterations: z.number(),
});

export type MakeBlob = z.infer<typeof MakeBlobSchema>;

export const StoreSchema = z.array(z.object({ c: z.string(), s: z.string() }));
export type Store = z.infer<typeof StoreSchema>;
