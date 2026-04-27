import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "aes-file-encryptor": resolve(__dirname, "../aes-file-encryptor/src/index.ts"),
    },
  },
});
