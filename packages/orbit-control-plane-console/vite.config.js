import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1": "http://127.0.0.1:8432",
      "/health": "http://127.0.0.1:8432",
    },
  },
  preview: { host: "127.0.0.1", port: 4174 },
});

