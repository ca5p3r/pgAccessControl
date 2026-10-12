import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// In development the UI runs on :5173 and proxies /api to the Python backend, so cookies stay same-origin.
// Override the backend address with VITE_API_TARGET (e.g. in frontend/.env.local).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: { "/api": env.VITE_API_TARGET || "http://localhost:8000" },
    },
    build: { outDir: "dist", sourcemap: false },
  };
});
