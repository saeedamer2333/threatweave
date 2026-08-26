import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The NestJS API runs separately in development; proxy /api to it so the
// frontend can use same-origin relative URLs in both dev and production.
const API_TARGET = process.env.VITE_API_TARGET ?? 'http://127.0.0.1:4000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
      },
    },
  },
})
