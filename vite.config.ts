import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [tailwindcss(), react()],
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['node_modules/**', 'dist/**', '.trunk/**'],
  },
})
