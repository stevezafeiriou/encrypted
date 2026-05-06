import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [tailwindcss(), react()],
  build: {
    assetsInlineLimit: 4096,
    cssCodeSplit: true,
    modulePreload: {
      resolveDependencies(_, deps) {
        return deps.filter((dep) => !dep.includes('blockchain-crypto-'))
      },
    },
    sourcemap: false,
    target: 'es2022',
    rollupOptions: {
      output: {
        assetFileNames: 'assets/[name]-[hash][extname]',
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        manualChunks(id) {
          if (id.includes('node_modules/react-router-dom')) {
            return 'router'
          }

          if (
            id.includes('node_modules/react') ||
            id.includes('node_modules/react-dom')
          ) {
            return 'react-vendor'
          }

          if (id.includes('node_modules/motion')) {
            return 'motion'
          }

          if (id.includes('node_modules/lucide-react')) {
            return 'icons'
          }

          if (id.includes('/src/lib/blockchainCrypto')) {
            return 'blockchain-crypto'
          }

          if (id.includes('node_modules/ethers')) {
            return 'wallet'
          }

          if (id.includes('node_modules/@noble')) {
            return 'noble-crypto'
          }

          if (id.includes('/src/lib/crypto')) {
            return 'local-crypto'
          }

          if (id.includes('node_modules')) {
            return 'vendor'
          }
        },
      },
    },
  },
  optimizeDeps: {
    include: [
      '@noble/hashes',
      '@noble/secp256k1',
      'lucide-react',
      'motion/react',
      'react',
      'react-dom',
      'react-router-dom',
    ],
    exclude: ['ethers'],
  },
  server: {
    hmr: {
      overlay: true,
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['node_modules/**', 'dist/**', '.trunk/**'],
  },
})
