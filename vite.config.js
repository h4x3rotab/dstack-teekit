import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import inject from '@rollup/plugin-inject'
import { fileURLToPath, URL } from 'node:url'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Provide global Buffer and process polyfills in the browser
    {
      ...inject({
        Buffer: ['buffer', 'Buffer'],
        process: 'process',
      }),
      apply: 'build',
    },
  ],
  resolve: {
    alias: {
      buffer: 'buffer/',
      process: 'process/browser',
      util: 'util/',
      crypto: 'crypto-browserify',
      stream: 'stream-browserify',
      assert: 'assert',
      events: 'events/',
      vm: 'vm-browserify',
    },
  },
  define: {
    'process.env': {},
  },
  optimizeDeps: {
    include: ['buffer', 'process', 'util', 'crypto-browserify', 'stream-browserify', 'assert', 'events', 'vm-browserify'],
    esbuildOptions: {
      define: {
        global: 'globalThis',
      },
      inject: [
        fileURLToPath(new URL('./src/vite-buffer-shim.ts', import.meta.url)),
      ],
    },
  },
})
