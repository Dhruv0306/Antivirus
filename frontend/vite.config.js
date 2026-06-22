import { defineConfig, transformWithEsbuild } from 'vite';
import react from '@vitejs/plugin-react';

// F-06: Use the callback form so mode is resolved by Vite from CLI flags
export default defineConfig(({ mode }) => ({
  plugins: [
    {
      name: 'treat-js-files-as-jsx',
      async transform(code, id) {
        if (!id.match(/src\/.*\.js$/)) {
          return null;
        }
        return transformWithEsbuild(code, id, {
          loader: 'jsx',
          jsx: 'automatic',
        });
      },
    },
    react(),
  ],
  esbuild: {
    // mode is 'production' only when --mode production is used (vite build default)
    drop: mode === 'production' ? ['console', 'debugger'] : [],
  },
  server: {
    port: 5000,
    strictPort: true,
  },
  preview: {
    port: 5000,
  },
  optimizeDeps: {
    esbuildOptions: {
      loader: {
        '.js': 'jsx',
      },
    },
  },
}));
