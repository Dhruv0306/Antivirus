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
        // Drop console/debugger only in production builds
        drop: mode === 'production' ? ['console', 'debugger'] : [],
    },
    server: {
        port: 5000,
        strictPort: true,
        host: true, // bind to 0.0.0.0 so the dev server is reachable via LAN IP
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
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/setupTests.js'],
        css: false,
    },
}));
