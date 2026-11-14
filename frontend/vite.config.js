import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Each entry: bypass text/html requests so React Router handles SPA navigation.
      '/register': {
        target: 'http://localhost:3001',
        bypass(req) {
          if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return '/index.html';
          }
        }
      },
      '/login': {
        target: 'http://localhost:3001',
        bypass(req) {
          if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return '/index.html';
          }
        }
      },
      '/recovery': {
        target: 'http://localhost:3001',
        bypass(req) {
          if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return '/index.html';
          }
        }
      },
      '/credentials': {
        target: 'http://localhost:3001',
        bypass(req) {
          if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return '/index.html';
          }
        }
      },
      '/profile': {
        target: 'http://localhost:3001',
        bypass(req) {
          if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return '/index.html';
          }
        }
      },
      '/health': 'http://localhost:3001'
    }
  }
});
