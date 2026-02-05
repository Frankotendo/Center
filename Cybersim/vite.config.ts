import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
  },
  define: {
    // This prevents "process is not defined" error in the browser
    'process.env': {} 
  }
});
