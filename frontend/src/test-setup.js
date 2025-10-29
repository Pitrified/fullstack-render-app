import { expect, afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import * as matchers from '@testing-library/jest-dom/matchers';

// Extend Vitest's expect with jest-dom matchers
expect.extend(matchers);

// Cleanup after each test case
afterEach(() => {
  cleanup();
});

// Mock environment variables
import.meta.env = {
  VITE_GOOGLE_CLIENT_ID: 'test-client-id',
  VITE_API_BASE_URL: 'http://localhost:8000',
};