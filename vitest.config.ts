import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // The DB is a shared file per process; run suites serially.
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    coverage: { provider: 'v8', include: ['src/**/*.ts'], exclude: ['src/**/__tests__/**', 'src/server.ts'] },
  },
});
