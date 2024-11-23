import { Config, createConfig } from '@umijs/test';

export default {
  ...createConfig(),
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  collectCoverageFrom: ['src/**/*.{ts,js,tsx,jsx}'],
} as Config.InitialOptions;
