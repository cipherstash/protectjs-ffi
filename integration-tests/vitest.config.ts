import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Disable watch mode by default - tests will run once and exit
    watch: false,
  },
})
