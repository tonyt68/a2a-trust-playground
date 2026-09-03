import { defineConfig } from 'vitest/config';

// A pinned config, not a convenience: this repo sits under ~/dev, which is
// also the parent directory of every other project on disk, and some of
// THOSE carry their own vitest.config.* at ~/dev itself. Vitest's config
// resolution walks UP from the working directory and stops at the first
// config file it finds — without one HERE, a `vitest run` from this repo
// silently picks up a sibling project's config and its unrelated `include`
// pattern, reporting "no test files found" against a suite that is very
// much present. Scoping discovery explicitly is what makes this repo's test
// run immune to whatever exists two directories up.
export default defineConfig({
  test: {
    include: ['tests/**/*.test.js'],
  },
});
