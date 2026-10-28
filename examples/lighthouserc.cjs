module.exports = {
  ci: {
    collect: { numberOfRuns: 3, settings: { chromeFlags: '--no-sandbox' } },
    assert: {
      assertions: {
        'categories:performance': ['error', { minScore: 0.85 }],
        'categories:accessibility': ['error', { minScore: 0.95 }],
        'categories:best-practices': ['error', { minScore: 0.90 }],
        'categories:seo': ['error', { minScore: 0.90 }],
      },
    },
    upload: { target: 'filesystem', outputDir: '.quality-results/lighthouse' },
  },
};
