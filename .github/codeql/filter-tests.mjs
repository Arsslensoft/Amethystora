// Drops CodeQL's results that lie in test code from a SARIF file, in place, before it is uploaded. Test code
// holds fixed keys, passwords and secrets on purpose, which CodeQL's queries report as if they were real.
// paths-ignore cannot do this alone: it does not reach every language, and Rust keeps its unit tests in the
// same file as the code, after `#[cfg(test)]`.
//
// node .github/codeql/filter-tests.mjs FILE.sarif

import { readFileSync, writeFileSync } from "node:fs";

// A test file or a file under a test folder, by its path from the repository's root
const TEST_PATH = [
  /(^|\/)tests?\//,
  /(^|\/)tests?\.rs$/,
  /_tests?\.rs$/,
  /(^|\/)test_[^/]*\.py$/,
  /(^|\/)test-[^/]*\.(sh|mjs|js)$/,
  /\.test\.m?js$/,
  /^apps\/vault-core\/src\/sync\/fake\.rs$/,
  /^apps\/vault-core\/src\/kemlock\/sync\/fake\.rs$/,
  /^apps\/vault-core\/src\/kemlock\/vectors\.rs$/,
];

// The line of a Rust file from which on everything is its unit tests, or none
const testsFrom = new Map();
function rustTestsFrom(path) {
  if (!testsFrom.has(path)) {
    let line = null;
    try {
      const lines = readFileSync(path, "utf8").split("\n");
      for (let i = 0; i < lines.length - 1; i++) {
        if (/^#\[cfg\(test\)\]\s*$/.test(lines[i]) && /^(pub(\(crate\))? )?mod \w+/.test(lines[i + 1])) {
          line = i + 1;
          break;
        }
      }
    } catch {}
    testsFrom.set(path, line);
  }
  return testsFrom.get(path);
}

function inTests(result) {
  const location = result.locations?.[0]?.physicalLocation;
  const path = location?.artifactLocation?.uri;
  if (!path) return false;
  if (TEST_PATH.some((re) => re.test(path))) return true;
  if (path.endsWith(".rs")) {
    const from = rustTestsFrom(path);
    return from !== null && (location.region?.startLine ?? 0) >= from;
  }
  return false;
}

const file = process.argv[2];
const sarif = JSON.parse(readFileSync(file, "utf8"));
for (const run of sarif.runs ?? []) {
  const before = run.results?.length ?? 0;
  run.results = (run.results ?? []).filter((r) => !inTests(r));
  console.log(`${file}: ${before - run.results.length} of ${before} results in test code left out`);
}
writeFileSync(file, JSON.stringify(sarif));
