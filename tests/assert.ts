// Tiny assertion helper — no dependencies, so tests run under plain node.
let passed = 0;
let failed = 0;
const failures: string[] = [];

export function check(name: string, cond: boolean, extra?: unknown) {
  if (cond) {
    passed++;
  } else {
    failed++;
    failures.push(name + (extra !== undefined ? ` — ${JSON.stringify(extra)}` : ""));
  }
}

export function eq<T>(name: string, got: T, want: T) {
  check(name, got === want, { got, want });
}

export function section(title: string) {
  console.log("\n" + title);
}

export function report(): never {
  console.log(`\n${passed} checks passed, ${failed} failed`);
  if (failed) {
    console.log("\nFailures:");
    for (const f of failures) console.log("  ✗ " + f);
    process.exit(1);
  }
  process.exit(0);
}
