import assert from 'node:assert/strict';
import { setTimeout } from 'node:timers/promises';
import { openApp, openPortal, readSmokeEntry, signIn } from '@synopackageland/cli/e2e';

// Configure an authorized fixture action with a known, initially different result.
export function actionFixture() {
  const action = process.env.APP_TEST_ACTION;
  const result = process.env.APP_TEST_RESULT;
  const expected = process.env.APP_TEST_EXPECTED;
  assert.ok(action && result && expected, 'Set APP_TEST_ACTION, APP_TEST_RESULT and APP_TEST_EXPECTED');
  return {action, result, expected};
}

export async function openFixture(app: Parameters<typeof signIn>[0], browser: NonNullable<Parameters<typeof openApp>[3]>) {
  const entry = readSmokeEntry({entry: process.env.APP_TEST_ENTRY});
  await signIn(app);
  return entry.window ? openApp(app, entry.appId, 30_000, browser) : openPortal(app, entry.entry, browser);
}

type Root = Awaited<ReturnType<typeof openFixture>>;
export async function assertOutcome(root: Root, result: string, expected: string) {
  const deadline = Date.now() + 10_000;
  let actual;
  do {
    actual = (await root.locator(result).textContent({timeout: 1000}))?.trim();
    if (actual === expected) break;
    await setTimeout(100);
  } while (Date.now() < deadline);
  assert.equal(actual, expected, 'the primary action changed its real outcome');
}
