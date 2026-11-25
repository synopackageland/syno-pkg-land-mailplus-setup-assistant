import assert from 'node:assert/strict';
import { test } from '@e2e-dev/web';
import { actionFixture, assertOutcome, openFixture } from './support/action.ts';

// Opt-in semantic step; keep the final result assertion deterministic.
test('an AI step performs the authorized fixture action', async ({app, browser, agent}) => {
  const {result, expected} = actionFixture();
  const instruction = process.env.APP_TEST_AI_ACTION;
  assert.ok(instruction, 'Set APP_TEST_AI_ACTION to one bounded authorized fixture action');
  const root = await openFixture(app, browser);
  assert.notEqual((await root.locator(result).textContent())?.trim(), expected);
  await agent.act(instruction);
  await assertOutcome(root, result, expected);
});
