import assert from 'node:assert/strict';
import { test } from '@e2e-dev/web';
import { actionFixture, assertOutcome, openFixture } from './support/action.ts';

// An action and its observable result, without a model or AI key.
// For CRUD, prepare a private fixture first and assert saved/read-back data.
// For long jobs, replace this with the bounded lifecycle in the testing guide.
test('the primary action changes the fixture outcome', async ({app, browser}) => {
  const {action, result, expected} = actionFixture();
  const root = await openFixture(app, browser);
  assert.notEqual((await root.locator(result).textContent())?.trim(), expected);
  await root.locator(action).click();
  await assertOutcome(root, result, expected);
});
