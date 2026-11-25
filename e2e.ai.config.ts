import base from './e2e.config.ts';
import { e2eAgent } from '@synopackageland/cli/e2e';

// Loaded only by e2e:ai; the default config needs no AI dependencies or key.
export default { ...base, agents: { default: e2eAgent() } };
