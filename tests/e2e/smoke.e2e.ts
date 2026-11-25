import { appOpenSmoke } from '@synopackageland/cli/e2e';

// Keep a marker that appears only after your App has loaded its content.
// For a wrapped upstream, replace ready with its own selector or {text: '…'}.
appOpenSmoke({ ready: '[data-app-status], .dsmapp-facts dd, .binary-app, [data-app-ready]' });
