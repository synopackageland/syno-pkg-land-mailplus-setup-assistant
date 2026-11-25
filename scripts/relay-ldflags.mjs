// Prints the -ldflags that bind the package identity and the normalized TCP
// listener policy into a test binary, exactly as `synopkgland build` does, so
// the relay lifecycle test exercises the real SDK listener.
import {readFileSync} from 'node:fs'
import {parse} from 'yaml'
import {readTCPListeners, tcpPolicyFlag} from '../node_modules/@synopackageland/cli/dist/standalone/tcp-listeners.js'

const manifest = parse(readFileSync(new URL('../dsm-package.yaml', import.meta.url), 'utf8'))
console.log([
  `-X github.com/synopackageland/syno-pkg-land-sdk/ipc.packageID=${manifest.package}`,
  ...tcpPolicyFlag({tcpListeners: readTCPListeners(manifest.tcp_listeners)}),
].join(' '))
