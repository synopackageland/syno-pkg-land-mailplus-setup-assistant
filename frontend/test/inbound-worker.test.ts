// @vitest-environment node
// The inbound Email Worker (backend/internal/mail/cloudflare/inbound-worker.mjs)
// against a scripted SMTP peer: what Cloudflare would see for each outcome.
import {expect, test} from 'vitest'
// @ts-expect-error plain ES module without types, embedded by the Go client
import worker from '../../backend/internal/mail/cloudflare/inbound-worker.mjs'

function peer(replies: (string | null)[]) {
 const enc = new TextEncoder(), queue = [replies.shift()], sent: string[] = []
 let wake: (() => void) | undefined
 const readable = new ReadableStream<Uint8Array>({
  async pull(c) {
   while(queue.length === 0) await new Promise<void>(r => {wake = r})
   const next = queue.shift()
   if(next === null || next === undefined) c.close(); else c.enqueue(enc.encode(next))
  },
 })
 const writable = new WritableStream<Uint8Array>({write(chunk) {sent.push(new TextDecoder().decode(chunk)); queue.push(replies.shift()); wake?.()}})
 return {socket: {opened: Promise.resolve(), readable, writable, close: async () => {}}, sent}
}

async function deliver(replies: (string | null)[], to = 'admin@mail.example.test', size = 20) {
 const p = peer(replies)
 let address: unknown, rejected: string | undefined, thrown: string | undefined
 const env = {NAS: {connect: async (a?: unknown) => {address = a; return p.socket}},
  CONFIG: {ehlo: 'mail.example.test', domain: 'mail.example.test', maxBytes: 1000}}
 const message = {to, from: 'sender@external.test', rawSize: size, raw: new Blob(['Subject: a\r\n\r\n.dot line\r\n']).stream(),
  setReject: (r: string) => {rejected = r}}
 try {await worker.email(message, env)} catch(e) {thrown = (e as Error).message}
 return {address, rejected, thrown, sent: p.sent.join('')}
}

const ok = ['220 mail\r\n', '250 mail\r\n', '250 ok\r\n', '250 ok\r\n', '354 go\r\n', '250 queued\r\n']

test('a final 250 accepts the message; connect() gets an address and DATA is dot-stuffed', async () => {
 const r = await deliver([...ok])
 expect(r).toMatchObject({rejected: undefined, thrown: undefined})
 // A VPC Service connect() without an argument throws on Cloudflare.
 expect(typeof r.address).toBe('string')
 expect(r.sent).toContain('RCPT TO:<admin@mail.example.test>')
 expect(r.sent).toContain('\r\n..dot line\r\n.\r\n')
})

test('a permanent MailPlus refusal is passed on as a rejection', async () => {
 const r = await deliver(['220 mail\r\n', '250 mail\r\n', '250 ok\r\n', '550 no such user\r\n'])
 expect(r.rejected).toBeTruthy()
 expect(r.thrown).toBeUndefined()
})

test('a 5xx to MAIL, RCPT or DATA is passed on as a rejection', async () => {
 for(const replies of [
  ['220 mail\r\n', '250 mail\r\n', '553 sender refused\r\n'],
  ['220 mail\r\n', '250 mail\r\n', '250 ok\r\n', '550 no such user\r\n'],
  ['220 mail\r\n', '250 mail\r\n', '250 ok\r\n', '250 ok\r\n', '554 no valid recipients\r\n'],
  [...ok.slice(0, 5), '552 too big\r\n'],
 ]) {
  const r = await deliver(replies)
  expect(r.rejected).toBe('Rejected by the mail server')
  expect(r.thrown).toBeUndefined()
 }
})

test('a 5xx to the greeting or to EHLO is temporary: it refuses the session, not the message', async () => {
 for(const replies of [['554 no service\r\n'], ['220 mail\r\n', '550 access denied\r\n'], ['220 mail\r\n', '502-not\r\n502 here\r\n']]) {
  const r = await deliver(replies)
  expect(r.thrown).toBe('Temporary delivery failure')
  expect(r.rejected).toBeUndefined()
  expect(r.sent).not.toContain('MAIL FROM')
 }
})

test('a temporary refusal or a closed connection throws, so the sender retries', async () => {
 for(const replies of [['220 mail\r\n', '250 mail\r\n', '451 later\r\n'], ['220 mail\r\n', null]]) {
  const r = await deliver(replies)
  expect(r.thrown).toBe('Temporary delivery failure')
  expect(r.rejected).toBeUndefined()
 }
})

test('another domain, a relay-shaped address or an oversized message is rejected before connecting', async () => {
 for(const to of ['admin@example.test', 'admin@sub.mail.example.test', 'admin@mail.example.test.evil.test', 'x%evil.test@mail.example.test',
  'evil.test!x@mail.example.test', '"a b"@mail.example.test', '@evil.test:x@mail.example.test', 'a@b@mail.example.test', '.a@mail.example.test', 'a..b@mail.example.test', '@mail.example.test']) {
  const r = await deliver([...ok], to)
  expect(r.rejected, to).toBe('Unknown recipient')
  expect(r.address, to).toBeUndefined()
 }
 const big = await deliver([...ok], undefined, 5000)
 expect(big.rejected).toBeTruthy()
 expect(big.address).toBeUndefined()
})

test('any plain address of the domain goes to MailPlus, which decides whether the user exists', async () => {
 // A user added in MailPlus after setup: the Worker needs no list.
 const r = await deliver([...ok], 'New.User+tag@MAIL.Example.Test')
 expect(r).toMatchObject({rejected: undefined, thrown: undefined})
 expect(r.sent).toContain('RCPT TO:<New.User+tag@mail.example.test>')
 // MailPlus says the user does not exist: passed on as a rejection.
 const unknown = await deliver(['220 mail\r\n', '250 mail\r\n', '250 ok\r\n', '550 5.1.1 User unknown\r\n'], 'nobody@mail.example.test')
 expect(unknown.rejected).toBe('Rejected by the mail server')
})

test('a configuration without the domain is a temporary failure, so senders retry', async () => {
 const message = {to: 'admin@mail.example.test', from: 'a@b.test', rawSize: 1, raw: new Blob(['x']).stream(), setReject: () => {}}
 await expect(worker.email(message, {NAS: {}, CONFIG: {ehlo: 'mail.example.test', recipients: ['admin@mail.example.test'], maxBytes: 1000}})).rejects.toThrow('Invalid configuration')
})

// ---- End to end with the uploaded metadata (Go golden:
// backend/internal/mail/cloudflare/testdata/inbound-upload-metadata.json).
// The env is built the way the platform delivers bindings: a json binding is
// its parsed JSON value; a vpc_service binding is a connect() whose argument
// is ignored and which opens TCP to the service's registered host:port (here
// a local Postfix-like SMTP server).
import {readFileSync} from 'node:fs'
import {createServer, connect as tcp, type AddressInfo, type Server} from 'node:net'
import {Readable, Writable} from 'node:stream'

type Metadata = {bindings: {type: string; name: string; json?: unknown; service_id?: string}[]}
const metadata: Metadata = JSON.parse(readFileSync(new URL('../../backend/internal/mail/cloudflare/testdata/inbound-upload-metadata.json', import.meta.url), 'utf8'))

/** A Postfix-like SMTP server: 220, EHLO, MAIL, RCPT (known recipients only), DATA, QUIT. */
function smtpServer(known: string[], dataReply = '250 2.0.0 Ok: queued as TEST') {
 const log: string[] = []
 const server = createServer(socket => {
  let buf = '', data = false, body = ''
  socket.write('220 mail.sample-nas.test ESMTP Postfix\r\n')
  socket.on('data', chunk => {
   buf += chunk.toString('latin1')
   for(;;) {
    if(data) {
     const end = buf.indexOf('\r\n.\r\n')
     if(end < 0) return
     body = buf.slice(0, end); buf = buf.slice(end + 5); data = false
     log.push('BODY ' + body); socket.write(dataReply + '\r\n'); continue
    }
    const nl = buf.indexOf('\r\n'); if(nl < 0) return
    const line = buf.slice(0, nl); buf = buf.slice(nl + 2); log.push(line)
    if(/^EHLO /i.test(line)) socket.write('250-mail.sample-nas.test\r\n250-SIZE 10485760\r\n250 8BITMIME\r\n')
    else if(/^MAIL FROM:/i.test(line)) socket.write('250 2.1.0 Ok\r\n')
    else if(/^RCPT TO:/i.test(line)) socket.write(known.some(k => line.toLowerCase().includes(`<${k}>`)) ? '250 2.1.5 Ok\r\n' : '550 5.1.1 User unknown\r\n')
    else if(/^DATA$/i.test(line)) {data = true; socket.write('354 End data with <CR><LF>.<CR><LF>\r\n')}
    else if(/^QUIT$/i.test(line)) {socket.end('221 2.0.0 Bye\r\n'); return}
    else socket.write('502 5.5.2 Error\r\n')
   }
  })
  socket.on('error', () => {})
 })
 return {server, log, get body() {return log}}
}

// The Worker reads env.NAS and env.CONFIG by name and passes the parsed config
// to deliver() on its own; it never copies (spreads) env. The harness env
// refuses enumeration, so a `{...env}` in the Worker fails the tests.
function platformEnv(server: Server): Record<string, unknown> {
 const {port} = server.address() as AddressInfo
 const env: Record<string, unknown> = {}
 for(const b of metadata.bindings) {
  if(b.type === 'json') env[b.name] = b.json // the parsed JSON value, as Workers deliver it
  else if(b.type === 'vpc_service') env[b.name] = {connect(address?: unknown) {
   if(typeof address !== 'string') throw new TypeError("Failed to execute 'connect' on 'Fetcher': parameter 1 is not of type 'SocketAddress or string'.")
   const s = tcp(port, '127.0.0.1') // the registered host:port; the argument is ignored
   return {opened: new Promise<void>((ok, fail) => {s.once('connect', () => ok()); s.once('error', fail)}),
    readable: Readable.toWeb(s) as unknown as ReadableStream<Uint8Array>, writable: Writable.toWeb(s), close: async () => {s.destroy()}}
  }}
 }
 return noSpread(env)
}

function noSpread<T extends object>(env: T): T {
 return new Proxy(env, {ownKeys() {throw new Error('env enumerated')}})
}

async function listen(server: Server) {await new Promise<void>(ok => server.listen(0, '127.0.0.1', ok))}

test('the uploaded metadata delivers through the VPC binding with a full SMTP dialogue', async () => {
 const config = metadata.bindings.find(b => b.type === 'json')!.json as {domain: string; ehlo: string}
 expect(typeof config).toBe('object') // never a JSON string (build 27)
 const smtp = smtpServer([`admin@${config.domain}`])
 await listen(smtp.server)
 try {
  let rejected: string | undefined
  const raw = 'From: a@external.test\r\nSubject: MPSA-1C3ABD29\r\n\r\n.leading dot\r\nbody\r\n'
  // The domain is matched case-insensitively and spelled as configured; the local part goes as sent.
  await worker.email({to: `admin@${config.domain.toUpperCase()}`, from: 'sender@external.test', rawSize: raw.length,
   raw: new Blob([raw]).stream(), setReject: (r: string) => {rejected = r}}, platformEnv(smtp.server))
  expect(rejected).toBeUndefined()
  // Byte for byte, dot-stuffed; the final CRLF belongs to the end marker.
  expect(smtp.log).toEqual([`EHLO ${config.ehlo}`, 'MAIL FROM:<sender@external.test>', `RCPT TO:<admin@${config.domain}>`, 'DATA',
   'BODY ' + raw.slice(0, -2).replace('\r\n.leading', '\r\n..leading')])
 } finally {smtp.server.close()}
})

test('with the platform env, a MailPlus 5xx is rejected and a 4xx throws (the sender retries)', async () => {
 const config = metadata.bindings.find(b => b.type === 'json')!.json as {domain: string}
 for(const [known, dataReply, expectThrow] of [[[], '250 ok', false], [[`admin@${config.domain}`], '451 4.3.0 try later', true]] as const) {
  const smtp = smtpServer([...known], dataReply)
  await listen(smtp.server)
  try {
   let rejected: string | undefined, thrown: string | undefined
   try {
    await worker.email({to: `admin@${config.domain}`, from: 'sender@external.test', rawSize: 10, raw: new Blob(['Subject: x\r\n\r\nhi\r\n']).stream(),
     setReject: (r: string) => {rejected = r}}, platformEnv(smtp.server))
   } catch(e) {thrown = (e as Error).message}
   if(expectThrow) expect(thrown).toBe('Temporary delivery failure')
   else expect(rejected).toBeTruthy()
  } finally {smtp.server.close()}
 }
})

test('a CONFIG delivered as a JSON string (an older upload) is still parsed; a broken one is a temporary failure', async () => {
 const config = metadata.bindings.find(b => b.type === 'json')!.json as {domain: string}
 const smtp = smtpServer([`admin@${config.domain}`])
 await listen(smtp.server)
 try {
  const env = platformEnv(smtp.server)
  let rejected: string | undefined
  await worker.email({to: `admin@${config.domain}`, from: 's@external.test', rawSize: 10, raw: new Blob(['Subject: x\r\n\r\nhi\r\n']).stream(),
   setReject: (r: string) => {rejected = r}}, noSpread({NAS: env.NAS, CONFIG: JSON.stringify(config)}))
  expect(rejected).toBeUndefined()
  await expect(worker.email({to: `admin@${config.domain}`, from: 's@external.test', rawSize: 10, raw: new Blob(['x']).stream(), setReject: () => {}},
   noSpread({NAS: env.NAS, CONFIG: {}}))).rejects.toThrow('Invalid configuration')
 } finally {smtp.server.close()}
})
