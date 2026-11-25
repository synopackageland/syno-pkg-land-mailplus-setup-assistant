// MailPlus Setup Assistant inbound Worker: Email Routing hands one message to
// email(); it is delivered byte for byte to MailPlus over one Workers VPC
// Service (SMTP TCP 25 on the NAS LAN address). There is no spool. Cloudflare
// accepts the message from the sender only after MailPlus's final 250; any
// other outcome before that throws, and the sender gets a temporary error and
// retries on its own schedule. A permanent MailPlus refusal of this message
// (5xx to MAIL, RCPT or DATA) is passed on as a rejection; a 5xx to the 220
// greeting or to EHLO says nothing about the message (MailPlus refuses the
// session: overloaded, misconfigured, blocking the VPC address), so it is a
// temporary failure too. No HTTP handler, message contents or SMTP replies are
// logged.
const encoder = new TextEncoder();

async function deliver(env, config, bytes, from, recipient) {
  if (/[\r\n<>]/u.test(from) || /[\r\n<>]/u.test(recipient)) throw Error("Invalid envelope");
  let socket, timer, finished = false;
  const attempt = async () => {
    // A VPC Service binding needs an address argument but always connects to
    // its registered host and port; the value is ignored.
    socket = await env.NAS.connect("nas:25");
    if (finished) throw Error("SMTP deadline");
    await socket.opened;
    const reader = socket.readable.getReader();
    const writer = socket.writable.getWriter();
    let pending = "", readBytes = 0;
    const decoder = new TextDecoder();
    async function reply(expected) {
      let replyCode;
      for (;;) {
        let newline = pending.indexOf("\n");
        while (newline < 0) {
          const chunk = await reader.read();
          if (chunk.done) throw Error("SMTP closed before reply");
          readBytes += chunk.value.length;
          if (readBytes > 32768) throw Error("SMTP reply too large");
          pending += decoder.decode(chunk.value, { stream: true });
          newline = pending.indexOf("\n");
        }
        const line = pending.slice(0, newline).replace(/\r$/u, "");
        pending = pending.slice(newline + 1);
        if (!/^\d{3}[ -]/u.test(line)) throw Error("Invalid SMTP reply");
        const code = Number(line.slice(0, 3));
        if (replyCode !== undefined && replyCode !== code) throw Error("Invalid SMTP multiline reply");
        replyCode = code;
        if (line[3] !== " ") continue;
        if (code !== expected) {
          const error = Error("SMTP refusal");
          error.smtpCode = code;
          error.messageStage = messageStage;
          throw error;
        }
        return code;
      }
    }
    async function command(text, code) {
      await writer.write(encoder.encode(text + "\r\n"));
      return reply(code);
    }
    // Replies before MAIL are about the session, not this message.
    let messageStage = false;
    await reply(220);
    await command(`EHLO ${config.ehlo}`, 250);
    messageStage = true;
    await command(`MAIL FROM:<${from}>`, 250);
    await command(`RCPT TO:<${recipient}>`, 250);
    await command("DATA", 354);
    const escaped = new Uint8Array(bytes.length * 2 + 5);
    let size = 0, lineStart = true;
    for (const byte of bytes) {
      if (lineStart && byte === 46) escaped[size++] = 46;
      escaped[size++] = byte;
      lineStart = byte === 10;
    }
    if (bytes.length < 2 || bytes[bytes.length - 2] !== 13 || bytes[bytes.length - 1] !== 10) {
      escaped[size++] = 13; escaped[size++] = 10;
    }
    escaped[size++] = 46; escaped[size++] = 13; escaped[size++] = 10;
    await writer.write(escaped.subarray(0, size));
    await reply(250);
  };
  try {
    await Promise.race([
      attempt(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error("SMTP deadline")), 25000); }),
    ]);
  } finally {
    finished = true;
    clearTimeout(timer);
    try { await socket?.close(); } catch {}
  }
}

// The CONFIG json binding arrives as the parsed object. A string (an older
// upload sent the JSON text as a string) is parsed; anything else is a
// temporary failure, so senders retry instead of losing mail.
function settings(env) {
  const raw = typeof env.CONFIG === "string" ? JSON.parse(env.CONFIG) : env.CONFIG;
  if (!raw || typeof raw.domain !== "string" || !raw.domain || typeof raw.ehlo !== "string" || typeof raw.maxBytes !== "number") {
    throw Error("Invalid configuration");
  }
  return raw;
}

// The relay guard is the domain: only a recipient whose domain is exactly the
// configured MailPlus domain (case-insensitive) is handed on, and MailPlus,
// the final destination for that domain, decides whether the user exists. The
// local part must be a plain dot-atom without "%" or "!": Postfix can rewrite
// user%other@domain (percent hack) or a bang path into another destination,
// so those are refused here instead of trusting MailPlus's relay settings. A
// quoted local part, a source route or a second "@" is refused likewise.
const LOCAL = /^[A-Za-z0-9#$&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9#$&'*+/=?^_`{|}~-]+)*$/u;
function accepted(address, domain) {
  if (typeof address !== "string" || address.length > 254) return undefined;
  const at = address.lastIndexOf("@");
  if (at <= 0) return undefined;
  const local = address.slice(0, at), host = address.slice(at + 1);
  if (local.length > 64 || !LOCAL.test(local) || host.toLowerCase() !== domain.toLowerCase()) return undefined;
  return `${local}@${domain}`;
}

export default {
  async email(message, env) {
    const config = settings(env);
    const recipient = accepted(message.to, config.domain);
    if (!recipient) { message.setReject("Unknown recipient"); return; }
    if (message.rawSize > config.maxBytes) { message.setReject("Message exceeds receiving limit"); return; }
    const bytes = new Uint8Array(await new Response(message.raw).arrayBuffer());
    if (bytes.length > config.maxBytes) { message.setReject("Message exceeds receiving limit"); return; }
    try {
      await deliver(env, config, bytes, message.from, recipient);
    } catch (error) {
      // A 5xx to MAIL, RCPT or DATA is final; everything else, a 5xx to the
      // greeting or EHLO included, is temporary (Cloudflare answers the sender
      // 4xx and the sender retries).
      if (error.messageStage && error.smtpCode >= 500 && error.smtpCode < 600) { message.setReject("Rejected by the mail server"); return; }
      throw Error("Temporary delivery failure");
    }
  },
};
