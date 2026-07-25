// POST /api/contact — sends project inquiries to CONTACT_EMAIL via Resend.
// Spam defenses: honeypot field, minimum-fill-time gate, per-IP rate limit,
// and Cloudflare Turnstile verification when TURNSTILE_SECRET_KEY is set.

const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 5;
const hits = new Map(); // per-instance; resets on cold start, good enough as a first gate

function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  return recent.length > MAX_PER_WINDOW;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (rateLimited(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later, or email us directly.' });
  }

  const { name = '', email = '', tier = 'Not sure yet', message = '', company = '', elapsed = 0, turnstileToken = '' } = req.body || {};

  // Honeypot: real users never see or fill the "company" field.
  // Time gate: humans take more than 3 seconds to fill a form.
  if (company || elapsed < 3000) {
    // Pretend success so bots don't learn what tripped them.
    return res.status(200).json({ ok: true });
  }

  if (!name.trim() || name.length > 200) {
    return res.status(400).json({ error: 'Please add your name.' });
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim()) || email.length > 320) {
    return res.status(400).json({ error: 'Please enter a valid email so we can reply.' });
  }
  if (message.length > 5000) {
    return res.status(400).json({ error: 'Message is too long — please keep it under 5000 characters.' });
  }

  if (process.env.TURNSTILE_SECRET_KEY) {
    const verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: process.env.TURNSTILE_SECRET_KEY, response: turnstileToken, remoteip: ip }),
    }).then((r) => r.json()).catch(() => ({ success: false }));
    if (!verify.success) {
      return res.status(400).json({ error: 'Could not verify you are human. Please retry the check and submit again.' });
    }
  }

  if (!process.env.RESEND_API_KEY) {
    return res.status(503).json({ error: 'The contact form is not fully set up yet. Please email us directly at team@dimesvault.com.' });
  }

  const to = process.env.CONTACT_EMAIL || 'team@dimesvault.com';
  const from = process.env.MAIL_FROM || 'AI Site Sprint <onboarding@resend.dev>';
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const send = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from,
      to: [to],
      reply_to: email.trim(),
      subject: `Project inquiry — ${tier} — ${name.trim()}`,
      html: `<h2>New inquiry from aisitesprint.com</h2>
        <p><b>Name:</b> ${esc(name.trim())}</p>
        <p><b>Email:</b> ${esc(email.trim())}</p>
        <p><b>Interested tier:</b> ${esc(tier)}</p>
        <p><b>About the business:</b></p>
        <p>${esc(message.trim()).replace(/\n/g, '<br>') || '(not provided)'}</p>`,
    }),
  });

  if (!send.ok) {
    const detail = await send.text().catch(() => '');
    console.error('Resend error', send.status, detail);
    return res.status(500).json({ error: 'Something went wrong sending your message. Please email us directly at team@dimesvault.com.' });
  }

  return res.status(200).json({ ok: true });
}
