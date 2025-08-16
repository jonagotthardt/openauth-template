// src/index.ts

// Passwort-Hash Funktionen mit Web Crypto
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const newHash = await hashPassword(password);
  return newHash === hash;
}

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/register") {
      const { email, password } = await request.json();

      if (!email || !password) {
        return new Response(JSON.stringify({ error: "Missing email or password" }), { status: 400 });
      }

      const password_hash = await hashPassword(password);

      await env.AUTH_DB.prepare(
        `INSERT INTO users (email, password_hash) VALUES (?, ?)
         ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash`
      ).bind(email, password_hash).run();

      const row = await env.AUTH_DB.prepare(`SELECT id FROM users WHERE email = ?`)
        .bind(email).first<{ id: string }>();

      if (!row?.id) {
        return new Response(JSON.stringify({ error: "Failed to create user" }), { status: 500 });
      }

      return new Response(JSON.stringify({ message: "User registered", id: row.id }), { status: 200 });
    }

    if (request.method === "POST" && url.pathname === "/login") {
      const { email, password } = await request.json();

      if (!email || !password) {
        return new Response(JSON.stringify({ error: "Missing email or password" }), { status: 400 });
      }

      const row = await env.AUTH_DB.prepare(`SELECT id, password_hash FROM users WHERE email = ?`)
        .bind(email).first<{ id: string; password_hash: string }>();

      if (!row?.id || !row.password_hash) {
        return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
      }

      const valid = await verifyPassword(password, row.password_hash);

      if (!valid) {
        return new Response(JSON.stringify({ error: "Invalid password" }), { status: 401 });
      }

      return new Response(JSON.stringify({ message: "Login successful", id: row.id }), { status: 200 });
    }

    return new Response("Not Found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;