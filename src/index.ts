// src/index.ts
import { hash } from "bcryptjs"; // Optional: sichere Hash-Bibliothek
import { compare } from "bcryptjs";

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/register") {
      const { email, password } = await request.json();

      if (!email || !password) {
        return new Response(JSON.stringify({ error: "Missing email or password" }), { status: 400 });
      }

      // Passwort hashen
      const password_hash = await hash(password, 10);

      // Insert oder Update in D1
      await env.AUTH_DB.prepare(
        `INSERT INTO users (email, password_hash) VALUES (?, ?)
         ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash`
      ).bind(email, password_hash).run();

      // ID abfragen
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

      const valid = await compare(password, row.password_hash);

      if (!valid) {
        return new Response(JSON.stringify({ error: "Invalid password" }), { status: 401 });
      }

      return new Response(JSON.stringify({ message: "Login successful", id: row.id }), { status: 200 });
    }

    return new Response("Not Found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;