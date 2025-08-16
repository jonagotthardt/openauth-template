import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Subject Definition
const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

// Passwort-Hash Funktionen
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

// Worker Handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Direkt den OpenAuth Issuer aufrufen – kein Redirect/Code nötig
    return issuer({
      storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
      subjects,
      providers: {
        password: PasswordProvider({
          async register(ctx, email, password) {
            const hash = await hashPassword(password);

            // Insert oder Update ohne RETURNING
            await env.AUTH_DB.prepare(
              `INSERT INTO user (email, password_hash) VALUES (?, ?)
               ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash`
            ).bind(email, hash).run();

            // Anschließend ID abfragen
            const row = await env.AUTH_DB.prepare(
              `SELECT id FROM user WHERE email = ?`
            ).bind(email).first<{ id: string }>();

            if (!row?.id) throw new Error("Failed to fetch user ID after register");

            console.log("Register debug:", { email, id: row.id });

            return ctx.subject("user", { id: String(row.id) });
          },

          async login(ctx, email, password) {
            const row = await env.AUTH_DB.prepare(
              `SELECT id, password_hash FROM user WHERE email = ?`
            ).bind(email).first<{ id: string; password_hash: string }>();

            if (!row?.id || !row.password_hash) throw new Error("User not found");

            const valid = await verifyPassword(password, row.password_hash);
            if (!valid) throw new Error("Invalid password");

            console.log("Login debug:", { email, id: row.id });

            return ctx.subject("user", { id: String(row.id) });
          },
        }),
      },
      theme: {
        title: "CommunitySMP Login",
        primary: "#0051c3",
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;