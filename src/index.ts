import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";
import * as bcrypt from "bcryptjs"; // bcryptjs nutzen für Hash

const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Demo redirect
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    } else if (url.pathname === "/callback") {
      return Response.json({
        message: "Login successful!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    // OpenAuth Setup
    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider({
          // Registrierung
          async register(ctx, email, password) {
            const hash = await bcrypt.hash(password, 10);
            const result = await env.AUTH_DB.prepare(
              `INSERT INTO user (email, password_hash) VALUES (?, ?) 
               ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash
               RETURNING id;`
            ).bind(email, hash).first<{ id: string }>();
            return ctx.subject("user", { id: String(result?.id) });
          },
          // Login
          async login(ctx, email, password) {
            const row = await env.AUTH_DB.prepare(
              `SELECT id, password_hash FROM user WHERE email = ?`
            ).bind(email).first<{ id: string; password_hash: string }>();

            if (!row) throw new Error("User not found");

            const valid = await bcrypt.compare(password, row.password_hash);
            if (!valid) throw new Error("Invalid password");

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