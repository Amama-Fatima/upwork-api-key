import express, { type Request, type Response } from "express";
import axios, { AxiosError } from "axios";
import { Pool } from "pg";

const app = express();

const CLIENT_ID = process.env.UPWORK_CLIENT_ID as string;
const CLIENT_SECRET = process.env.UPWORK_CLIENT_SECRET as string;
const REDIRECT_URI = "https://api.kingofautomation.com/upwork/callback";
const PORT = process.env.PORT || 3000;

if (!CLIENT_ID || !CLIENT_SECRET || !process.env.DATABASE_URL) {
  console.error("❌ Missing required environment variables");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS upwork_tokens (
        id SERIAL PRIMARY KEY,
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Database initialized successfully");
  } finally {
    client.release();
  }
}

interface UpworkTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

interface StoredTokens {
  id: number;
  access_token: string;
  refresh_token: string;
  expires_at: number;
}

async function saveTokens(
  accessToken: string,
  refreshToken: string,
  expiresAt: number,
) {
  const client = await pool.connect();
  try {
    await client.query("DELETE FROM upwork_tokens");

    await client.query(
      `INSERT INTO upwork_tokens (access_token, refresh_token, expires_at)
       VALUES ($1, $2, $3)`,
      [accessToken, refreshToken, expiresAt],
    );
  } finally {
    client.release();
  }
}

async function getTokens(): Promise<StoredTokens | null> {
  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT * FROM upwork_tokens ORDER BY created_at DESC LIMIT 1",
    );
    return result.rows[0] || null;
  } finally {
    client.release();
  }
}

async function updateTokens(
  accessToken: string,
  refreshToken: string,
  expiresAt: number,
) {
  const client = await pool.connect();
  try {
    await client.query(
      `UPDATE upwork_tokens
       SET access_token = $1,
           refresh_token = $2,
           expires_at = $3,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = (SELECT id FROM upwork_tokens ORDER BY created_at DESC LIMIT 1)`,
      [accessToken, refreshToken, expiresAt],
    );
  } finally {
    client.release();
  }
}

app.get("/", (_req: Request, res: Response) => {
  res.status(200).json({ status: "Upwork OAuth server running" });
});

app.get("/upwork/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "ok" });
});

app.get("/upwork/auth", (_req: Request, res: Response) => {
  const authUrl =
    `https://www.upwork.com/ab/account-security/oauth2/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code`;

  res.redirect(authUrl);
});

app.get("/upwork/callback", async (req: Request, res: Response) => {
  try {
    const { code, error } = req.query as {
      code?: string;
      error?: string;
    };

    if (error) {
      return res.status(400).send(`Authorization failed: ${error}`);
    }

    if (!code) {
      return res.status(400).send("Missing authorization code");
    }

    const tokenResponse = await axios.post<UpworkTokenResponse>(
      "https://www.upwork.com/api/v3/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
      },
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    const expiresAt = Date.now() + expires_in * 1000;
    await saveTokens(access_token, refresh_token, expiresAt);

    res.send("✅ Authorization successful. You can close this window.");
  } catch (error) {
    const axiosError = error as AxiosError;
    console.error(
      "Token exchange error:",
      axiosError.response?.data || axiosError.message,
    );
    res.status(500).send("Authorization failed.");
  }
});

app.post("/upwork/refresh", async (_req: Request, res: Response) => {
  try {
    const storedTokens = await getTokens();

    if (!storedTokens?.refresh_token) {
      return res.status(400).json({ error: "No refresh token available" });
    }

    const tokenResponse = await axios.post<UpworkTokenResponse>(
      "https://www.upwork.com/api/v3/oauth2/token",
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: storedTokens.refresh_token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
      },
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    const expiresAt = Date.now() + expires_in * 1000;
    await updateTokens(access_token, refresh_token, expiresAt);

    res.json({ success: true, expires_in });
  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(500).json({ error: "Failed to refresh token" });
  }
});

app.get("/upwork/token", async (_req: Request, res: Response) => {
  try {
    const storedTokens = await getTokens();

    if (!storedTokens) {
      return res
        .status(404)
        .json({ error: "No tokens available. Please authorize first." });
    }

    const isExpired = Date.now() >= storedTokens.expires_at;

    res.json({
      has_token: true,
      is_expired: isExpired,
      expires_at: new Date(storedTokens.expires_at).toISOString(),
      access_token: storedTokens.access_token,
    });
  } catch (error) {
    console.error("Error fetching tokens:", error);
    res.status(500).json({ error: "Failed to retrieve tokens" });
  }
});

async function startServer() {
  try {
    await initDatabase();

    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`Callback URL: ${REDIRECT_URI}`);
    });

    // Graceful shutdown (important for Railway)
    process.on("SIGTERM", () => {
      console.log("SIGTERM received. Shutting down gracefully...");
      server.close(() => {
        pool.end();
        process.exit(0);
      });
    });
  } catch (err) {
    console.error("❌ Startup failed:", err);
    process.exit(1);
  }
}

startServer();
