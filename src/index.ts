import express, { type Request, type Response } from "express";
import axios, { AxiosError } from "axios";
import { Pool } from "pg";

const app = express();

const CLIENT_ID = process.env.UPWORK_CLIENT_ID as string;
const CLIENT_SECRET = process.env.UPWORK_CLIENT_SECRET as string;
const REDIRECT_URI = "https://api.kingofautomation.com/upwork/callback";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
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
    console.log("Database initialized successfully");
  } catch (error) {
    console.error("Database initialization error:", error);
  } finally {
    client.release();
  }
}

initDatabase();

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
  created_at: Date;
  updated_at: Date;
}

interface CallbackQuery {
  code?: string;
  error?: string;
}

async function saveTokens(
  accessToken: string,
  refreshToken: string,
  expiresAt: number,
): Promise<void> {
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
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query(
      `UPDATE upwork_tokens 
       SET access_token = $1, refresh_token = $2, expires_at = $3, updated_at = CURRENT_TIMESTAMP
       WHERE id = (SELECT id FROM upwork_tokens ORDER BY created_at DESC LIMIT 1)`,
      [accessToken, refreshToken, expiresAt],
    );
  } finally {
    client.release();
  }
}

app.get("/upwork/auth", (req: Request, res: Response): void => {
  const authUrl = `https://www.upwork.com/ab/account-security/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code`;
  res.redirect(authUrl);
});

app.get(
  "/upwork/callback",
  async (
    req: Request<{}, {}, {}, CallbackQuery>,
    res: Response,
  ): Promise<void> => {
    try {
      const { code, error } = req.query;

      if (error) {
        console.error("Authorization error:", error);
        res.status(400).send(`Authorization failed: ${error}`);
        return;
      }

      if (!code) {
        res.status(400).send("Missing authorization code");
        return;
      }

      const tokenResponse = await axios.post<UpworkTokenResponse>(
        "https://www.upwork.com/api/v3/oauth2/token",
        new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
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

      // Save tokens to database
      const expiresAt = Date.now() + expires_in * 1000;
      await saveTokens(access_token, refresh_token, expiresAt);

      console.log("Tokens stored successfully in database");

      res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Authorization Successful</title>
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
              max-width: 600px;
              margin: 80px auto;
              padding: 20px;
              text-align: center;
            }
            .success {
              color: #28a745;
              font-size: 48px;
              margin-bottom: 20px;
            }
            h1 { font-size: 24px; margin-bottom: 10px; }
            p { color: #666; line-height: 1.6; }
          </style>
        </head>
        <body>
          <div class="success">✓</div>
          <h1>Authorization Successful</h1>
          <p>Your Upwork account has been successfully connected to King of Automation.</p>
          <p>You can safely close this window.</p>
        </body>
      </html>
    `);
    } catch (error) {
      const axiosError = error as AxiosError;
      console.error(
        "Token exchange error:",
        axiosError.response?.data || axiosError.message,
      );
      res.status(500).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Authorization Failed</title>
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
              max-width: 600px;
              margin: 80px auto;
              padding: 20px;
              text-align: center;
            }
            .error { color: #dc3545; font-size: 48px; margin-bottom: 20px; }
            h1 { font-size: 24px; margin-bottom: 10px; }
            p { color: #666; }
          </style>
        </head>
        <body>
          <div class="error">✗</div>
          <h1>Authorization Failed</h1>
          <p>There was an error connecting your Upwork account. Please try again.</p>
        </body>
      </html>
    `);
    }
  },
);

app.post(
  "/upwork/refresh",
  async (req: Request, res: Response): Promise<void> => {
    try {
      const storedTokens = await getTokens();

      if (!storedTokens?.refresh_token) {
        res.status(400).json({ error: "No refresh token available" });
        return;
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

      console.log("Tokens refreshed successfully");

      res.json({ success: true, expires_in });
    } catch (error) {
      const axiosError = error as AxiosError;
      console.error(
        "Token refresh error:",
        axiosError.response?.data || axiosError.message,
      );
      res.status(500).json({ error: "Failed to refresh token" });
    }
  },
);

app.get("/upwork/token", async (req: Request, res: Response): Promise<void> => {
  try {
    const storedTokens = await getTokens();

    if (!storedTokens) {
      res
        .status(404)
        .json({ error: "No tokens available. Please authorize first." });
      return;
    }

    const isExpired = Date.now() >= storedTokens.expires_at;

    res.json({
      has_token: true,
      is_expired: isExpired,
      expires_at: new Date(storedTokens.expires_at).toISOString(),
      access_token: storedTokens.access_token,
      refresh_token: storedTokens.refresh_token,
    });
  } catch (error) {
    console.error("Error fetching tokens:", error);
    res.status(500).json({ error: "Failed to retrieve tokens" });
  }
});

app.get("/upwork/health", (req: Request, res: Response): void => {
  if (!req.query.code && !req.query.error) {
    res.status(200).send(`
      <!DOCTYPE html>
      <html>
        <head><title>OAuth Callback Endpoint</title></head>
        <body>
          <p>This is an OAuth callback endpoint. Please initiate authorization through the proper OAuth flow.</p>
        </body>
      </html>
    `);
  }
});

app.get("/", (req: Request, res: Response): void => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Upwork OAuth Server</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            max-width: 800px;
            margin: 80px auto;
            padding: 20px;
          }
          h1 { color: #333; }
          .endpoint {
            background: #f5f5f5;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
          }
          .method {
            display: inline-block;
            padding: 4px 8px;
            background: #007bff;
            color: white;
            border-radius: 3px;
            font-size: 12px;
            margin-right: 10px;
          }
          .post { background: #28a745; }
        </style>
      </head>
      <body>
        <h1>Upwork OAuth 2.0 Server</h1>
        <p>API endpoints:</p>
        
        <div class="endpoint">
          <span class="method">GET</span>
          <strong>/upwork/auth</strong> - Initiate OAuth flow
        </div>
        
        <div class="endpoint">
          <span class="method">GET</span>
          <strong>/upwork/callback</strong> - OAuth callback (Upwork redirects here)
        </div>
        
        <div class="endpoint">
          <span class="method">GET</span>
          <strong>/upwork/token</strong> - Get current access token and status
        </div>
        
        <div class="endpoint">
          <span class="method post">POST</span>
          <strong>/upwork/refresh</strong> - Refresh expired token
        </div>
        
        <div class="endpoint">
          <span class="method">GET</span>
          <strong>/upwork/health</strong> - Health check
        </div>
      </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, (): void => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Callback URL: ${REDIRECT_URI}`);
});
