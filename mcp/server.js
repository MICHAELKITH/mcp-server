import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID, timingSafeEqual } from "crypto";
import { exec } from "child_process";
import { promisify } from "util";
import { z } from "zod";

const execAsync = promisify(exec);

// ── Config ──────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const TIMEOUT_MS = parseInt(process.env.CMD_TIMEOUT_MS || "30000", 10);
const TOKEN      = process.env.MCP_TOKEN;

if (!TOKEN || TOKEN.length < 16) {
  console.error("Refusing to start: set MCP_TOKEN to a random string of 16+ characters.");
  process.exit(1);
}

// ── Auth helper (constant-time compare) ─────────────────────────────────────
function tokenIsValid(header) {
  const expected = Buffer.from(`Bearer ${TOKEN}`);
  const given    = Buffer.from(header || "");
  return given.length === expected.length && timingSafeEqual(given, expected);
}

// ── MCP server factory (one per session) ────────────────────────────────────
function createMcpServer() {
  const server = new McpServer({
    name:    "execute-command-server",
    version: "1.0.0",
  });

  server.tool(
    "execute_command",
    "Execute a shell command on this Windows machine and return stdout, stderr, and exit code.",
    {
      command: z.string().describe("The shell command to execute"),
    },
    async ({ command }) => {
      const cwd = process.cwd();
      console.log(`[execute_command] cmd="${command}" cwd="${cwd}"`);

      try {
        // No `shell` option: Node uses cmd.exe on Windows by default
        const { stdout, stderr } = await execAsync(command, {
          cwd,
          timeout: TIMEOUT_MS,
          maxBuffer: 10 * 1024 * 1024, // 10 MB
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ exit_code: 0, stdout, stderr }, null, 2),
            },
          ],
        };
      } catch (err) {
        // exec throws on non-zero exit or timeout
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                exit_code: err.code   ?? -1,
                stdout:    err.stdout ?? "",
                stderr:    err.stderr ?? err.message,
                timed_out: err.killed ?? false,
              }, null, 2),
            },
          ],
        };
      }
    }
  );

  return server;
}

// ── Express app ─────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// Health check (no auth required, defined before the auth middleware)
app.get("/health", (_req, res) => {
  res.json({ status: "ok", sessions: sessions.size });
});

// Require the bearer token on everything under /mcp
app.use("/mcp", (req, res, next) => {
  if (!tokenIsValid(req.headers.authorization)) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
});

// Session store for stateful transports
const sessions = new Map(); // sessionId → transport

// Handle all MCP messages on POST /mcp
app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] || randomUUID();

  let transport = sessions.get(sessionId);
  if (!transport) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => sessionId,
    });

    const server = createMcpServer();
    await server.connect(transport);
    sessions.set(sessionId, transport);

    transport.onclose = () => {
      sessions.delete(sessionId);
      console.log(`[session] closed: ${sessionId}`);
    };

    console.log(`[session] created: ${sessionId}`);
  }

  await transport.handleRequest(req, res, req.body);
});

// SSE stream endpoint for server-to-client notifications
app.get("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  const transport = sessions.get(sessionId);

  if (!transport) {
    res.status(404).json({ error: "Session not found" });
    return;
  }

  await transport.handleRequest(req, res);
});

// Session teardown
app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  const transport = sessions.get(sessionId);

  if (transport) {
    await transport.handleRequest(req, res);
    sessions.delete(sessionId);
  } else {
    res.status(404).json({ error: "Session not found" });
  }
});

// Bind to localhost only so other devices on your Wi-Fi can't reach it
app.listen(PORT, "127.0.0.1", () => {
  console.log(`MCP execute-command server listening on http://127.0.0.1:${PORT}`);
  console.log(`  Endpoint : POST/GET/DELETE http://127.0.0.1:${PORT}/mcp  (token required)`);
  console.log(`  Health   : GET  http://127.0.0.1:${PORT}/health`);
});