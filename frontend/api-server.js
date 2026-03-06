import express from 'express';
import cors from 'cors';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors());
app.use(express.json());

const MCP_SERVER_URL = 'http://127.0.0.1:8000';

let mcpClient = null;
let connecting = false;

async function createMcpClient() {
  if (connecting) return null;
  connecting = true;
  try {
    const transport = new SSEClientTransport(new URL(`${MCP_SERVER_URL}/sse`));
    const client = new Client(
      { name: 'threat-intel-frontend', version: '1.0.0' },
      { capabilities: {} }
    );
    await client.connect(transport);
    console.log('✅ Connected to MCP server at', MCP_SERVER_URL);
    connecting = false;
    return client;
  } catch (err) {
    console.error('❌ Failed to connect to MCP server:', err.message);
    connecting = false;
    return null;
  }
}

async function getMcpClient() {
  if (!mcpClient) {
    mcpClient = await createMcpClient();
  }
  return mcpClient;
}

// Check MCP connection status
app.get('/api/status', async (req, res) => {
  if (mcpClient) {
    return res.json({ connected: true, server: MCP_SERVER_URL });
  }
  const client = await getMcpClient();
  res.json({ connected: !!client, server: MCP_SERVER_URL });
});

// Reconnect to MCP server
app.post('/api/connect', async (req, res) => {
  mcpClient = null;
  const client = await getMcpClient();
  if (client) {
    res.json({ connected: true, message: 'Connected to MCP server' });
  } else {
    res.status(503).json({ connected: false, message: 'Could not connect to MCP server. Make sure it is running on port 8000.' });
  }
});

// List all available tools
app.get('/api/tools', async (req, res) => {
  try {
    const client = await getMcpClient();
    if (!client) {
      return res.status(503).json({ error: 'MCP server not connected. Start the Python server with: python server.py' });
    }
    const result = await client.listTools();
    res.json(result);
  } catch (err) {
    mcpClient = null;
    res.status(500).json({ error: err.message });
  }
});

// Call a specific tool
app.post('/api/call/:toolName', async (req, res) => {
  try {
    const client = await getMcpClient();
    if (!client) {
      return res.status(503).json({ error: 'MCP server not connected. Start the Python server with: python server.py' });
    }
    const { toolName } = req.params;
    const args = req.body;
    console.log(`🔧 Calling tool: ${toolName}`, args);
    const result = await client.callTool({ name: toolName, arguments: args });
    res.json(result);
  } catch (err) {
    console.error('Tool call error:', err.message);
    mcpClient = null;
    res.status(500).json({ error: err.message });
  }
});

// Serve the React production build when it exists (Docker / `npm run build`)
const distPath = join(__dirname, 'dist');
if (existsSync(distPath)) {
  app.use(express.static(distPath));
  // SPA fallback — let React Router handle unknown paths
  app.get('*', (_req, res) => res.sendFile(join(distPath, 'index.html')));
}

const PORT = process.env.API_PORT || 3001;
app.listen(PORT, async () => {
  console.log(`🚀 API server running on http://localhost:${PORT}`);
  console.log('Attempting initial connection to MCP server...');
  await getMcpClient();
});
