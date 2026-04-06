//  Argus Platform — Complete Backend Server
//  Supports: Mock Mode, Live Mode, AI Analysis
//  Run with node server.js
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const express = require("express");
const cors = require("cors");
const https = require("https");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Serve the frontend HTML from the same directory
app.use(express.static(path.join(__dirname)));

// Configurration 

// Easy swap for alerts
const USE_MOCK_DATA = false; // Change to false to fetch from Wazuh
const USE_API = true;      //Change to true to use live API

const WAZUH_IP           = "192.168.56.103";
const INDEXER_USER       = "admin";
const INDEXER_PASSWORD   = "8Q3w?tuhy0ETbXZ+cL16qJYm2x82p?MT";
const WAZUH_API_USER     = "wazuh";
const WAZUH_API_PASSWORD = "?Vg9gQAxA*Kf*1mMXo37..7wdPUjNFfE";
const agent = new https.Agent({ rejectUnauthorized: false });

// Load mock alerts from JSON file
let mockAlerts = [];
try {
  const mockPath = path.join(__dirname, "mock_alerts.json");
  mockAlerts = JSON.parse(fs.readFileSync(mockPath, "utf8"));

  // Normalize to always be an array
  if (!Array.isArray(mockAlerts) && mockAlerts.alerts) {
    mockAlerts = mockAlerts.alerts;
  }
  console.log(`Loaded ${mockAlerts.length} mock alerts`);
} catch (err) {
  console.warn("Could not load mock_alerts.json:", err.message);
}

// Helper Functions

function httpsRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const opts = { ...options, rejectUnauthorized: false };
    const req = https.request(opts, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data), headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, data, headers: res.headers });
        }
      });
    });
    req.on("error", (err) => reject(err));
    req.setTimeout(10000);
    if (postData) req.write(postData);
    req.end();
  });
}

function getSeverity(level) {
  if (level >= 12) return "CRITICAL";
  if (level >= 7)  return "MEDIUM";
  return "LOW";
}

// Get a simple agent list from mock alerts
function agentsFromMockAlerts(alerts) {
  const map = {};
  alerts.forEach((a, i) => {
    const name = a.source || a.agentName || a.agent?.name;
    const ip   = a.source_ip || a.sourceIp || a.agent?.ip;
    if (name && name !== "—" && name !== "System" && !map[name]) {
      map[name] = {
        id:      String(i + 1).padStart(3, "0"),
        name,
        ip:      ip || "—",
        os:      "—",
        version: "—",
        status:  "active"
      };
    }
  });
  return Object.values(map);
}

// Routes

// Alert Loader (swappable source)
async function loadAlerts() {
  try {
    let alertsData = [];
    if (USE_API) {
      const response = await fetch('/api/alerts');
      const data = await response.json();
      alertsData = data.alerts || [];
    } else {
      alertsData = mockAlerts;
    }
    return alertsData;
  } catch (err) {
    console.error("Error loading alerts:", err);
    return [];
  }
}

// GET /api/alerts
app.get("/api/alerts", async (req, res) => {
  try {
    if (USE_MOCK_DATA) {
      return res.json({ success: true, alerts: mockAlerts, mode: "mock" });
    }

    // Live Wazuh Indexer
    const auth = Buffer.from(`${INDEXER_USER}:${INDEXER_PASSWORD}`).toString("base64");
    const response = await httpsRequest({
      hostname: WAZUH_IP,
      port: 9200,
      path: "/wazuh-alerts-*/_search?size=50&sort=@timestamp:desc",
      method: "GET",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/json"
      }
    });

    if (response.status !== 200) throw new Error(`Indexer returned ${response.status}`);

    const hits = response.data?.hits?.hits || [];
    const alerts = hits.map((hit, i) => {
      const src = hit._source || {};
      return {
        id:          hit._id || `live-${i}`,
        title:       src.rule?.description || "Unknown Alert",
        severity:    getSeverity(src.rule?.level || 0),
        description: src.full_log || src.message || "",
        source:      src.agent?.name || "—",
        sourceIp:    src.data?.srcip || src.agent?.ip || null,
        location:    src.manager?.name || null,
        ruleId:      src.rule?.id || null,
        timestamp:   src["@timestamp"] || new Date().toISOString()
      };
    });

    res.json({ success: true, alerts, mode: "live" });
  } catch (err) {
    console.error("[/api/alerts]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/agents
app.get("/api/agents", async (req, res) => {
  try {
    if (USE_MOCK_DATA) {
      return res.json({
        success: true,
        agents:  agentsFromMockAlerts(mockAlerts),
        mode:    "mock"
      });
    }

    const auth = Buffer.from(`${WAZUH_API_USER}:${WAZUH_API_PASSWORD}`).toString("base64");

    // Get JWT token
    const tokenRes = await httpsRequest({
      hostname: WAZUH_IP,
      port: 55000,
      path: "/security/user/authenticate",
      method: "GET",
      headers: { Authorization: `Basic ${auth}` }
    });

    const token = tokenRes.data?.data?.token;
    if (!token) throw new Error("Could not obtain Wazuh API token");

    // Fetch agents
    const agentsRes = await httpsRequest({
      hostname: WAZUH_IP,
      port: 55000,
      path: "/agents?limit=100&select=id,name,ip,os,version,status",
      method: "GET",
      headers: { Authorization: `Bearer ${token}` }
    });

    const raw = agentsRes.data?.data?.affected_items || [];
    const agents = raw.map(a => ({
      id:      a.id,
      name:    a.name,
      ip:      a.ip || "—",
      os:      a.os?.full || a.os?.name || "—",
      version: a.version || "—",
      status:  a.status || "unknown"
    }));

    res.json({ success: true, agents, mode: "live" });
  } catch (err) {
    console.error("[/api/agents]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/ai/analyze 
app.post("/api/ai/analyze", async (req, res) => {
  try {
    const { alert } = req.body;
    if (!alert) return res.status(400).json({ success: false, error: "No alert provided" });

    // Build a message describing the alert and send it to Flask/OpenAI
    const message = `Analyze this security alert and provide investigation steps:
      Title: ${alert.title}
      Severity: ${alert.severity}
      Source: ${alert.source || "unknown"}
      Source IP: ${alert.sourceIp || "unknown"}
      Description: ${alert.description || "none"}
      Timestamp: ${alert.timestamp}`;

    const response = await fetch("http://localhost:5001/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });

    const data = await response.json();
    res.json({ success: true, response: data.response });

  } catch (err) {
    console.error("[/api/ai/analyze]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/chat", async (req, res) => {
  try {
    const { message } = req.body;

    const response = await fetch("http://localhost:5001/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message })
    });

    const data = await response.json();
    res.json(data);

  } catch (err) {
    console.error("Chat route error:", err);
    res.status(500).json({ error: "Chatbot error" });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`\n Argus backend running at http://localhost:${PORT}/dashboard.html`);
  console.log(`   Mode: ${USE_MOCK_DATA ? " MOCK DATA" : " LIVE WAZUH"}`);
  console.log("\n   Endpoints:");
  console.log("   → GET  /api/alerts");
  console.log("   → GET  /api/agents");
  console.log("   → POST /api/ai/analyze");
  console.log("   → GET  / (serves frontend)\n");
});

