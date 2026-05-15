import { useMemo, useState } from "react";

const COMPROMISED_KEY = "GSA-PROD-4f9a2b1c-GLOBAL";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const sessionFixtures = [
  {
    session_id: "sess-pay-1028",
    ip_address: "10.0.1.10",
    user_agent: "payments-service/4.7 InternalApp",
    app_name: "payments-service",
    last_seen: "2m ago",
  },
  {
    session_id: "sess-auth-8831",
    ip_address: "10.0.1.11",
    user_agent: "auth-service/3.2 InternalApp",
    app_name: "auth-service",
    last_seen: "4m ago",
  },
  {
    session_id: "sess-partner-4452",
    ip_address: "172.20.4.19",
    user_agent: "PartnerSync/1.9",
    app_name: "webhook-processor",
    last_seen: "6m ago",
  },
  {
    session_id: "sess-ext-7190",
    ip_address: "185.220.101.42",
    user_agent: "curl/8.1",
    app_name: "payments-service",
    last_seen: "now",
  },
  {
    session_id: "sess-ext-7394",
    ip_address: "45.142.212.100",
    user_agent: "python-requests/2.31",
    app_name: "data-pipeline",
    last_seen: "1m ago",
  },
];

const ipContext = {
  "10.0.1.10": "Known_Internal",
  "10.0.1.11": "Known_Internal",
  "172.20.4.19": "Known_Partner",
  "185.220.101.42": "Unknown_External",
  "45.142.212.100": "Unknown_External",
};

const appCriticality = {
  "payments-service": "P1",
  "auth-service": "P1",
  "data-pipeline": "P2",
  "webhook-processor": "P3",
  "notification-svc": "P4",
};

const criticalityLabel = {
  P1: "Critical",
  P2: "High",
  P3: "Medium",
  P4: "Low",
};

const Identity_API = {
  async Get_Active_Sessions(key_id) {
    await delay(500);
    return sessionFixtures.map((session) => ({ ...session, key_id }));
  },
  async Rotate_Key(key_id) {
    await delay(750);
    return {
      old_key_id: key_id,
      new_key_id: `GSA-PROD-${crypto.randomUUID().slice(0, 8).toUpperCase()}-ROTATED`,
      rotated_at: new Date().toISOString(),
      status: "old key invalidated",
    };
  },
  async Tag_Session_As_Malicious(session_id) {
    await delay(250);
    return {
      session_id,
      routed_to: "Honey-Token",
      tagged_at: new Date().toISOString(),
      status: "traffic diverted",
    };
  },
};

const Asset_Inventory_API = {
  async Check_IP_Context(ip_address) {
    await delay(180);
    return ipContext[ip_address] ?? "Unknown_External";
  },
  async Get_App_Criticality(app_name) {
    await delay(180);
    return appCriticality[app_name] ?? "P4";
  },
};

const Notification_API = {
  async Prompt_App_Owner(app_name) {
    await delay(300);
    return {
      app_name,
      channel: `#owner-${app_name}`,
      message: `Rotate Now requested for ${app_name}`,
      action: "Rotate Now",
      prompt_id: `prompt-${app_name}-${Date.now()}`,
      sent_at: new Date().toISOString(),
    };
  },
};

function severityForSession(session) {
  if (session.ip_context === "Unknown_External" && ["P1", "P2"].includes(session.criticality)) {
    return "Critical";
  }

  if (session.ip_context === "Unknown_External") {
    return "High";
  }

  if (session.ip_context === "Known_Partner") {
    return "Watch";
  }

  return "Normal";
}

function statusColor(status) {
  const colors = {
    Critical: "#f97373",
    High: "#fb923c",
    Watch: "#facc15",
    Normal: "#34d399",
    Honey: "#a78bfa",
  };

  return colors[status] ?? "#94a3b8";
}

function App() {
  const [keyId, setKeyId] = useState(COMPROMISED_KEY);
  const [sessions, setSessions] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [maliciousTags, setMaliciousTags] = useState([]);
  const [rotation, setRotation] = useState(null);
  const [logLines, setLogLines] = useState([]);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [isRotating, setIsRotating] = useState(false);
  const [ownerApproval, setOwnerApproval] = useState(false);

  const impactedApps = useMemo(
    () => [...new Set(sessions.map((session) => session.app_name))],
    [sessions],
  );

  const highRiskSessions = useMemo(
    () => sessions.filter((session) => ["Critical", "High"].includes(session.severity)),
    [sessions],
  );

  const canRotate = notifications.length > 0 && ownerApproval && !rotation && !isRotating;

  const appendLog = (message, level = "INFO") => {
    const time = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    setLogLines((current) => [...current, { message, level, time }]);
  };

  const investigateKey = async () => {
    setIsInvestigating(true);
    setSessions([]);
    setNotifications([]);
    setMaliciousTags([]);
    setRotation(null);
    setOwnerApproval(false);
    setLogLines([]);

    appendLog(`Identity_API.Get_Active_Sessions(${keyId})`);
    const activeSessions = await Identity_API.Get_Active_Sessions(keyId);
    appendLog(`Found ${activeSessions.length} active sessions using the exposed key`, "OK");

    const enrichedSessions = [];
    const tags = [];

    for (const session of activeSessions) {
      appendLog(`Asset_Inventory_API.Check_IP_Context(${session.ip_address})`);
      const ip_context = await Asset_Inventory_API.Check_IP_Context(session.ip_address);

      appendLog(`Asset_Inventory_API.Get_App_Criticality(${session.app_name})`);
      const criticality = await Asset_Inventory_API.Get_App_Criticality(session.app_name);

      const enriched = {
        ...session,
        ip_context,
        criticality,
        severity: severityForSession({ ...session, ip_context, criticality }),
      };

      if (ip_context === "Unknown_External") {
        appendLog(`Identity_API.Tag_Session_As_Malicious(${session.session_id})`, "WARN");
        const tag = await Identity_API.Tag_Session_As_Malicious(session.session_id);
        tags.push(tag);
        enriched.honey_token_status = tag.status;
      }

      enrichedSessions.push(enriched);
      setSessions([...enrichedSessions]);
      setMaliciousTags([...tags]);
    }

    const appsToPrompt = [
      ...new Set(
        enrichedSessions
          .filter((session) => ["Critical", "High"].includes(session.severity))
          .map((session) => session.app_name),
      ),
    ];

    const prompts = [];

    for (const appName of appsToPrompt) {
      appendLog(`Notification_API.Prompt_App_Owner(${appName})`, "WARN");
      const prompt = await Notification_API.Prompt_App_Owner(appName);
      prompts.push(prompt);
      setNotifications([...prompts]);
    }

    if (prompts.length > 0) {
      appendLog("Rotation is queued behind owner approval because Rotate_Key is high impact", "WARN");
    } else {
      appendLog("No high-risk sessions found. Rotation prompt not required.", "OK");
    }

    setIsInvestigating(false);
  };

  const rotateKey = async () => {
    setIsRotating(true);
    appendLog(`Identity_API.Rotate_Key(${keyId})`, "WARN");
    const result = await Identity_API.Rotate_Key(keyId);
    setRotation(result);
    appendLog(`New key generated: ${result.new_key_id}`, "OK");
    appendLog(`Old key invalidated: ${result.old_key_id}`, "OK");
    setIsRotating(false);
  };

  return (
    <main className="shell">
      <section className="header">
        <div>
          <p className="eyebrow">Security Automation Console</p>
          <h1>Compromised Key Response</h1>
          <p className="subhead">
            Active-session triage with honey-token containment and owner-gated rotation.
          </p>
        </div>
        <div className="key-panel">
          <label htmlFor="keyId">Key ID</label>
          <input
            id="keyId"
            value={keyId}
            onChange={(event) => setKeyId(event.target.value)}
            disabled={isInvestigating || isRotating}
          />
        </div>
      </section>

      <section className="actions">
        <button onClick={investigateKey} disabled={isInvestigating || isRotating}>
          {isInvestigating ? "Investigating..." : "Investigate Active Sessions"}
        </button>
        <label className="approval">
          <input
            type="checkbox"
            checked={ownerApproval}
            onChange={(event) => setOwnerApproval(event.target.checked)}
            disabled={notifications.length === 0 || Boolean(rotation)}
          />
          App owner clicked Rotate Now
        </label>
        <button className="danger" onClick={rotateKey} disabled={!canRotate}>
          {isRotating ? "Rotating..." : "Rotate Key"}
        </button>
      </section>

      <section className="metrics" aria-label="Incident metrics">
        <Metric label="Active sessions" value={sessions.length} tone="#60a5fa" />
        <Metric label="High risk" value={highRiskSessions.length} tone="#f97373" />
        <Metric label="Honey-token routes" value={maliciousTags.length} tone="#a78bfa" />
        <Metric label="Owner prompts" value={notifications.length} tone="#facc15" />
      </section>

      <section className="grid">
        <Panel title="Session Triage">
          {sessions.length === 0 ? (
            <EmptyState text="Run an investigation to load active key sessions." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>IP Context</th>
                    <th>Application</th>
                    <th>Criticality</th>
                    <th>User Agent</th>
                    <th>Disposition</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.session_id}>
                      <td>
                        <strong>{session.session_id}</strong>
                        <span>{session.ip_address} - {session.last_seen}</span>
                      </td>
                      <td>{session.ip_context}</td>
                      <td>{session.app_name}</td>
                      <td>
                        {session.criticality} {criticalityLabel[session.criticality]}
                      </td>
                      <td>{session.user_agent}</td>
                      <td>
                        <Badge label={session.honey_token_status ? "Honey" : session.severity} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Control Plane">
          <div className="control-list">
            <ControlItem label="Impacted apps" value={impactedApps.join(", ") || "None yet"} />
            <ControlItem
              label="Owner prompts"
              value={
                notifications.length
                  ? notifications.map((notice) => `${notice.app_name} via ${notice.channel}`).join(", ")
                  : "Waiting for high-risk session detection"
              }
            />
            <ControlItem
              label="Rotation state"
              value={rotation ? `${rotation.status} at ${new Date(rotation.rotated_at).toLocaleTimeString()}` : "Not rotated"}
            />
            {rotation && (
              <div className="new-key">
                <span>New key</span>
                <code>{rotation.new_key_id}</code>
              </div>
            )}
          </div>
        </Panel>

        <Panel title="Execution Log" wide>
          <div className="terminal">
            {logLines.length === 0 ? (
              <span className="muted">Awaiting API workflow...</span>
            ) : (
              logLines.map((line, index) => (
                <div key={`${line.time}-${index}`}>
                  <span>{line.time}</span>
                  <b data-level={line.level}>[{line.level}]</b>
                  {line.message}
                </div>
              ))
            )}
          </div>
        </Panel>
      </section>
    </main>
  );
}

function Metric({ label, value, tone }) {
  return (
    <div className="metric" style={{ "--tone": tone }}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function Panel({ title, children, wide = false }) {
  return (
    <section className={wide ? "panel wide" : "panel"}>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function Badge({ label }) {
  return (
    <span className="badge" style={{ "--badge": statusColor(label) }}>
      {label}
    </span>
  );
}

function EmptyState({ text }) {
  return <div className="empty">{text}</div>;
}

function ControlItem({ label, value }) {
  return (
    <div className="control-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}


export default App;
