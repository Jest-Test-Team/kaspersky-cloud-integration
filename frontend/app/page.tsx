"use client";

import { FormEvent, useEffect, useState } from "react";

type Status = {
  intelligenceConfigured: boolean;
  intelligenceBaseUrl: string;
  supportedOperations: EndpointDescriptor[];
  cloudConsoleApi: string;
};

type EndpointDescriptor = {
  name: string;
  method: string;
  upstreamPath: string;
  applicationPath: string;
  input: string;
};

type LookupResponse = {
  type: string;
  indicator: string;
  result: Record<string, unknown>;
};

type KscOperation = {
  name: string;
  class: string;
  method: string;
  applicationPath: string;
  description: string;
};

type KscStatus = {
  product: string;
  baseUrl: string;
  configured: boolean;
  transport: string;
  operations: KscOperation[];
};

type KscQuery = { label: string; path: string };

const kscQueries: KscQuery[] = [
  { label: "Server info", path: "/api/ksc/server-info" },
  { label: "Groups", path: "/api/ksc/groups" },
  { label: "Hosts", path: "/api/ksc/hosts" },
  { label: "Licenses", path: "/api/ksc/licenses" },
];

const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

function extractVerdict(result: Record<string, unknown>) {
  const zone = result.Zone ?? result.zone;
  const status = result.FileStatus ?? result.Status ?? result.status;
  const general = (result.DomainGeneralInfo ?? result.IpGeneralInfo ?? result.UrlGeneralInfo) as Record<string, unknown> | undefined;
  const categories = Array.isArray(general?.Categories) ? general.Categories : [];
  const summary = categories.length > 0
    ? `${categories.length} categories · reputation ${String(zone ?? "unknown").toLowerCase()}`
    : `Kaspersky reputation: ${String(zone ?? "unknown").toLowerCase()}`;
  return { zone: typeof zone === "string" ? zone : "Unknown", status: typeof status === "string" ? status : summary };
}

export default function Home() {
  const [status, setStatus] = useState<Status | null>(null);
  const [indicator, setIndicator] = useState("");
  const [lookup, setLookup] = useState<LookupResponse | null>(null);
  const [fileResult, setFileResult] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [kscStatus, setKscStatus] = useState<KscStatus | null>(null);
  const [kscResult, setKscResult] = useState("");
  const [kscBusy, setKscBusy] = useState("");

  useEffect(() => {
    fetch(`${apiBase}/api/integrations/status`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`Backend returned ${response.status}`);
        return response.json();
      })
      .then(setStatus)
      .catch((err: Error) => setError(err.message));

    fetch(`${apiBase}/api/ksc/status`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`Backend returned ${response.status}`);
        return response.json();
      })
      .then(setKscStatus)
      .catch(() => undefined);
  }, []);

  async function runKscQuery(query: KscQuery) {
    setKscBusy(query.path);
    setKscResult("");
    try {
      const response = await fetch(`${apiBase}${query.path}`);
      const data = await response.json();
      setKscResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setKscResult(err instanceof Error ? err.message : "KSC request failed");
    } finally {
      setKscBusy("");
    }
  }

  async function parseResponse(response: Response) {
    const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? `Request failed with ${response.status}`);
    return data;
  }

  async function submitLookup(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setLookup(null);
    try {
      const response = await fetch(`${apiBase}/api/intelligence/lookup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator }),
      });
      setLookup(await parseResponse(response));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Lookup failed");
    } finally {
      setLoading(false);
    }
  }

  async function submitFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setLoading(true);
    setError("");
    setFileResult("");
    try {
      const response = await fetch(`${apiBase}/api/intelligence/file/scan`, { method: "POST", body: form });
      setFileResult(JSON.stringify(await parseResponse(response), null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : "File analysis failed");
    } finally {
      setLoading(false);
    }
  }

  const verdict = lookup ? extractVerdict(lookup.result) : null;

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Kaspersky security integration</p>
          <h1>Kaspersky cloud intelligence, without on-prem APIs.</h1>
          <p className="lede">Every officially documented basic-token operation for Kaspersky Threat Intelligence Portal, with credentials held only by the backend.</p>
        </div>
        <div className="statusCard">
          <StatusRow label="Threat Intelligence" ready={status?.intelligenceConfigured} />
          <StatusRow label="Security Center Open API" ready={kscStatus?.configured} />
          <span className="consoleUrl">{kscStatus?.baseUrl ?? status?.cloudConsoleApi ?? "Connecting to backend…"}</span>
        </div>
      </header>

      {error ? <div className="error">{error}</div> : null}

      <section className="lookupCard">
        <div className="sectionHeading">
          <div>
            <span className="priority">Priority 01</span>
            <h2>Threat Intelligence lookup</h2>
          </div>
          <span className="types">HASH · IPv4 · DOMAIN · URL</span>
        </div>
        <form className="lookupForm" onSubmit={submitLookup}>
          <input aria-label="Threat indicator" placeholder="Paste an indicator of compromise" value={indicator} onChange={(event) => setIndicator(event.target.value)} />
          <button disabled={loading || !indicator.trim()}>{loading ? "Checking…" : "Investigate"}</button>
        </form>
        {!status?.intelligenceConfigured && status ? <p className="configurationNote">Set <code>KASPERSKY_TIP_API_KEY</code> on the backend to enable live lookups.</p> : null}

        {lookup && verdict ? (
          <div className="resultGrid">
            <div className={`verdict zone-${verdict.zone.toLowerCase()}`}>
              <span>{lookup.type}</span>
              <strong>{verdict.zone}</strong>
              <p>{verdict.status}</p>
              <code>{lookup.indicator}</code>
            </div>
            <pre>{JSON.stringify(lookup.result, null, 2)}</pre>
          </div>
        ) : (
          <div className="emptyState">Official Kaspersky enrichment results will appear here.</div>
        )}
      </section>

      <section className="integrationCard">
        <div className="sectionHeading">
          <div>
            <span className="priority">Threat Intelligence · Sandbox</span>
            <h2>File analysis</h2>
          </div>
          <span className="types">SCAN FILE · 256 MiB MAX</span>
        </div>
        <p className="configurationNote">Submitted files are transferred to Kaspersky for analysis. Do not upload confidential material.</p>
        <form className="fileForm" onSubmit={submitFile}>
          <input aria-label="File for analysis" type="file" name="file" required />
          <button disabled={loading || !status?.intelligenceConfigured}>Submit to Sandbox</button>
        </form>
        {fileResult ? <pre className="integrationResponse">{fileResult}</pre> : null}
      </section>

      <section className="integrationCard">
        <div className="sectionHeading">
          <div>
            <span className="priority">Official API catalog</span>
            <h2>All published cloud endpoints</h2>
          </div>
          <span className="types">{status?.supportedOperations.length ?? 6} ENDPOINTS</span>
        </div>
        <div className="endpointTable">
          {(status?.supportedOperations ?? []).map((endpoint) => (
            <div className="endpointRow" key={endpoint.upstreamPath}>
              <strong>{endpoint.name}</strong>
              <code>{endpoint.method} {endpoint.upstreamPath}</code>
              <span>{endpoint.input}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="integrationCard">
        <div className="sectionHeading">
          <div>
            <span className="priority">Kaspersky Security Center 15.2</span>
            <h2>Administration Server Open API</h2>
          </div>
          <span className="types">{kscStatus?.operations.length ?? 0} OPERATIONS</span>
        </div>
        <p className="configurationNote">{kscStatus?.transport ?? "HTTP+JSON over /api/v1.0/Class.Method"}</p>
        {!kscStatus?.configured && kscStatus ? (
          <p className="configurationNote">Set <code>KSC_AUTHORIZATION</code> or <code>KSC_SESSION</code> on the backend to enable live calls.</p>
        ) : null}

        <div className="lookupForm">
          {kscQueries.map((query) => (
            <button key={query.path} onClick={() => runKscQuery(query)} disabled={kscBusy !== "" || !kscStatus}>
              {kscBusy === query.path ? "Loading…" : query.label}
            </button>
          ))}
        </div>

        {kscResult ? <pre className="integrationResponse">{kscResult}</pre> : (
          <div className="emptyState">Choose a Security Center query to call the Administration Server.</div>
        )}

        <div className="endpointTable">
          {(kscStatus?.operations ?? []).map((op) => (
            <div className="endpointRow" key={op.applicationPath}>
              <strong>{op.name}</strong>
              <code>{op.class === "*" ? op.applicationPath : `${op.class}.${op.method}`}</code>
              <span>{op.description}</span>
            </div>
          ))}
        </div>
        <a className="documentationLink" href="https://support.kaspersky.com/help/KSC/15.2/KSCAPI/" target="_blank" rel="noreferrer">KSC 15.2 Open API reference</a>
      </section>
    </main>
  );
}

function StatusRow({ label, ready }: { label: string; ready?: boolean }) {
  return <div className="statusRow"><span className={ready ? "dot ready" : "dot"} /><strong>{label}</strong><em>{ready ? "Configured" : "Needs credential"}</em></div>;
}
