// Minimal dev server: serves dist/ and mounts the gateway function at /api/*.
// Lets us drive the real app (with real auth, policy, audit) under a headless
// browser for visual QA, without the Netlify CLI.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import handler from "../netlify/functions/api.mts";

const DIST = new URL("../dist/", import.meta.url).pathname;
const PORT = Number(process.env.PORT || 8899);
const TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".json": "application/json",
};

const server = createServer(async (req, res) => {
  const url = `http://localhost:${PORT}${req.url}`;
  if (req.url.startsWith("/api/")) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const request = new Request(url, {
      method: req.method,
      headers: req.headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
    });
    const response = await handler(request, {});
    res.statusCode = response.status;
    response.headers.forEach((v, k) => {
      if (k !== "set-cookie") res.setHeader(k, v);
    });
    const sc = response.headers.getSetCookie?.() ?? [];
    if (sc.length) res.setHeader("set-cookie", sc);
    res.end(Buffer.from(await response.arrayBuffer()));
    return;
  }
  // static
  let path = req.url.split("?")[0];
  if (path === "/" || !extname(path)) path = "/index.html";
  try {
    const data = await readFile(join(DIST, path));
    res.setHeader("content-type", TYPES[extname(path)] || "application/octet-stream");
    res.end(data);
  } catch {
    res.statusCode = 404;
    res.end("not found");
  }
});

server.listen(PORT, () => console.log(`dev server on http://localhost:${PORT}`));
