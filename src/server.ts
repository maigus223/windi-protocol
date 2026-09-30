// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import { createServer, type Server } from "node:http";
import { Gateway } from "./gateway.js";

/** Minimal node:http adapter. Real deployments should sit behind TLS and a reverse proxy. */
export function createGatewayServer(gateway: Gateway): Server {
  return createServer((req, res) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 16 * 1024) {
        res.writeHead(413).end();
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      let body: unknown;
      if (chunks.length > 0) {
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          res.writeHead(400, { "content-type": "application/problem+json" });
          res.end(JSON.stringify({ title: "Invalid JSON", status: 400 }));
          return;
        }
      }
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string") headers[k.toLowerCase()] = v;
      }
      const url = new URL(req.url ?? "/", "http://placeholder");
      const out = gateway.handle({
        method: req.method ?? "GET",
        path: url.pathname,
        authority: headers["host"] ?? "",
        headers,
        body,
        remoteAddress: req.socket.remoteAddress,
      });
      res.writeHead(out.status, out.headers);
      res.end(JSON.stringify(out.body));
    });
  });
}
