// Stand-in for admin.omniaxislabs.com /api/wazuh/alerts in the test stack.
// Records every request (headers and raw body) so the e2e test can verify
// signatures itself. GET /received returns them; DELETE /received clears.
import { createServer } from "node:http";

const received = [];
createServer((req, res) => {
  if (req.url === "/received" && req.method === "GET") {
    res.setHeader("content-type", "application/json");
    return res.end(JSON.stringify(received));
  }
  if (req.url === "/received" && req.method === "DELETE") {
    received.length = 0;
    return res.end("{}");
  }
  if (req.url === "/api/wazuh/alerts" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ headers: req.headers, body });
      res.statusCode = 202;
      res.end("{}");
    });
    return;
  }
  res.statusCode = 404;
  res.end("{}");
}).listen(9000, "0.0.0.0", () => console.log("mock portal on :9000"));
