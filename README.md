# Wireshark Web Traffic Investigation

## Overview

I captured and investigated HTTP traffic in an isolated virtual lab using Wireshark. I compared normal web access with a controlled sequence of requests resembling web-path probing, then corroborated the findings with Apache access logs.

The investigation identified five GET requests from one client over approximately 4.173 seconds. The home page returned HTTP 200, while four test paths returned HTTP 404.

This was a self-generated lab simulation, not a real security incident.

## Environment

- **Platform:** Oracle VirtualBox
- **Network:** Internal Network named `dos-lab`
- **Client:** Kali Linux — `192.168.77.10`
- **Web server:** Kali Linux clone — `192.168.77.20`
- **Capture interface:** `eth0` on the web server
- **Tools:** Wireshark 4.6.4, curl, and Apache
- **Investigation date:** October 20, 2026

## Investigation Questions

- What does a normal TCP and HTTP exchange look like?
- Which client generated the test requests?
- Which paths were requested, and how quickly?
- How did the server respond?
- Do the web server logs support the packet evidence?

## Normal Traffic Analysis

I generated a normal request from the client:

```bash
curl -I --max-time 5 http://192.168.77.20/
```

In Wireshark, I observed:

1. Client sends SYN.
2. Server responds with SYN-ACK.
3. Client sends ACK.
4. Client sends `HEAD / HTTP/1.1`.
5. Server responds with `HTTP/1.1 200 OK`.

Using Follow TCP Stream, I examined the request and response headers.

The request contained:

- **Host:** `192.168.77.20`
- **User-Agent:** `curl/8.19.0`

The response included `Content-Length: 10703`. Because the request used HEAD, this described the corresponding page size without transferring its HTML body.

## Controlled Probing Simulation

I started a fresh capture and generated five requests from the client:

```bash
for page in / /admin-check /backup-check /login-check /config-check; do
  curl -sS -o /dev/null --max-time 5 \
    -w "$page -> HTTP %{http_code}\n" \
    "http://192.168.77.20$page"
  sleep 1
done
```

Observed results:

- `/` — HTTP 200
- `/admin-check` — HTTP 404
- `/backup-check` — HTTP 404
- `/login-check` — HTTP 404
- `/config-check` — HTTP 404

The four test paths were selected to simulate requests for potentially interesting web resources.

## Wireshark Filters Used

### TCP traffic involving port 80

```text
tcp.port == 80
```

### HTTP requests from the client

```text
http.request && ip.src == 192.168.77.10
```

### HTTP 404 responses from the server

```text
http.response.code == 404 && ip.src == 192.168.77.20
```

I also used Follow TCP Stream to pair individual requests with their responses.

## Findings

### Source and Destination

The five requests originated from `192.168.77.10` and targeted `192.168.77.20` on TCP port 80.

### Timing

The request capture showed:

- **First request:** 0.000432746 seconds
- **Last request:** 4.173668021 seconds
- **Elapsed time:** 4.173235275 seconds

These are relative capture times, not clock times.

### Request Characteristics

The requests used GET and identified their User-Agent as `curl/8.19.0`.

The User-Agent is a client-supplied header. It supports describing the request but does not independently prove software identity or identify a person.

### Server Responses

The home page returned HTTP 200. All four test paths returned HTTP 404.

Following the `/admin-check` TCP stream directly paired:

```text
GET /admin-check HTTP/1.1
```

with:

```text
HTTP/1.1 404 Not Found
```

## Apache Log Corroboration

On the web server, I reviewed:

```bash
sudo tail -n 10 /var/log/apache2/access.log
```

I then isolated the test paths:

```bash
sudo grep -- '-check' /var/log/apache2/access.log
```

The logs confirmed:

- Client IP `192.168.77.10`
- All four `-check` paths
- HTTP 404 for each test path
- User-Agent `curl/8.19.0`

The displayed log entries placed the home-page GET at 17:33:10 and the four test-path requests at 17:33:11 through 17:33:14 on October 20, 2026, with timezone offset `-0400`.

The logs and packet evidence agreed on the source, paths, and response codes.

## Assessment

Several different paths requested by one client within a short period can be consistent with web probing.

In this case, the activity was an authorized simulation generated with a curl loop. The observed pattern alone would not establish malicious intent in a real investigation.

The reviewed evidence did not demonstrate successful compromise or access to the four requested test resources. HTTP 404 responses alone cannot establish that an entire server is secure.

## Suggested Follow-Up in a Real Investigation

These are proposed next steps, not actions performed in this lab:

- Check whether the source belongs to an authorized scanner or tester.
- Review a wider time window for additional requests.
- Look for successful responses to sensitive paths.
- Correlate with authentication, application, and endpoint logs.
- Evaluate alert thresholds against normal traffic before introducing blocking.

## Evidence Screenshots

1. `01-normal-http-traffic.png` — Normal TCP and HTTP exchange.
2. `02-normal-http-stream.png` — HEAD request and HTTP 200 response.
3. `03-tcp-handshake.png` — SYN, SYN-ACK, and ACK.
4. `04-web-probing-requests.png` — Five GET requests and their relative times.
5. `05-not-found-responses.png` — Four HTTP 404 responses.
6. `06-probing-http-stream.png` — A test request paired with its 404 response.
7. `07-apache-log-corroboration.png` — Matching Apache access-log entries.

## Capture Files

The following lab captures are available for download and analysis in Wireshark:

- [Normal HTTP capture](01-normal-http.pcapng)
- [Simulated web-probing capture](02-web-probing-retest.pcapng)

The normal-traffic screenshots include separate baseline requests. Their timestamps and client source ports may differ; they should not be treated as one identical TCP session.

## Limitations

- This was a small, controlled simulation with one client and one server.
- Four missing-page responses are insufficient to classify real traffic as malicious.
- The investigation used unencrypted HTTP; encrypted HTTPS payloads would not be readable in the same way without appropriate decryption material.
- Conclusions apply only to the traffic and log entries reviewed.
- The investigation did not include host forensics or a full compromise assessment.

## Skills Demonstrated

- Packet capture and display filtering
- TCP handshake analysis
- HTTP request and response inspection
- TCP stream reconstruction
- Source and destination identification
- Timeline analysis
- Packet-to-log correlation
- Evidence-based reporting

## What I Learned

A useful investigation combines packet details, timing, server responses, and logs rather than relying on one suspicious-looking request.

I also learned to separate observations from conclusions: repeated 404 responses can justify further investigation, but they do not prove malicious intent or successful compromise.
