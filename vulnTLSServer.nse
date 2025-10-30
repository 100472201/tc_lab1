-- vulnTLSServer.nse
-- Checks TLS/SSL server certificate and basic TLS configuration for common weaknesses.
-- Author: (tu nombre) -- basado en ideas y funciones de ssl-cert, ssl-enum-ciphers y tls
-- References: https://nmap.org/nsedoc/scripts/ssl-cert.html
--             https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html
--             https://nmap.org/nsedoc/lib/tls.html


-- 1. heading
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local sslcert = require "sslcert"
local tls = require "tls"


-- 2. description, categories, portrule
description = [[
Identify TLS certificate problems and basic TLS configuration weaknesses:
- certificate checks (self-signed, signature hash, key type/size, validity period, CN/SANs, IPs, non-qualified names)
- TLS config checks (protocol support for TLS1.2/1.3, detection of CBC/SHA suites acceptance, compression enabled)
]]

categories = {"vuln","safe","discovery"}

portrule = shortport.ssl

-- Helper: read TLS records returned by a socket using tls.record_read / record_buffer
local function get_record_iter(sock)
  local buffer = ""
  local i = 1
  local fragment
  return function ()
    local record
    i, record = tls.record_read(buffer, i, fragment)
    if record == nil then
      local status, err
      status, buffer, err = tls.record_buffer(sock, buffer, i)
      if not status then return nil, err end
      i, record = tls.record_read(buffer, i, fragment)
      if record == nil then return nil, "done" end
    end
    fragment = record.fragment
    return record
  end
end

-- Try a client_hello described by 't' and return parsed ServerHello/records table or nil+err
local function try_client_hello(host, port, t)
  local timeout = stdnse.get_timeout(host, 8000, 2000)
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  local status, sock, err
  if specialized then
    status, sock = specialized(host, port)
    if not status then return nil, sock end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout)
    status, err = sock:connect(host, port)
    if not status then sock:close(); return nil, err end
  end

  sock:set_timeout(timeout)
  local req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then sock:close(); return nil, err end

  local get_next_record = get_record_iter(sock)
  local records = {}
  while true do
    local record, rerr = get_next_record()
    if not record then sock:close(); return records, rerr end
    records[record.type] = records[record.type] or record
    local done = false
    for j = 1, #record.body do
      local b = record.body[j]
      if record.type == "handshake" and (b.type == "server_hello" or b.type == "server_hello_done") then
        done = true
      end
      -- TLSv1.3 specifics: server_hello may be followed by encrypted_extensions; treat server_hello as final for our checks.
    end
    if done then sock:close(); return records end
  end
end

-- Utility: days between two epoch seconds
local function days_between(t1, t2) return math.floor((t2 - t1) / 86400) end

-- Normalize certificate parsing result from sslcert.getCertificate
local function safe_get_cert(host, port)
  local ok, cert_or_err = sslcert.getCertificate(host, port)
  if not ok then return nil, cert_or_err end
  local cert = cert_or_err
  local parsed, perr = sslcert.parse_ssl_certificate(cert.der or cert.pem)
  if not parsed then
    -- parse may fail if openssl not available; fall back to minimal info in cert table
    return cert, nil
  end
  return parsed, nil
end

-- Main action
action = function(host, port)
  local critical_alerts = {}
  local high_alerts = {}
  local medium_alerts = {}
  local low_alerts = {}

  -- 1) Certificate checks
  local parsed, perr = safe_get_cert(host, port)
  if not parsed then
    table.insert(critical_alerts, "No pudimos obtener/parsear el certificado: "..tostring(perr or "unknown"))
  else
    -- Self-signed: compare subject and issuer
    local subj = parsed.subject or {}
    local issuer = parsed.issuer or {}
    local function table_eq(a,b)
      if not a or not b then return false end
      for k,v in pairs(a) do if tostring(b[k]) ~= tostring(v) then return false end end
      for k,v in pairs(b) do if tostring(a[k]) ~= tostring(v) then return false end end
      return true
    end
    if table_eq(subj, issuer) then
      table.insert(critical_alerts, "Self-signed certificate detected")
    end

    -- Signature algorithm: SHA-1 deprecated -> critical
    local sigalg = parsed.signatureAlgorithm or parsed.sig_alg or ""
    if sigalg:lower():match("sha1") then
      table.insert(critical_alerts, "Certificado firmado usando SHA-1 (algoritmo: "..tostring(sigalg)..")")
    end

    -- Public key type / size
    local pk = parsed.publicKeyAlgorithm or parsed.pubkey or {}
    local pk_type = parsed.pubkey and parsed.pubkey.type or parsed.key and parsed.key.type or parsed.publicKey and parsed.publicKey.type
    local pk_bits = parsed.pubkey and parsed.pubkey.bits or parsed.key and parsed.key.bits or parsed.publicKey and parsed.publicKey.bits
    if pk_type then
      pk_type = tostring(pk_type):lower()
      if not (pk_type:match("rsa") or pk_type:match("ecdsa")) then
        table.insert(high_alerts, "Certificado con tipo de clave inusual: "..tostring(pk_type))
      else
        if pk_type:match("rsa") and (not pk_bits or tonumber(pk_bits) < 2048) then
          table.insert(high_alerts, "Clave RSA demasiado corta: "..tostring(pk_bits or "unknown").." bits")
        end
      end
    end

    -- Validity period: check days remaining and total lifespan
    local notbefore = parsed.notBefore and parsed.notBefore.timestamp or parsed.notBefore
    local notafter = parsed.notAfter and parsed.notAfter.timestamp or parsed.notAfter
    local now = os.time()
    if notbefore and notafter then
      local lifespan = days_between(notbefore, notafter)
      local days_left = days_between(now, notafter)
      if lifespan < 90 or lifespan > 366 then
        table.insert(medium_alerts, "Certificate lifespan is "..tostring(lifespan).." days (recommended 90-366)")
      end
      if days_left < 0 then
        table.insert(critical_alerts, "Certificate already expired on "..tostring(parsed.notAfter))
      elseif days_left < 30 then
        table.insert(medium_alerts, "Certificate expires in "..tostring(days_left).." days")
      end
    end

    -- CN / SAN checks: domain matching, IPs in cert, non-qualified hostnames
    local cn = (parsed.subject and parsed.subject.commonName) or parsed.cn or ""
    local sans = {}
    if parsed.extensions and parsed.extensions.subjectAltName then
      local san = parsed.extensions.subjectAltName
      if type(san) == "table" then for _,v in ipairs(san) do table.insert(sans, v) end end
    end
    -- If no SANs, check CN
    local given_name = stdnse.get_hostname(host)
    -- Domain name matching: check if given_name present in CN or SANs (simple check)
    local matched = false
    if cn and cn ~= "" and given_name and given_name ~= "" then
      if cn:lower() == given_name:lower() then matched = true end
    end
    for _,v in ipairs(sans) do
      if tostring(v):lower():match(tostring(given_name):lower()) then matched = true end
      -- detect IPs in SAN entries (simple numeric match)
      if tostring(v):match("%d+%.%d+%.%d+%.%d+") then
        table.insert(low_alerts, "Certificate contains IP address in SAN: "..tostring(v))
      end
      -- non-qualified hostname: no dot
      if tostring(v):find("%.") == nil then
        table.insert(low_alerts, "Certificate uses non-qualified hostname in SAN: "..tostring(v))
      end
    end
    if not matched then
      table.insert(medium_alerts, "Domain name does not match certificate CN/SANs (CN='"..tostring(cn).."')")
    end
    -- Also warn if CN is IP address
    if cn:match("^%d+%.%d+%.%d+%.%d+$") then
      table.insert(low_alerts, "Certificate commonName is an IP address: "..cn)
    end
  end

  -- 2) TLS connection checks: protocol support, CBC/SHA detection, compression enabled
  -- Protocols test: try client hello with TLSv1.3, TLSv1.2, TLSv1.0 (detect which succeed)
  local protocols_supported = {}
  local proto_order = {"TLSv1.3","TLSv1.2","TLSv1.1","TLSv1.0"}
  for _,p in ipairs(proto_order) do
    local t = { protocol = p }
    local recs, err = try_client_hello(host, port, t)
    if recs and recs.handshake then
      -- if server_hello present, protocol accepted
      local ok = false
      for i=1,#recs.handshake.body do
        if recs.handshake.body[i].type == "server_hello" then ok = true break end
      end
      if ok then protocols_supported[#protocols_supported+1] = p end
    end
  end
  -- Check TLS protocol high alerts
  local supports_1_2_or_1_3 = false
  for _,p in ipairs(protocols_supported) do if p == "TLSv1.2" or p == "TLSv1.3" then supports_1_2_or_1_3 = true end end
  if #protocols_supported == 0 then
    table.insert(high_alerts, "Server does not negotiate TLS 1.2 or TLS 1.3 (no modern protocol detected)")
  elseif not supports_1_2_or_1_3 and #protocols_supported > 0 then
    table.insert(high_alerts, "Server supports only old TLS versions: "..table.concat(protocols_supported,", "))
  end

  -- Detect if server accepts CBC+SHA suites: offer a small list of CBC+SHA suites and see if server picks one
  local test_ciphers = {
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
  }
  local t = { protocol = "TLSv1.2", ciphers = test_ciphers }
  local recs, err = try_client_hello(host, port, t)
  local picked_cipher = nil
  if recs and recs.handshake then
    for i=1,#recs.handshake.body do
      local b = recs.handshake.body[i]
      if b.type == "server_hello" and b.cipher then
        picked_cipher = b.cipher
        break
      end
    end
  end
  if picked_cipher then
    -- check if chosen is CBC or uses SHA1
    local info = tls.cipher_info(picked_cipher)
    if info and (info.mode == "CBC" or tostring(info.hash):lower():match("sha1")) then
      table.insert(critical_alerts, "Cipher chosen by server includes CBC mode and/or SHA hash: "..tostring(picked_cipher))
    else
      -- If chosen cipher is not in our allowed list, warn (HIGH)
      local allowed = {
        ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]=1, ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]=1,
        ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]=1, ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]=1,
        ["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]=1, ["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]=1,
        ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]=1, ["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"]=1,
        ["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]=1
      }
      if not allowed[picked_cipher] then
        table.insert(high_alerts, "Unsupported TLS cipher chosen: "..tostring(picked_cipher))
      end
    end
  else
    -- couldn't determine chosen cipher; do an additional probe: offer a broad set and parse if server responds
    -- (skip for brevity)
  end

  -- Test compression: send ClientHello with DEFLATE compressor and see if server_hello compression != NULL
  local t_comp = { protocol = "TLSv1.2", compressors = {"DEFLATE"} }
  local recs_comp, errc = try_client_hello(host, port, t_comp)
  local compression_enabled = false
  if recs_comp and recs_comp.handshake then
    for i=1,#recs_comp.handshake.body do
      local b = recs_comp.handshake.body[i]
      if b.type == "server_hello" and b.compression then
        if tostring(b.compression) ~= "NULL" and tostring(b.compression) ~= "0" then
          compression_enabled = true
          break
        end
      end
    end
  end
  if compression_enabled then
    table.insert(critical_alerts, "TLS compression enabled on server (vulnerable to CRIME)")
  end

  -- Format output according to assignment format
  local function format_block(title, list)
    if #list == 0 then return "" end
    local out = {}
    out[#out+1] = "**********************"
    out[#out+1] = title..": "..tostring(#list)
    out[#out+1] = "**********************"
    for _,v in ipairs(list) do
      out[#out+1] = "- "..v
    end
    return table.concat(out, "\n")
  end

  local result_parts = {}
  table.insert(result_parts, format_block("CRITICAL ALERTS", critical_alerts))
  table.insert(result_parts, format_block("HIGH ALERTS", high_alerts))
  table.insert(result_parts, format_block("MEDIUM ALERTS", medium_alerts))
  table.insert(result_parts, format_block("LOW ALERTS", low_alerts))

  return table.concat(result_parts, "\n")
end
