-- vulnTLSServer.nse
-- Checks TLS/SSL server certificate for common weaknesses.
-- Author: (your name)

local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local sslcert = require "sslcert"
local datetime = require "datetime"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
Identify TLS certificate problems:
- Self-signed certificates
- CBC and/or SHA Support
- Enable Compression 
- Certificate Type
- Validity period issues
- Domain name mismatches
- Non-qualified names and IPs in certificates
]]

categories = {"safe", "discovery"}

portrule = shortport.port_or_service({443, 8443, 9443}, {"https", "https-alt", "ssl"})

-- From ssl-cert.nse
function stringify_name(name)
  local fields = {}
  local k, v
  if not name then
    return nil
  end
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    fields[#fields + 1] = string.format("%s=%s", k, v or '')
  end
  return table.concat(fields, "/")
end

action = function(host, port)
  local alerts = {
    critical = {},
    high = {},
    medium = {},
    low = {}
  }

  local target_name = host.name or tls.servername(host) or host.targetname or host.ip
  host.targetname = target_name

  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  -- CRITICAL ALERTS (3)

  -- 1. Check for self-signed certificate
    -- Self-signed check: compare subject/issuer fields key-by-key (robusto contra orden)
  local function is_self_signed(subject, issuer)
    local keys = {}
    for k,_ in pairs(subject or {}) do keys[k] = true end
    for k,_ in pairs(issuer or {}) do keys[k] = true end
    for k,_ in pairs(keys) do
      local s = subject[k] or ""
      local i = issuer[k] or ""
      if s ~= i then
        return false
      end
    end
    return true
  end

  if is_self_signed(cert.subject, cert.issuer) then
    table.insert(alerts.critical, "Self-Signed Certificate. The certificate is self-signed.")
  end

  -- 2. Check for CBC and SHA-1 in certificate signature (later on)  

  -- 3. Check for compression support
  local sock_compress = nmap.new_socket()
  sock_compress:set_timeout(5000)
  local status_compress, err_compress = sock_compress:connect(host, port)
  if status_compress then
    local status_hello, server_hello = tls.client_hello(sock_compress, nil, nil, { "DEFLATE" })
    if status_hello and type(server_hello) == "table" and server_hello.compression_method and server_hello.compression_method == "DEFLATE" then
      table.insert(alerts.critical, "Enable Compression. TLS compression must be disabled to protect against the CRIME vulnerability, which could allow attackers to recover sensitive information such as session cookies.")
    end
    sock_compress:close()
  end


  -- HIGH ALERTS (3)

  -- 1. Check for certificate type
  if cert.pubkey.type == "rsa" then
    if cert.pubkey.bits < 2048 then
      table.insert(alerts.high, string.format("Weak Key. The certificate's public key is weak: %s bits %s.", cert.pubkey.bits, cert.pubkey.type))
    end
  elseif cert.pubkey.type == "ec" then
    if cert.pubkey.ecdhparams.curve_params.curve ~= "secp256r1" then
      table.insert(alerts.high, string.format("Weak Key. The certificate's public key is weak: %s curve.", cert.pubkey.ecdhparams.curve_params.curve))
    end
  else
    table.insert(alerts.high, string.format("Unsupported Key Type. The certificate's public key type is not supported: %s.", cert.pubkey.type))
  end

  -- 2. Check for supported protocols
  local supported_protocols = {}
  local protocols_to_check = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"}
  for _, proto in ipairs(protocols_to_check) do
    local sock = nmap.new_socket()
    sock:set_timeout(3000)
    local ok = sock:connect(host, port)
    if ok then
      local status_hello = false
      -- try sending client hello for this specific protocol
      local ok_hello, _ = tls.client_hello(sock, proto)
      if ok_hello then
        table.insert(supported_protocols, proto)
      end
      sock:close()
    end
  end

  local has_tls1_3 = false
  local has_tls1_2 = false
  local has_tls1_1 = false
  local has_tls1_0 = false
  for _, proto in ipairs(supported_protocols) do
    if proto == "TLSv1.3" then has_tls1_3 = true end
    if proto == "TLSv1.2" then has_tls1_2 = true end
    if proto == "TLSv1.1" then has_tls1_1 = true end
    if proto == "TLSv1.0" then has_tls1_0 = true end
  end

    -- Raise HIGH only if server does NOT support TLS 1.2/1.3 but DOES support older versions.
  if not has_tls1_2 and not has_tls1_3 and (has_tls1_1 or has_tls1_0) then
    table.insert(alerts.high, "Outdated TLS Support. The server does not support TLS 1.2 or TLS 1.3 but supports older protocols: " .. table.concat(supported_protocols, ", "))
  end

  -- 3. Check for weak cipher suites
    -- 3. Check for cipher suites (use ssl-enum-ciphers output when present, group alerts)
  local function normalize_cipher(name)
    return (name or ""):upper():gsub("%-", "_"):gsub("%s+", "")
  end

  local recommended_ciphers = {
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305"
  }
  local recommended_lookup = {}
  for _, c in ipairs(recommended_ciphers) do
    recommended_lookup[normalize_cipher(c)] = true
  end

  -- map cipher_name -> set of protocols where found
  local cipher_protocols = {}

  -- helper to record a cipher was seen under a protocol
  local function record_cipher(proto, name)
    if not name then return end
    local n = name
    if not cipher_protocols[n] then cipher_protocols[n] = {} end
    cipher_protocols[n][proto] = true
  end

  -- 1) Prefer data from ssl-enum-ciphers: port.version.service_data
  if port.version and port.version.service_data then
    local sd = port.version.service_data
    -- compressors check (critical if anything other than NULL)
    if sd.compressors and type(sd.compressors) == "table" then
      for _, comp in ipairs(sd.compressors) do
        if comp and comp ~= "NULL" and comp ~= "null" then
          table.insert(alerts.critical, "Enable Compression. TLS compression is enabled on the server (compressor: " .. tostring(comp) .. ").")
        end
      end
    end

    -- ssl-enum-ciphers may present a table keyed by protocol or an array of tables
    if sd.ciphers then
      -- sd.ciphers may be array of tables with fields 'protocol' and 'ciphers' OR simple array of cipher entries
      for _, entry in ipairs(sd.ciphers) do
        if type(entry) == "table" and entry.protocol and entry.ciphers then
          -- entry.ciphers is list of tables with .name
          for _, c in ipairs(entry.ciphers) do
            if type(c) == "table" and c.name then
              record_cipher(entry.protocol, c.name)
            elseif type(c) == "string" then
              record_cipher(entry.protocol, c)
            end
          end
        elseif type(entry) == "table" and entry.name and entry.protocol then
          -- sometimes single cipher entries
          record_cipher(entry.protocol, entry.name)
        elseif type(entry) == "string" then
          -- unknown protocol context, mark under "UNKNOWN"
          record_cipher("UNKNOWN", entry)
        end
      end
    end
  end

  -- 3) Final fallback: probe a short set of well-known CBC/legacy ciphers (try multiple client_hello signatures)
  if next(cipher_protocols) == nil then
    local fallback_probe = {
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_256_CBC_SHA",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    }
    for _, probe in ipairs(fallback_probe) do
      local sock = nmap.new_socket()
      sock:set_timeout(3000)
      local ok = sock:connect(host, port)
      if ok then
        local accepted = false
        -- try multiple calling conventions for tls.client_hello (some NSE versions differ)
        local succ, res = pcall(function() return tls.client_hello(sock, nil, {probe}) end)
        if succ and res then accepted = true end
        if not accepted then
          succ, res = pcall(function() return tls.client_hello(sock, nil, nil, {probe}) end)
          if succ and res then accepted = true end
        end
        if not accepted then
          succ, res = pcall(function() return tls.client_hello(sock, probe) end)
          if succ and res then accepted = true end
        end
        if accepted then record_cipher("PROBED", probe) end
        sock:close()
      end
    end
  end

  -- If still empty, note that we couldn't enumerate ciphers
  if next(cipher_protocols) == nil then
    stdnse.debug1("vulnTLSServer: could not enumerate cipher suites (no port.version data, sslcert.getCipherSuites failed, and probes found nothing)")
  end

  -- group results
  local cbc_set = {}
  local sha_set = {}
  local nonrec_set = {}

  for cipher_name, protos in pairs(cipher_protocols) do
    local norm = normalize_cipher(cipher_name)
    -- detect CBC
    if string.find(norm, "CBC") then
      cbc_set[cipher_name] = protos
    end
    -- detect SHA-1 / legacy _SHA
    if string.find(norm, "SHA1") or (string.find(norm, "_SHA") and
       not (string.find(norm, "SHA256") or string.find(norm, "SHA384") or string.find(norm, "SHA512") or string.find(norm, "SHA224"))) then
      sha_set[cipher_name] = protos
    end
    -- detect not-in-recommendation (HIGH) — only if not already in recommended list
    if not recommended_lookup[norm] then
      nonrec_set[cipher_name] = protos
    end
  end

  -- remove from nonrec_set any cipher that is already in cbc_set or sha_set (we want critical to cover them)
  for c,_ in pairs(cbc_set) do nonrec_set[c] = nil end
  for c,_ in pairs(sha_set) do nonrec_set[c] = nil end

  -- prepare human readable helpers to show protocols per cipher
  local function proto_list(set)
    local out = {}
    for c, protos in pairs(set) do
      local p = {}
      for pr,_ in pairs(protos) do table.insert(p, pr) end
      table.sort(p)
      table.insert(out, string.format("%s (in: %s)", c, table.concat(p, ", ")))
    end
    table.sort(out)
    return out
  end

  -- emit grouped alerts
  if next(cbc_set) then
    table.insert(alerts.critical, "Cipher includes CBC mode: " .. table.concat(proto_list(cbc_set), "; "))
  end
  if next(sha_set) then
    table.insert(alerts.critical, "Cipher uses SHA-1 or legacy SHA: " .. table.concat(proto_list(sha_set), "; "))
  end
  if next(nonrec_set) then
    table.insert(alerts.high, "Unsupported TLS cipher(s) not in recommended list: " .. table.concat(proto_list(nonrec_set), "; "))
  end


  -- MEDIUM ALERTS
  
  -- 1. Certificate Lifespan: Check validity
  local now = os.time()
  local notBefore = os.time(cert.validity.notBefore)
  local notAfter = os.time(cert.validity.notAfter)

  if now < notBefore then
    table.insert(alerts.high, "Invalid Certificate. The certificate is not yet valid.")
  end
  if now > notAfter then
    table.insert(alerts.high, "Expired Certificate. The certificate has expired.")
  end

  local lifespan_days = (notAfter - notBefore) / (60 * 60 * 24)
  if lifespan_days < 90 then
    table.insert(alerts.medium, string.format("Short Certificate Lifespan. The certificate lifespan is too short: %.0f days (less than 90 days).", lifespan_days))
  end
  if lifespan_days > 366 then
    table.insert(alerts.medium, string.format("Long Certificate Lifespan. The certificate lifespan is too long: %.0f days (more than 366 days).", lifespan_days))
  end

  -- 2. Check for domain name mismatch
  local common_name = cert.subject.commonName
  local subject_alt_names = {}
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        for name in string.gmatch(e.value, "DNS:([^,]+)") do
          table.insert(subject_alt_names, name)
        end
      end
    end
  end

  local matches_cn = (common_name and host.targetname:match(common_name:gsub("*", ".*")))
  local matches_san = false
  for _, san in ipairs(subject_alt_names) do
    if host.targetname:match(san:gsub("*", ".*")) then
      matches_san = true
      break
    end
  end

  if not matches_cn and not matches_san then
    table.insert(alerts.medium, string.format("Domain Name Mismatch. The domain name %s does not match the common name %s or any of the subject alternative names.", host.targetname, common_name))
  end

  -- LOW ALERTS

  -- 1. Check for non-qualified hostnames and IP addresses in certificate
  local names_to_check = {}
  if common_name then
    table.insert(names_to_check, common_name)
  end
  for _, san in ipairs(subject_alt_names) do
    table.insert(names_to_check, san)
  end

  for _, name in ipairs(names_to_check) do
    if not string.find(name, "%.") then
      table.insert(alerts.low, string.format("Non-Qualified Hostname. The certificate contains a non-qualified hostname: %s.", name))
    end
    if string.match(name, "^%d+.%d+.%d+.%d+$") then
      table.insert(alerts.low, string.format("IP Address in Certificate. The certificate contains an IP address: %s.", name))
    end
  end
  local output_lines = {}
  local severities = {"critical", "high", "medium", "low"}

  for _, severity in ipairs(severities) do
    if alerts[severity] and #alerts[severity] > 0 then
      table.insert(output_lines, "**********************")
      table.insert(output_lines, string.format("%s ALERTS: %d", string.upper(severity), #alerts[severity]))
      table.insert(output_lines, "**********************")
      for _, msg in ipairs(alerts[severity]) do
        table.insert(output_lines, "- " .. msg)
      end
      table.insert(output_lines, "**********************")
    end
  end

  if #output_lines > 0 then
    return table.concat(output_lines, "\n")
  else
    return nil
  end
end
