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
  for _, c in ipairs(recommended_ciphers) do recommended_lookup[normalize_cipher(c)] = true end

  -- A reasonably broad probe list. Add/remove entries if you want to speed up or broaden detection.
  local probe_ciphers = {
    -- CBC / legacy (we want to catch these as critical)
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_RSA_WITH_SEED_CBC_SHA",
    -- SHA1-legacy markers (many overlap with CBC above)
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    -- Modern / recommended
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305",
    -- Other commonly-seen (not recommended)
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    -- Extra legacy / odd
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
  }

  -- storage for accepted ciphers
  local accepted = {}

  -- helper to try multiple tls.client_hello call signatures for compatibility
  local function try_cipher_probe(host, port, cipher_name, timeout_ms)
    timeout_ms = timeout_ms or 3000
    local sock = nmap.new_socket()
    sock:set_timeout(timeout_ms)
    local ok_conn, conn_err = sock:connect(host, port)
    if not ok_conn then
      sock:close()
      return false
    end

    local accepted_flag = false

    -- Try signature A: tls.client_hello(sock, nil, {cipher})
    local succ, res = pcall(function() return tls.client_hello(sock, nil, {cipher_name}) end)
    if succ and res then accepted_flag = true end

    -- Try signature B: tls.client_hello(sock, nil, nil, {cipher})
    if not accepted_flag then
      succ, res = pcall(function() return tls.client_hello(sock, nil, nil, {cipher_name}) end)
      if succ and res then accepted_flag = true end
    end

    -- Try signature C: tls.client_hello(sock, cipher) (older variants)
    if not accepted_flag then
      succ, res = pcall(function() return tls.client_hello(sock, cipher_name) end)
      if succ and res then accepted_flag = true end
    end

    -- Ensure socket closed
    pcall(function() sock:close() end)
    return accepted_flag
  end

  -- Probe each cipher (parallelizing would be nicer but keep it simple & safe)
  for _, c in ipairs(probe_ciphers) do
    local ok = false
    -- protect each probe from errors
    local succ, res = pcall(function() return try_cipher_probe(host, port, c, 2000) end)
    if succ and res then ok = true end
    if ok then
      accepted[c] = true
    end
  end

  -- If we found none, we can still try a smaller focused list of legacy ciphers to force detection
  if next(accepted) == nil then
    local short_probe = {
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    }
    for _, c in ipairs(short_probe) do
      local succ, res = pcall(function() return try_cipher_probe(host, port, c, 2000) end)
      if succ and res then accepted[c] = true end
    end
  end

  -- Analyze accepted ciphers and create grouped alerts
  local cbc_list = {}
  local sha_list = {}
  local nonrec_list = {}

  for cipher_name, _ in pairs(accepted) do
    local norm = normalize_cipher(cipher_name)

    -- CBC => CRITICAL
    if string.find(norm, "CBC") then table.insert(cbc_list, cipher_name) end

    -- SHA-1 or legacy _SHA => CRITICAL
    if string.find(norm, "SHA1") or (string.find(norm, "_SHA") and
       not (string.find(norm, "SHA256") or string.find(norm, "SHA384") or string.find(norm, "SHA512") or string.find(norm, "SHA224"))) then
      table.insert(sha_list, cipher_name)
    end

    -- HIGH if not in recommended list (but we will remove those already counted as critical later)
    if not recommended_lookup[norm] then
      table.insert(nonrec_list, cipher_name)
    end
  end

  -- remove critical items from nonrec_list
  local critical_map = {}
  for _, c in ipairs(cbc_list) do critical_map[c] = true end
  for _, c in ipairs(sha_list) do critical_map[c] = true end
  local filtered_nonrec = {}
  local seen_nr = {}
  for _, c in ipairs(nonrec_list) do
    if not critical_map[c] and not seen_nr[c] then
      table.insert(filtered_nonrec, c)
      seen_nr[c] = true
    end
  end

  -- add grouped alerts (use add_alert helper if you have it; else use table.insert(alerts.X,...))
  local function add_alert(level, msg)
    if not level or not msg then return end
    if not alerts[level] then alerts[level] = {} end
    -- prevent duplicates
    for _, v in ipairs(alerts[level]) do if v == msg then return end end
    table.insert(alerts[level], msg)
  end

  if #cbc_list > 0 then
    add_alert("critical", string.format("Cipher includes CBC mode: %s", table.concat(cbc_list, ", ")))
  end
  if #sha_list > 0 then
    add_alert("critical", string.format("Cipher uses SHA-1 or legacy SHA: %s", table.concat(sha_list, ", ")))
  end
  if #filtered_nonrec > 0 then
    add_alert("high", string.format("Unsupported TLS cipher(s) not in recommended list: %s", table.concat(filtered_nonrec, ", ")))
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
