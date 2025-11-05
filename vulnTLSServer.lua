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

  host.targetname = tls.servername(host) or host.ip

  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  -- CRITICAL ALERTS (3)

  -- 1. Check for self-signed certificate
  if stringify_name(cert.subject) == stringify_name(cert.issuer) then
    local subj = cert.subject.commonName or stringify_name(cert.subject)
    local issuer = cert.issuer.commonName or stringify_name(cert.issuer)
    table.insert(alerts.critical, string.format(
      "Self-Signed Certificate. The certificate is self-signed, as the subject and issuer are identical. Subject: %s; Issuer: %s.",
      subj, issuer))
  end

  -- 2. Check for SHA-1 signature
  if cert.sig_algorithm and string.find(cert.sig_algorithm:lower(), "sha1") then
    table.insert(alerts.critical, "SHA-1 Signature. The certificate signature uses the deprecated SHA-1 algorithm.")
  end

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
    sock:set_timeout(5000)
    local status, err = sock:connect(host, port)
    if status then
      local status_hello, err_hello = tls.client_hello(sock, proto, nil)
      if status_hello then
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

  if not has_tls1_2 and not has_tls1_3 then
    if has_tls1_0 or has_tls1_1 then
      table.insert(alerts.high, "Outdated TLS Support. The server does not support TLS 1.2 or TLS 1.3, but supports older protocols: " .. table.concat(supported_protocols, ", "))
    end
  else -- Server supports TLS 1.2 or 1.3
    if has_tls1_1 then
      table.insert(alerts.high, "Outdated TLS Support. The server supports the outdated TLS 1.1 protocol along with modern protocols.")
    end
    if has_tls1_0 then
      table.insert(alerts.high, "Outdated TLS Support. The server supports the outdated TLS 1.0 protocol along with modern protocols.")
    end
  end

  -- 3. Check for cipher suites
  -- Check for weak cipher suites
  local ciphers = port.version and port.version.service_data and port.version.service_data.ciphers
  if ciphers then
    local allowlist = {
      ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] = true,
      ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] = true,
      ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] = true,
      ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] = true,
      ["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"] = true,
      ["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = true,
      ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"] = true,
      ["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"] = true,
      ["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = true,
    }
    for _, cipher in ipairs(ciphers) do
      local cipher_name = cipher.name
      if not allowlist[cipher_name] then
        if string.find(cipher_name, "CBC") then
          table.insert(alerts.critical, string.format("Weak Cipher Suite. The server uses a weak cipher suite: %s (CBC mode).", cipher_name))
        elseif (string.find(cipher_name, "_SHA") or string.find(cipher_name, "_SHA1")) and not string.find(cipher_name, "SHA256") and not string.find(cipher_name, "SHA384") then
          table.insert(alerts.critical, string.format("Weak Cipher Suite. The server uses a weak cipher suite: %s (SHA-1 hash).", cipher_name))
        else
          table.insert(alerts.high, string.format("Cipher Suite Not in Allowlist. The server supports a cipher suite that is not in the allowlist: %s", cipher_name))
        end
      end
    end
  else
    -- Fallback to manual check of weak ciphers
    local weak_ciphers_to_test = {
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_256_CBC_SHA",
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    }
    for _, cipher_name in ipairs(weak_ciphers_to_test) do
      local sock = nmap.new_socket()
      sock:set_timeout(5000)
      local status, err = sock:connect(host, port)
      if status then
        local status_hello, err_hello = tls.client_hello(sock, nil, {cipher_name})
        if status_hello then
          -- The server accepted the cipher
          table.insert(alerts.critical, string.format("Weak CBC Cipher. The server supports a weak CBC cipher: %s", cipher_name))
          sock:close()
          break -- Stop after finding one
        end
        sock:close()
      end
    end
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
