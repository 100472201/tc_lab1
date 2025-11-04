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
- Weak key types/sizes  
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

  -- Check for self-signed certificate
  if stringify_name(cert.subject) == stringify_name(cert.issuer) then
    local subj = cert.subject.commonName or stringify_name(cert.subject)
    local issuer = cert.issuer.commonName or stringify_name(cert.issuer)
    table.insert(alerts.critical, string.format(
      "Self-signed certificate detected. Subject and issuer are identical. Subject: %s; Issuer: %s.",
      subj, issuer))
  end

  -- Check for certificate type
  if cert.pubkey.type == "rsa" then
    if cert.pubkey.bits < 2048 then
      table.insert(alerts.high, string.format("Weak key: %s bits %s.", cert.pubkey.bits, cert.pubkey.type))
    end
  elseif cert.pubkey.type == "ec" then
    if cert.pubkey.ecdhparams.curve_params.curve ~= "secp256r1" then
      table.insert(alerts.high, string.format("Weak key: %s curve.", cert.pubkey.ecdhparams.curve_params.curve))
    end
  else
    table.insert(alerts.high, string.format("Unsupported key type: %s.", cert.pubkey.type))
  end

  -- Check validity
  local now = os.time()
  local notBefore = os.time(cert.validity.notBefore)
  local notAfter = os.time(cert.validity.notAfter)

  if now < notBefore then
    table.insert(alerts.high, "Certificate is not yet valid.")
  end
  if now > notAfter then
    table.insert(alerts.high, "Certificate has expired.")
  end

  local lifespan_days = (notAfter - notBefore) / (60 * 60 * 24)
  if lifespan_days < 90 then
    table.insert(alerts.medium, string.format("Certificate lifespan is too short: %.0f days (less than 90 days).", lifespan_days))
  end
  if lifespan_days > 366 then
    table.insert(alerts.medium, string.format("Certificate lifespan is too long: %.0f days (more than 366 days).", lifespan_days))
  end

  -- Check for domain name mismatch
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

  -- Check for supported protocols
  local port_state = nmap.get_port_state(host, port)
  if port_state and port_state.ssl_tunnel and port_state.ssl_tunnel.version then
    local version = port_state.ssl_tunnel.version
    if version == "TLSv1.0" or version == "SSLv3" then
      table.insert(alerts.high, string.format("Unsupported protocol version: %s.", version))
    end
  end

  -- Check for weak cipher suites
  if port_state and port_state.ssl_tunnel and port_state.ssl_tunnel.cipher then
    local cipher = port_state.ssl_tunnel.cipher
    if string.find(cipher, "CBC") then
      table.insert(alerts.critical, string.format("Weak cipher suite used: %s (uses CBC mode).", cipher))
    end
    if string.find(cipher, "_SHA") and not string.find(cipher, "SHA256") and not string.find(cipher, "SHA384") then
      table.insert(alerts.critical, string.format("Weak cipher suite used: %s (uses SHA-1 hash).", cipher))
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
    table.insert(alerts.medium, string.format("Domain name mismatch: %s does not match %s or any subject alternative names.", host.targetname, common_name))
  end

  -- Check for non-qualified hostnames and IP addresses in certificate
  local names_to_check = {}
  if common_name then
    table.insert(names_to_check, common_name)
  end
  for _, san in ipairs(subject_alt_names) do
    table.insert(names_to_check, san)
  end

  for _, name in ipairs(names_to_check) do
    if not string.find(name, "%.") then
      table.insert(alerts.low, string.format("Non-qualified hostname in certificate: %s.", name))
    end
    if string.match(name, "^%d+.%d+.%d+.%d+$") then
      table.insert(alerts.low, string.format("IP address found in certificate: %s.", name))
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
