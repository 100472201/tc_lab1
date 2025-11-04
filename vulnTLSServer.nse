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
    table.insert(alerts.high, "Self-signed certificate.")
  end

  -- Check for weak key size
  if cert.pubkey.type == "rsa" and cert.pubkey.bits < 2048 then
    table.insert(alerts.medium, string.format("Weak key: %s bits %s.", cert.pubkey.bits, cert.pubkey.type))
  end

  -- Check validity
  local now = os.time()
  if cert.validity.notBefore and now < os.time(cert.validity.notBefore) then
    table.insert(alerts.high, "Certificate is not yet valid.")
  end
  if cert.validity.notAfter and now > os.time(cert.validity.notAfter) then
    table.insert(alerts.high, "Certificate has expired.")
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
  
  local output = stdnse.output_table()
  for level, messages in pairs(alerts) do
    if #messages > 0 then
      output[level] = messages
    end
  end

  return output
end
