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

categories = {"discovery", "safe", "intrusive"}

portrule = shortport.port_or_service({443, 8443, 9443}, {"https", "ssl"})


-- 3. locals
-- we define the possible alerts
local alerts = {
  critical = {},
  high = {},
  medium = {},
  low = {}
}

local function add_alert(sev, title, desc)
  table.insert(alerts[sev], {title = title, desc = desc})
end


-- 4. check the certificate

local function check_certificate(host, port)
  local status, cert = sslcert.get_certificate(host, port)
  if not status then
    add_alert("critical", "No se pudo obtener certificado", "Falla al leer el certificado TLS.")
    return nil
  end

  -- Self-signed check
  if cert.issuer == cert.subject then
    add_alert("critical", "Self-signed certificate detected",
              "El certificado está firmado por sí mismo (issuer == subject).")
  end

  -- Key type / size
  local keytype = cert.public_key_type or "unknown"
  local keysize = cert.public_key_bits or 0
  if not ((keytype == "RSA" and keysize >= 2048) or (keytype == "ECDSA" and keysize >= 256)) then
    add_alert("high", "Weak or non-recommended certificate key",
              string.format("Tipo: %s, Tamaño: %d bits", keytype, keysize))
  end

  -- Lifespan check (validity period in days)
  if cert.validity then
    local days = cert.validity.days
    if days < 90 or days > 366 then
      add_alert("medium", "Certificate lifespan out of recommended range",
                string.format("Lifespan: %d days (se recomiendan 90..366 días)", days))
    end
  end

  -- CN / SAN domain matching (simplified)
  local host_s = host.targetname or host.ip or host
  local cn = cert.subject_common_name or ""
  local san = cert.subject_alt_name or {}
  local match = false
  if cn == host_s then match = true end
  for _, v in ipairs(san) do
    if v == host_s then match = true; break end
  end
  if not match then
    add_alert("medium", "Domain name does not match certificate CN/SAN",
              string.format("Host: %s, CN: %s, SANs: %s", host_s, cn, table.concat(san, ", ")))
  end

  -- Non-qualified hostnames or IPs in cert
  if string.match(cn, "%d+%.%d+%.%d+%.%d+") then
    add_alert("low", "IP address included in certificate CN",
              "El CN contiene una dirección IP, lo que no es recomendable.")
  end
  if not string.find(cn, "%.") then
    add_alert("low", "Non-qualified host name in certificate",
              "El CN parece no ser un nombre totalmente calificado (no contiene '.').")
  end

  return cert
end

---
-- 5. Check TLS connection properties: ciphers, protocols, compression
---
local function check_tls_props(host, port)
  -- negotiate TLS (we try a handshake and inspect the negotiated cipher & protocol)
  local ok, sock, status = tls.new(host, port, {timeout = 5000})
  if not ok then
    add_alert("critical", "TLS handshake failed", "No se pudo establecer conexión TLS: " .. tostring(sock))
    return nil
  end

    -- get negotiated parameters (API names may vary depending on nmap version)
  local proto = "unknown"
  local cipher = "unknown"
  local compression = false

  -- some socket APIs expose methods, others expose fields - check safely
  if sock then
    -- protocol
    if type(sock.ssl_protocol) == "function" then
      proto = sock:ssl_protocol() or proto
    elseif type(sock.ssl_protocol) ~= "nil" then
      proto = sock.ssl_protocol or proto
    elseif type(sock.version) == "function" then
      proto = sock:version() or proto
    elseif type(sock.version) ~= "nil" then
      proto = sock.version or proto
    end

    -- cipher
    if type(sock.ssl_cipher) == "function" then
      cipher = sock:ssl_cipher() or cipher
    elseif type(sock.ssl_cipher) ~= "nil" then
      cipher = sock.ssl_cipher or cipher
    end

    -- compression
    if type(sock.ssl_compression) == "function" then
      compression = sock:ssl_compression() or compression
    elseif type(sock.ssl_compression) ~= "nil" then
      compression = sock.ssl_compression or compression
    end
  end

  -- Compression check
  if compression and compression ~= "none" then
    add_alert("critical", "TLS compression enabled",
              "Se detectó compresión en la conexión TLS (vulnerable a CRIME).")
  end

  -- CBC or SHA checks inside cipher name (heurística)
  local ciph_upper = string.upper(cipher)
  if string.find(ciph_upper, "CBC") or string.find(ciph_upper, "SHA1") or string.find(ciph_upper, "SHA-1") then
    add_alert("critical", "Cipher uses CBC and/or SHA-1",
              string.format("Cipher negociado: %s", cipher))
  end

  -- Protocol support check: raise high if only TLS < 1.2
  if proto and (string.match(proto, "TLSv1$") or string.match(proto, "SSLv3") or string.match(proto, "TLSv1.0")) then
    add_alert("high", "Server supports deprecated TLS/SSL versions",
              "El servidor negocia TLS/SSL obsoletos (pre-TLS1.2).")
  end

  -- Check if negotiated cipher is among allowed list (high alert if other)
  local allowed = {
    ["ECDHE-ECDSA-AES128-GCM-SHA256"]=true,
    ["ECDHE-RSA-AES128-GCM-SHA256"]=true,
    ["ECDHE-ECDSA-AES256-GCM-SHA384"]=true,
    ["ECDHE-RSA-AES256-GCM-SHA384"]=true,
    ["ECDHE-ECDSA-CHACHA20-POLY1305"]=true,
    ["ECDHE-RSA-CHACHA20-POLY1305"]=true,
    ["DHE-RSA-AES128-GCM-SHA256"]=true,
    ["DHE-RSA-AES256-GCM-SHA384"]=true,
    ["DHE-RSA-CHACHA20-POLY1305"]=true
  }
  if cipher and not allowed[cipher] then
    add_alert("high", "Unsupported TLS cipher suite",
              string.format("Cipher no recomendado soportado: %s", cipher))
  end

  sock:close()
  return {protocol = proto, cipher = cipher, compression = compression}
end

---
-- 7. Format output according to the required Nmap output format
---
local function format_alerts()
  local out = {}
  local function fmt(sev_label, list)
    table.insert(out, "**********************")
    table.insert(out, string.format("%s ALERTS: %d", string.upper(sev_label), #list))
    table.insert(out, "**********************")
    for _, a in ipairs(list) do
      if a.desc and a.desc ~= "" then
        table.insert(out, string.format("- %s. %s", a.title, a.desc))
      else
        table.insert(out, string.format("- %s", a.title))
      end
    end
  end

  if #alerts.critical > 0 then fmt("critical", alerts.critical) end
  if #alerts.high > 0 then fmt("high", alerts.high) end
  if #alerts.medium > 0 then fmt("medium", alerts.medium) end
  if #alerts.low > 0 then fmt("low", alerts.low) end

  if #out == 0 then return "No TLS/certificate issues detected." end
  return table.concat(out, "\n")
end

---
-- 8. Main action (where functions are called)
---
action = function(host, port)
  -- reset alerts
  alerts = {critical = {}, high = {}, medium = {}, low = {}}

  -- get host target (string)
  local target = host.ip or host.targetname or tostring(host)

  -- 1) Certificate analysis
  check_certificate(host, port)

  -- 2) TLS properties
  check_tls_props(host, port)

  -- 3) (Opcional) scans adicionales: enumeración de suites si la API lo permite

  -- 4) Return formatted alerts
  local result = format_alerts()
  return result
end
