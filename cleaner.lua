-- Tracking Removal — URL Parser, Redirect Unwrapper, and Message Cleaner
-- Pure Lua 5.5 sandbox-safe module (no os/io/debug/package/print dependencies).

local rules = require("rules")
local list_parser = require("list_parser")

local M = {}

local MAX_UNWRAP_DEPTH = 5

-- Pure-Lua Base64 decoding fallback (used when C-Cord's `encoding` global is absent, e.g. CLI unit tests).
local B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_LOOKUP = {}
for i = 1, #B64_ALPHABET do
  B64_LOOKUP[B64_ALPHABET:byte(i)] = i - 1
end

local function pure_base64_decode(str)
  if type(str) ~= "string" then
    return nil
  end
  local clean = str:gsub("%s+", "")
  if #clean == 0 or (#clean % 4) ~= 0 then
    return nil
  end
  local out = {}
  local n = #clean
  local i = 1
  while i <= n do
    local b1 = clean:byte(i)
    local b2 = clean:byte(i + 1)
    local b3 = clean:byte(i + 2)
    local b4 = clean:byte(i + 3)

    local v1 = B64_LOOKUP[b1]
    local v2 = B64_LOOKUP[b2]
    if not v1 or not v2 then
      return nil
    end

    local pad3 = (b3 == 61) -- '='
    local pad4 = (b4 == 61)
    local v3 = pad3 and 0 or B64_LOOKUP[b3]
    local v4 = pad4 and 0 or B64_LOOKUP[b4]
    if (not pad3 and not v3) or (not pad4 and not v4) then
      return nil
    end

    local triple = (v1 << 18) | (v2 << 12) | (v3 << 6) | v4
    out[#out + 1] = string.char((triple >> 16) & 0xFF)
    if not pad3 then
      out[#out + 1] = string.char((triple >> 8) & 0xFF)
    end
    if not pad4 then
      out[#out + 1] = string.char(triple & 0xFF)
    end
    i = i + 4
  end
  return table.concat(out)
end

local function base64url_decode(str)
  if type(str) ~= "string" or str == "" then
    return nil
  end
  local s = str:gsub("-", "+"):gsub("_", "/")
  local rem = #s % 4
  if rem == 2 then
    s = s .. "=="
  elseif rem == 3 then
    s = s .. "="
  elseif rem == 1 then
    return nil
  end
  if _G.encoding and type(_G.encoding.base64_decode) == "function" then
    return _G.encoding.base64_decode(s)
  end
  return pure_base64_decode(s)
end

-- RFC 3986 percent-decoding (preserves literal '+' so query values and paths aren't mangled).
local function percent_decode(str)
  if type(str) ~= "string" then
    return ""
  end
  return (str:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

-- Decodes percent-encoded redirect URLs, safely handling double-encoded values (up to 2 passes).
local function percent_decode_url(str)
  if type(str) ~= "string" or str == "" then
    return nil
  end
  local decoded = percent_decode(str)
  if decoded:match("^[Hh][Tt][Tt][Pp][Ss]?%%3[Aa]") then
    decoded = percent_decode(decoded)
  end
  return decoded
end

local function has_prefix(str, prefixes)
  if not prefixes then
    return false
  end
  for i = 1, #prefixes do
    local p = prefixes[i]
    if #str >= #p and str:sub(1, #p) == p then
      return true
    end
  end
  return false
end

local function host_matches_domain(host_lower, domain)
  if host_lower == domain then
    return true
  end
  local dlen = #domain
  if #host_lower > dlen + 1 and host_lower:sub(-(dlen + 1)) == "." .. domain then
    return true
  end
  return false
end

local function is_host_in_set(host_lower, domain_set)
  if not domain_set or not host_lower or host_lower == "" then
    return false
  end
  if domain_set[host_lower] then
    return true
  end
  local pos = 1
  while true do
    local dot = host_lower:find(".", pos, true)
    if not dot then
      break
    end
    local suffix = host_lower:sub(dot + 1)
    if domain_set[suffix] then
      return true
    end
    pos = dot + 1
  end
  return false
end

-- Safely extracts the registered brand label for multi-TLD services (e.g. www.google.co.uk -> "google").
local function extract_brand(host_lower)
  if not host_lower or host_lower == "" or host_lower:sub(1, 1) == "[" then
    return nil
  end
  local labels = {}
  for label in host_lower:gmatch("[^%.]+") do
    labels[#labels + 1] = label
  end
  local n = #labels
  if n < 2 then
    return nil
  end
  local last = labels[n]
  if not last:match("^[a-z]+$") or #last < 2 or #last > 6 then
    return nil
  end
  if n >= 3 and #last == 2 and rules.known_slds[labels[n - 1]] then
    return labels[n - 2]
  end
  return labels[n - 1]
end

local function find_domain_rules(host_lower)
  local matched = {}
  local seen = {}

  -- Exact and suffix matches in rules.domains
  local candidate = host_lower
  while candidate and candidate ~= "" do
    local r = rules.domains[candidate]
    if r and not seen[r] then
      seen[r] = true
      matched[#matched + 1] = r
    end
    local dot = candidate:find(".", 1, true)
    if not dot then
      break
    end
    candidate = candidate:sub(dot + 1)
  end

  -- Multi-TLD brand match in rules.brands
  local brand = extract_brand(host_lower)
  if brand then
    local br = rules.brands[brand]
    if br and not seen[br] then
      seen[br] = true
      matched[#matched + 1] = br
    end
  end

  return matched, brand
end

local function split_query(query_raw)
  local params = {}
  if not query_raw or query_raw == "" then
    return params
  end
  local pos = 1
  local len = #query_raw
  while pos <= len do
    local amp = query_raw:find("&", pos, true)
    local seg
    if amp then
      seg = query_raw:sub(pos, amp - 1)
      pos = amp + 1
    else
      seg = query_raw:sub(pos)
      pos = len + 1
    end
    if seg ~= "" then
      local eq = seg:find("=", 1, true)
      local raw_key, raw_val
      if eq then
        raw_key = seg:sub(1, eq - 1)
        raw_val = seg:sub(eq + 1)
      else
        raw_key = seg
        raw_val = nil
      end
      local key_decoded = percent_decode(raw_key)
      params[#params + 1] = {
        raw = seg,
        raw_key = raw_key,
        raw_val = raw_val,
        key_lower = key_decoded:lower(),
      }
    end
  end
  return params
end

---Parses an http(s) URL into structured components without altering original encodings.
---@param url string
---@return table|nil
function M.parse_url(url)
  if type(url) ~= "string" or url == "" then
    return nil
  end
  -- Reject control characters or spaces inside URL
  if url:find("[%s%c]") then
    return nil
  end

  local scheme, rest = url:match("^([Hh][Tt][Tt][Pp][Ss]?)://(.+)$")
  if not scheme or not rest then
    return nil
  end

  -- Split authority from path/query/fragment
  local delim_pos = rest:find("[/%?#]")
  local authority, tail
  if delim_pos then
    authority = rest:sub(1, delim_pos - 1)
    tail = rest:sub(delim_pos)
  else
    authority = rest
    tail = ""
  end

  if authority == "" then
    return nil
  end

  -- Split optional userinfo@host[:port]
  local userinfo, hostport
  local at_pos = authority:match(".*()@")
  if at_pos then
    userinfo = authority:sub(1, at_pos - 1)
    hostport = authority:sub(at_pos + 1)
  else
    hostport = authority
  end

  local host, port
  if hostport:sub(1, 1) == "[" then
    host, port = hostport:match("^(%[[^%]]+%])(:%d*)$")
    if not host then
      host = hostport:match("^(%[[^%]]+%])$")
    end
  else
    host, port = hostport:match("^([^:]+)(:%d*)$")
    if not host then
      host = hostport
    end
  end

  if not host or host == "" then
    return nil
  end

  -- Split fragment (#...)
  local has_fragment = false
  local fragment = nil
  local hash_pos = tail:find("#", 1, true)
  local before_hash = tail
  if hash_pos then
    has_fragment = true
    fragment = tail:sub(hash_pos + 1)
    before_hash = tail:sub(1, hash_pos - 1)
  end

  -- Split query (?...)
  local has_query = false
  local query_raw = ""
  local path = before_hash
  local q_pos = before_hash:find("?", 1, true)
  if q_pos then
    has_query = true
    query_raw = before_hash:sub(q_pos + 1)
    path = before_hash:sub(1, q_pos - 1)
  end

  return {
    scheme = scheme,
    scheme_lower = scheme:lower(),
    authority = authority,
    userinfo = userinfo,
    host = host,
    host_lower = host:lower(),
    port = port,
    path = path,
    has_query = has_query,
    query_raw = query_raw,
    params = split_query(query_raw),
    has_fragment = has_fragment,
    fragment = fragment,
  }
end

local function is_valid_redirect_target(target, current_url)
  if type(target) ~= "string" or target == "" or target == current_url then
    return false
  end
  local p = M.parse_url(target)
  if not p then
    return false
  end
  local h = p.host_lower
  if h == "localhost" or h:sub(1, 1) == "[" then
    return true
  end
  -- Require at least one dot and valid hostname characters
  if not h:find(".", 1, true) or h:sub(1, 1) == "." or h:sub(-1) == "." then
    return false
  end
  if h:find("[^a-z0-9%.%-]") then
    return false
  end
  return true
end

local function get_param_value(parsed, key_lower)
  for i = 1, #parsed.params do
    if parsed.params[i].key_lower == key_lower and parsed.params[i].raw_val ~= nil then
      return parsed.params[i].raw_val
    end
  end
  return nil
end

local redirect_helpers = {
  get_param = get_param_value,
  percent_decode = percent_decode,
  percent_decode_url = percent_decode_url,
  base64url_decode = base64url_decode,
}

local function path_matches_prefixes(path_lower, prefixes)
  if not prefixes then
    return true
  end
  for i = 1, #prefixes do
    local p = prefixes[i]
    if p:sub(-1) == "/" then
      if path_lower:sub(1, #p) == p then
        return true
      end
    else
      if path_lower == p or path_lower:sub(1, #p + 1) == p .. "/" then
        return true
      end
    end
  end
  return false
end

local function redirect_matches_host(rule, host_lower, brand)
  if rule.exact_hosts then
    return rule.exact_hosts[host_lower] == true
  end
  if rule.brand then
    return brand == rule.brand
  end
  if rule.domains then
    for i = 1, #rule.domains do
      if host_matches_domain(host_lower, rule.domains[i]) then
        return true
      end
    end
  end
  return false
end

local function try_unwrap_redirect(parsed, current_url)
  local host_lower = parsed.host_lower
  local path_lower = (parsed.path or ""):lower()
  local brand = extract_brand(host_lower)

  for i = 1, #rules.redirects do
    local r = rules.redirects[i]
    if redirect_matches_host(r, host_lower, brand) and path_matches_prefixes(path_lower, r.path_prefixes) then
      local candidate = nil
      if r.extract then
        candidate = r.extract(parsed, redirect_helpers)
      elseif r.params then
        for j = 1, #r.params do
          local raw_val = get_param_value(parsed, r.params[j])
          if raw_val and raw_val ~= "" then
            candidate = percent_decode_url(raw_val)
            if is_valid_redirect_target(candidate, current_url) then
              return candidate
            end
            candidate = nil
          end
        end
      end
      if candidate and is_valid_redirect_target(candidate, current_url) then
        return candidate
      end
    end
  end

  return nil
end

local function find_strict_keep_set(domain_rules, path)
  if not path or path == "" then
    return nil
  end
  local path_lower = path:lower()
  for i = 1, #domain_rules do
    local sp = domain_rules[i].strict_paths
    if sp then
      for j = 1, #sp do
        local entry = sp[j]
        local pats = entry.patterns
        for k = 1, #pats do
          if path_lower:match(pats[k]) then
            return entry.keep
          end
        end
      end
    end
  end
  return nil
end

local function should_strip_param(key_lower, domain_rules, opts)
  if key_lower == "" then
    return false
  end
  if rules.global_exact[key_lower] then
    return true
  end
  if has_prefix(key_lower, rules.global_prefixes) then
    return true
  end
  if opts then
    if opts.custom_exact and opts.custom_exact[key_lower] then
      return true
    end
    if opts.custom_prefixes and has_prefix(key_lower, opts.custom_prefixes) then
      return true
    end
  end
  for i = 1, #domain_rules do
    local dr = domain_rules[i]
    if dr.params and dr.params[key_lower] then
      return true
    end
    if dr.prefixes and has_prefix(key_lower, dr.prefixes) then
      return true
    end
  end
  return false
end

local function should_strip_fragment_param(key_lower, opts)
  if key_lower == "" then
    return false
  end
  if rules.fragment_exact[key_lower] then
    return true
  end
  if has_prefix(key_lower, rules.fragment_prefixes) then
    return true
  end
  if opts then
    if opts.custom_exact and opts.custom_exact[key_lower] then
      return true
    end
    if opts.custom_prefixes and has_prefix(key_lower, opts.custom_prefixes) then
      return true
    end
  end
  return false
end

local function clean_fragment(fragment, opts)
  if not fragment or fragment == "" then
    return fragment, false, {}
  end
  -- Never touch SPA hash routes (#/route), hashbangs (#!), or text highlights (#:~:text=...)
  local first = fragment:sub(1, 1)
  if first == "/" or first == "!" or first == ":" then
    return fragment, false, {}
  end
  if not fragment:find("=", 1, true) then
    return fragment, false, {}
  end

  local had_q = false
  local body = fragment
  if first == "?" then
    had_q = true
    body = fragment:sub(2)
  end

  local kept = {}
  local removed = {}
  local pos = 1
  local len = #body
  while pos <= len do
    local amp = body:find("&", pos, true)
    local seg
    if amp then
      seg = body:sub(pos, amp - 1)
      pos = amp + 1
    else
      seg = body:sub(pos)
      pos = len + 1
    end
    if seg ~= "" then
      local eq = seg:find("=", 1, true)
      if eq then
        local key_lower = percent_decode(seg:sub(1, eq - 1)):lower()
        if should_strip_fragment_param(key_lower, opts) then
          removed[#removed + 1] = key_lower
        else
          kept[#kept + 1] = seg
        end
      else
        kept[#kept + 1] = seg
      end
    end
  end

  if #removed == 0 then
    return fragment, false, removed
  end
  if #kept == 0 then
    return nil, true, removed
  end
  local rebuilt = table.concat(kept, "&")
  if had_q then
    rebuilt = "?" .. rebuilt
  end
  return rebuilt, true, removed
end

---Parses a comma/whitespace-separated list of custom params (supports trailing '*' wildcard).
---@param str string|nil
---@return table exact_set, string[] prefixes
function M.parse_custom_params(str)
  local exact = {}
  local prefixes = {}
  if type(str) ~= "string" or str == "" then
    return exact, prefixes
  end
  for token in str:gmatch("[^,%s;]+") do
    local t = token:lower()
    if #t > 1 and t:sub(-1) == "*" then
      prefixes[#prefixes + 1] = t:sub(1, -2)
    elseif t ~= "" and t ~= "*" then
      exact[t] = true
    end
  end
  return exact, prefixes
end

---Parses a comma/whitespace-separated list of domains to ignore.
---@param str string|nil
---@return table<string, boolean>
function M.parse_domain_list(str)
  local domains = {}
  if type(str) ~= "string" or str == "" then
    return domains
  end
  for token in str:gmatch("[^,%s;]+") do
    local d = token:lower():gsub("^https?://", ""):gsub("/.*$", ""):gsub("^%.", "")
    if d ~= "" then
      domains[d] = true
    end
  end
  return domains
end

---Cleans a single URL by unwrapping redirects and removing tracking parameters, path segments, and fragments.
---@param url string
---@param opts? table
---@return string cleaned_url, table info
function M.clean_url(url, opts)
  opts = opts or {}
  local info = {
    original = url,
    cleaned = url,
    valid = false,
    changed = false,
    removed_params = {},
    unwrapped_count = 0,
    path_cleaned = false,
    fragment_cleaned = false,
  }

  local parsed = M.parse_url(url)
  if not parsed then
    return url, info
  end
  info.valid = true

  -- Respect user-ignored domains before any processing
  if opts.ignored_domains and is_host_in_set(parsed.host_lower, opts.ignored_domains) then
    return url, info
  end

  local current_url = url

  -- Step 1: Unwrap tracking redirect wrappers (supports nested redirects up to MAX_UNWRAP_DEPTH)
  if opts.unwrap_redirects ~= false then
    for _ = 1, MAX_UNWRAP_DEPTH do
      local target = try_unwrap_redirect(parsed, current_url)
      if not target then
        break
      end
      local next_parsed = M.parse_url(target)
      if not next_parsed then
        break
      end
      info.unwrapped_count = info.unwrapped_count + 1
      current_url = target
      parsed = next_parsed

      -- If unwrapped destination is on a user-ignored domain, keep the unwrapped URL untouched
      if opts.ignored_domains and is_host_in_set(parsed.host_lower, opts.ignored_domains) then
        info.cleaned = current_url
        info.changed = (current_url ~= url)
        return current_url, info
      end
    end
  end

  -- Skip param/path/fragment mutation for immune domains (signed CDNs, OAuth endpoints)
  if is_host_in_set(parsed.host_lower, rules.immune_domains) then
    info.cleaned = current_url
    info.changed = (current_url ~= url)
    return current_url, info
  end

  local domain_rules = find_domain_rules(parsed.host_lower)

  -- Prepare compiled 3rd-party/custom filter list context (fast O(labels) lookup)
  local list_ctx = nil
  if opts.compiled_lists then
    list_ctx = list_parser.prepare_url(opts.compiled_lists, parsed, current_url)
    if list_ctx and list_ctx.exempt_all then
      -- Respect whole-domain exceptions from filter lists (e.g. Wayback Machine / archive.*)
      info.cleaned = current_url
      info.changed = (current_url ~= url)
      return current_url, info
    end
  end

  -- Step 2: Domain-specific path cleaning (e.g. Amazon /ref=..., StackOverflow sharer user IDs)
  local new_path = parsed.path
  if opts.clean_paths ~= false then
    for i = 1, #domain_rules do
      local pc = domain_rules[i].path_cleaner
      if pc then
        local cleaned_p, p_changed = pc(new_path, opts)
        if p_changed then
          new_path = cleaned_p
          info.path_cleaned = true
        end
      end
    end
  end

  -- Step 3: Filter query parameters while preserving original ordering and raw encoding
  local strict_keep = nil
  if opts.strict_canonical ~= false then
    strict_keep = find_strict_keep_set(domain_rules, new_path)
  end

  local use_builtin = (opts.use_builtin_rules ~= false)
  local kept_params = {}
  local removed_params = info.removed_params
  for i = 1, #parsed.params do
    local p = parsed.params[i]
    local user_custom = (opts.custom_exact and opts.custom_exact[p.key_lower])
      or (opts.custom_prefixes and has_prefix(p.key_lower, opts.custom_prefixes))

    local strip = false
    if user_custom then
      strip = true
    elseif strict_keep then
      strip = (not strict_keep[p.key_lower])
    else
      local list_strip, list_exempt = false, false
      if list_ctx then
        list_strip, list_exempt = list_parser.match_param(list_ctx, p)
      end
      if list_exempt then
        strip = false
      elseif list_strip then
        strip = true
      elseif use_builtin then
        strip = should_strip_param(p.key_lower, domain_rules, opts)
      end
    end

    if strip then
      removed_params[#removed_params + 1] = p.key_lower
    else
      kept_params[#kept_params + 1] = p.raw
    end
  end

  -- Step 4: Clean tracking parameters placed in URL fragments
  local new_fragment = parsed.fragment
  local keep_hash = parsed.has_fragment
  if opts.clean_fragments ~= false and parsed.has_fragment and parsed.fragment and parsed.fragment ~= "" then
    local f_val, f_changed, f_removed = clean_fragment(parsed.fragment, opts)
    if f_changed then
      info.fragment_cleaned = true
      new_fragment = f_val
      if f_val == nil then
        keep_hash = false
      end
      for i = 1, #f_removed do
        removed_params[#removed_params + 1] = f_removed[i]
      end
    end
  end

  -- If nothing changed at all, return the exact original URL byte-for-byte
  if info.unwrapped_count == 0 and #removed_params == 0 and not info.path_cleaned and not info.fragment_cleaned then
    return url, info
  end

  -- Rebuild URL cleanly
  local out = parsed.scheme .. "://" .. parsed.authority .. new_path
  if #kept_params > 0 then
    out = out .. "?" .. table.concat(kept_params, "&")
  end
  if keep_hash then
    out = out .. "#" .. (new_fragment or "")
  end

  info.cleaned = out
  info.changed = (out ~= url)
  return out, info
end

-- Characters that immediately terminate a URL scan in chat prose.
local STOP_CHARS = {
  [" "] = true, ["\t"] = true, ["\r"] = true, ["\n"] = true,
  ["<"] = true, [">"] = true, ['"'] = true, ["`"] = true,
  ["|"] = true, ["{"] = true, ["}"] = true, ["\\"] = true,
}

local TRAILING_PUNCT = {
  ["."] = true, [","] = true, [";"] = true, [":"] = true,
  ["!"] = true, ["?"] = true, ["'"] = true,
}

local function trim_paired_markdown(text, start_idx, url_str)
  if start_idx <= 1 then
    return url_str
  end
  local markers = { "***", "**", "~~", "__", "*", "_" }
  for i = 1, #markers do
    local m = markers[i]
    local mlen = #m
    if start_idx > mlen and #url_str > mlen then
      local before = text:sub(start_idx - mlen, start_idx - 1)
      local after = url_str:sub(-mlen)
      if before == m and after == m then
        url_str = url_str:sub(1, #url_str - mlen)
        return url_str
      end
    end
  end
  return url_str
end

local function is_alnum(ch)
  if not ch or ch == "" then
    return false
  end
  local b = ch:byte(1)
  return (b >= 48 and b <= 57) or (b >= 65 and b <= 90) or (b >= 97 and b <= 122)
end

---Scans a Discord message and sanitizes every http(s) URL while preserving Markdown,
---spoilers, angle-bracket embeds, balanced parentheses, and code blocks.
---@param text string
---@param opts? table
---@return string cleaned_text, table stats
function M.clean_text(text, opts)
  opts = opts or {}
  local stats = {
    changed = false,
    urls_found = 0,
    urls_cleaned = 0,
    params_removed = 0,
    redirects_unwrapped = 0,
    changes = {},
  }

  if type(text) ~= "string" or text == "" then
    return text, stats
  end
  -- Fast path: if no "://" appears anywhere in text, skip full scan
  if not text:find("://", 1, true) then
    return text, stats
  end

  local skip_code = (opts.skip_code_blocks ~= false)
  local len = #text
  local out = {}
  local cursor = 1
  local i = 1

  while i <= len do
    local ch = text:sub(i, i)

    -- Skip fenced code blocks (```...```) and inline code spans (`...`)
    if skip_code and ch == "`" then
      local tick_end = i
      while tick_end <= len and text:sub(tick_end, tick_end) == "`" do
        tick_end = tick_end + 1
      end
      local tick_count = tick_end - i
      if tick_count >= 3 then
        local close_start = text:find("```", tick_end, true)
        if close_start then
          i = close_start + 3
        else
          -- Unclosed fenced block extends to end of message
          i = len + 1
        end
      else
        local delim = string.rep("`", tick_count)
        local close_start = text:find(delim, tick_end, true)
        if close_start then
          i = close_start + tick_count
        else
          i = tick_end
        end
      end
    elseif (ch == "h" or ch == "H") and (i == 1 or not is_alnum(text:sub(i - 1, i - 1))) then
      local scheme = text:match("^([Hh][Tt][Tt][Pp][Ss]?://)", i)
      if scheme then
        local url_start = i
        local j = i + #scheme
        local paren_depth = 0
        local bracket_depth = 0

        while j <= len do
          local c = text:sub(j, j)
          local b = c:byte(1)
          if b <= 32 or b == 127 or STOP_CHARS[c] then
            break
          elseif c == "(" then
            paren_depth = paren_depth + 1
          elseif c == ")" then
            if paren_depth == 0 then
              break
            end
            paren_depth = paren_depth - 1
          elseif c == "[" then
            bracket_depth = bracket_depth + 1
          elseif c == "]" then
            if bracket_depth == 0 then
              break
            end
            bracket_depth = bracket_depth - 1
          end
          j = j + 1
        end

        local candidate = text:sub(url_start, j - 1)
        -- Trim paired surrounding Markdown formatting (*url*, ~~url~~, _url_)
        candidate = trim_paired_markdown(text, url_start, candidate)
        -- Trim trailing prose punctuation and unmatched closing bold/italic/strikethrough markers
        while #candidate > #scheme do
          local last = candidate:sub(-1)
          if TRAILING_PUNCT[last] or last == "*" then
            candidate = candidate:sub(1, #candidate - 1)
          elseif #candidate > #scheme + 1 and candidate:sub(-2) == "~~" then
            candidate = candidate:sub(1, #candidate - 2)
          else
            break
          end
        end

        local url_end = url_start + #candidate - 1
        if #candidate > #scheme then
          local cleaned, info = M.clean_url(candidate, opts)
          if info and info.valid then
            stats.urls_found = stats.urls_found + 1
            if info.changed then
              stats.changed = true
              stats.urls_cleaned = stats.urls_cleaned + 1
              stats.params_removed = stats.params_removed + #info.removed_params
              stats.redirects_unwrapped = stats.redirects_unwrapped + info.unwrapped_count
              stats.changes[#stats.changes + 1] = info

              out[#out + 1] = text:sub(cursor, url_start - 1)
              out[#out + 1] = cleaned
              cursor = url_end + 1
            end
          end
        end

        i = url_end + 1
      else
        i = i + 1
      end
    else
      i = i + 1
    end
  end

  if not stats.changed then
    return text, stats
  end

  out[#out + 1] = text:sub(cursor)
  return table.concat(out), stats
end

return M
