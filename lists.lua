-- Tracking Removal — 3rd-Party & Custom Filter List Manager
-- Handles built-in community filter subscriptions (AdGuard #17, DandelionSprout,
-- ClearURLs), custom HTTPS list URLs, local file imports, gzip-compressed caching,
-- and background auto-updates via C-Cord's async net.http API.

local list_parser = require("list_parser")

local M = {}

local MAX_LIST_BYTES = 4 * 1024 * 1024 -- 4 MiB safety cap per filter list
local FETCH_TIMEOUT_MS = 15000

M.PRESETS = {
  {
    id = "adguard_trackparam",
    name = "AdGuard URL Tracking Filter (#17)",
    setting_key = "list_adguard",
    default_enabled = true,
    urls = {
      "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
      "https://filters.adtidy.org/extension/ublock/filters/17.txt",
    },
  },
  {
    id = "dandelionsprout",
    name = "DandelionSprout Legitimate URL Shortener",
    setting_key = "list_dandelionsprout",
    default_enabled = false,
    urls = {
      "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt",
    },
  },
  {
    id = "clearurls",
    name = "ClearURLs Rules (JSON)",
    setting_key = "list_clearurls",
    default_enabled = false,
    urls = {
      "https://rules2.clearurls.xyz/data.minify.json",
      "https://raw.githubusercontent.com/ClearURLs/Rules/master/data.min.json",
    },
  },
}

local compiled_index = list_parser.new_index()
local is_syncing = false
local last_errors = {}

local function trim(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function is_https_url(u)
  return type(u) == "string" and u:match("^https://[^%s]+$") ~= nil
end

local function cache_key_for_id(id)
  return "list_cache_" .. id
end

local function custom_url_id(url)
  if _G.crypto and type(_G.crypto.sha256) == "function" then
    return "url_" .. _G.crypto.sha256(url):sub(1, 16)
  end
  -- Deterministic fallback hash if crypto is absent
  local h = 5381
  for i = 1, #url do
    h = ((h * 33) + url:byte(i)) % 4294967296
  end
  return string.format("url_%08x_%d", h, #url)
end

local function encode_payload(raw_text)
  if _G.compress and type(_G.compress.gzip) == "function"
    and _G.encoding and type(_G.encoding.base64_encode) == "function"
  then
    local gz = _G.compress.gzip(raw_text, 6)
    if gz then
      local b64 = _G.encoding.base64_encode(gz)
      if b64 then
        return { gz_b64 = b64, size_bytes = #raw_text }
      end
    end
  end
  return { raw = raw_text, size_bytes = #raw_text }
end

local function decode_payload(entry)
  if type(entry) ~= "table" then
    return nil
  end
  if type(entry.gz_b64) == "string"
    and _G.encoding and type(_G.encoding.base64_decode) == "function"
    and _G.compress and type(_G.compress.gunzip) == "function"
  then
    local gz = _G.encoding.base64_decode(entry.gz_b64)
    if gz then
      local plain = _G.compress.gunzip(gz)
      if plain then
        return plain
      end
    end
  end
  if type(entry.raw) == "string" then
    return entry.raw
  end
  return nil
end

---Parses comma/whitespace/newline-separated custom HTTPS list URLs from settings.
---@param str string|nil
---@return string[]
function M.parse_custom_urls(str)
  local urls = {}
  local seen = {}
  if type(str) ~= "string" or str == "" then
    return urls
  end
  for token in str:gmatch("[^,%s]+") do
    local u = trim(token)
    if is_https_url(u) and not seen[u] then
      seen[u] = true
      urls[#urls + 1] = u
    end
  end
  return urls
end

local function get_local_lists_meta()
  local meta = storage.get("local_lists")
  if type(meta) ~= "table" then
    return {}
  end
  return meta
end

local function save_local_lists_meta(meta)
  storage.set("local_lists", meta)
end

---Returns the list of currently enabled remote subscriptions (built-in presets + custom URLs).
---@return table[]
function M.get_enabled_remote_lists()
  local active = {}
  for i = 1, #M.PRESETS do
    local p = M.PRESETS[i]
    if settings.get(p.setting_key, p.default_enabled) == true then
      active[#active + 1] = {
        id = p.id,
        name = p.name,
        urls = p.urls,
        is_preset = true,
      }
    end
  end
  local custom_urls = M.parse_custom_urls(settings.get("custom_list_urls", ""))
  for i = 1, #custom_urls do
    local u = custom_urls[i]
    local short_name = u:match("([^/]+)$") or u
    active[#active + 1] = {
      id = custom_url_id(u),
      name = "Custom: " .. short_name,
      url = u,
      urls = { u },
      is_preset = false,
    }
  end
  return active
end

---Rebuilds the in-memory compiled filter index from all enabled cached remote lists and local lists.
---@return table index
function M.rebuild()
  local idx = list_parser.new_index()
  local active_remotes = M.get_enabled_remote_lists()

  for i = 1, #active_remotes do
    local item = active_remotes[i]
    local cached = storage.get(cache_key_for_id(item.id))
    local raw = decode_payload(cached)
    if raw and raw ~= "" then
      local _, added, skipped, fmt = list_parser.parse_auto(raw, idx)
      idx.sources[#idx.sources + 1] = {
        id = item.id,
        name = item.name,
        kind = item.is_preset and "preset" or "remote",
        format = fmt,
        rules = added,
        skipped = skipped,
        updated_at_ms = cached.updated_at_ms or 0,
      }
    end
  end

  local local_meta = get_local_lists_meta()
  for i = 1, #local_meta do
    local m = local_meta[i]
    if type(m) == "table" and type(m.id) == "string" then
      local cached = storage.get("list_local_" .. m.id)
      local raw = decode_payload(cached)
      if raw and raw ~= "" then
        local _, added, skipped, fmt = list_parser.parse_auto(raw, idx)
        idx.sources[#idx.sources + 1] = {
          id = m.id,
          name = m.name or m.id,
          kind = "local",
          format = fmt,
          rules = added,
          skipped = skipped,
          updated_at_ms = m.imported_at_ms or 0,
        }
      end
    end
  end

  compiled_index = idx
  log.debug(string.format(
    "Compiled %d rules across %d active filter list(s) (%d skipped)",
    idx.total_rules, #idx.sources, idx.skipped_rules
  ))
  return compiled_index
end

---Returns the current active compiled list index (or nil if no external lists have rules loaded).
---@return table|nil
function M.get_index()
  if compiled_index and compiled_index.total_rules > 0 then
    return compiled_index
  end
  return nil
end

function M.is_syncing()
  return is_syncing
end

local function fetch_first_mirror(urls)
  local ua = "C-Cord-Tracking-Removal/" .. tostring(plugin.version or "1.0.0")
  local last_err = "No URLs configured"
  for i = 1, #urls do
    local url = urls[i]
    local resp, err = net.http.get(url, {
      headers = { ["User-Agent"] = ua },
      timeout_ms = FETCH_TIMEOUT_MS,
    })
    if resp and resp.status == 200 and type(resp.body) == "string" and #resp.body > 0 then
      if #resp.body > MAX_LIST_BYTES then
        last_err = "List exceeds 4 MiB limit"
      else
        -- Validate that the payload actually parses at least 1 tracking rule (guards against HTML error pages)
        local test_idx, added, _, fmt = list_parser.parse_auto(resp.body)
        if added > 0 and test_idx then
          return resp.body, added, fmt, url, nil
        else
          last_err = "Response contained no recognizable tracking rules"
        end
      end
    else
      last_err = err or ("HTTP " .. tostring(resp and resp.status or "error"))
    end
  end
  return nil, 0, nil, nil, last_err
end

---Asynchronously updates all enabled remote filter lists.
---If `force` is false, lists updated more recently than `update_interval_hours` are skipped.
---@param force? boolean
---@param on_done? fun(report: { updated: integer, skipped_fresh: integer, failed: integer, total_rules: integer, errors: string[] })
---@return boolean started
function M.sync_all(force, on_done)
  if is_syncing then
    return false
  end
  local active = M.get_enabled_remote_lists()
  if #active == 0 then
    M.rebuild()
    if on_done then
      on_done({ updated = 0, skipped_fresh = 0, failed = 0, total_rules = compiled_index.total_rules, errors = {} })
    end
    return false
  end

  local interval_hours = tonumber(settings.get("update_interval_hours", 24)) or 24
  local max_age_ms = math.max(1, interval_hours) * 3600 * 1000
  local now = time.now_ms()

  is_syncing = true
  async.spawn(function()
    local updated = 0
    local skipped_fresh = 0
    local failed = 0
    local errs = {}

    local ok_all, run_err = pcall(function()
      for i = 1, #active do
        local item = active[i]
        local key = cache_key_for_id(item.id)
        local cached = storage.get(key)
        local age = (type(cached) == "table" and tonumber(cached.updated_at_ms))
          and (now - cached.updated_at_ms) or nil

        if (not force) and age and age >= 0 and age < max_age_ms and decode_payload(cached) then
          skipped_fresh = skipped_fresh + 1
        else
          local body, added, fmt, used_url, err = fetch_first_mirror(item.urls)
          if body then
            local payload = encode_payload(body)
            payload.updated_at_ms = time.now_ms()
            payload.rule_count = added
            payload.format = fmt
            payload.url = used_url
            payload.name = item.name
            storage.set(key, payload)
            last_errors[item.id] = nil
            updated = updated + 1
            log.info(string.format("Synced %s (%d rules, %s)", item.name, added, fmt))
          else
            last_errors[item.id] = err
            failed = failed + 1
            errs[#errs + 1] = item.name .. ": " .. tostring(err)
            log.warn("Failed to sync " .. item.name .. ": " .. tostring(err))
          end
        end
      end
    end)

    if not ok_all then
      log.error("Unexpected error during filter list sync: " .. tostring(run_err))
      failed = failed + 1
      errs[#errs + 1] = tostring(run_err)
    end

    if updated > 0 or not compiled_index then
      M.rebuild()
    end

    is_syncing = false
    if on_done then
      on_done({
        updated = updated,
        skipped_fresh = skipped_fresh,
        failed = failed,
        total_rules = compiled_index.total_rules,
        errors = errs,
      })
    end
  end)

  return true
end

---Imports a local custom list (AdGuard/uBlock `$removeparam`, ClearURLs JSON, or plain text).
---@param name string
---@param raw_text string
---@return boolean ok, table|string result_or_err
function M.import_local_list(name, raw_text)
  if type(raw_text) ~= "string" or raw_text == "" then
    return false, "Selected file is empty"
  end
  if #raw_text > MAX_LIST_BYTES then
    return false, "File exceeds 4 MiB limit"
  end

  local _, added, skipped, fmt = list_parser.parse_auto(raw_text)
  if added == 0 then
    return false, "No recognizable tracking rules found in file"
  end

  local clean_name = trim(name or "custom-list.txt"):gsub("^.*[/\\]", "")
  if clean_name == "" then
    clean_name = "custom-list.txt"
  end

  local local_meta = get_local_lists_meta()
  local entry_id = nil
  local existing_idx = nil
  for i = 1, #local_meta do
    if local_meta[i].name and local_meta[i].name:lower() == clean_name:lower() then
      entry_id = local_meta[i].id
      existing_idx = i
      break
    end
  end
  if not entry_id then
    entry_id = "local_" .. tostring(time.now_ms()) .. "_" .. tostring(#local_meta + 1)
  end

  local payload = encode_payload(raw_text)
  payload.imported_at_ms = time.now_ms()
  payload.name = clean_name
  payload.format = fmt
  payload.rule_count = added
  storage.set("list_local_" .. entry_id, payload)

  local meta_entry = {
    id = entry_id,
    name = clean_name,
    format = fmt,
    rule_count = added,
    skipped_count = skipped,
    size_bytes = #raw_text,
    imported_at_ms = payload.imported_at_ms,
  }
  if existing_idx then
    local_meta[existing_idx] = meta_entry
  else
    local_meta[#local_meta + 1] = meta_entry
  end
  save_local_lists_meta(local_meta)
  M.rebuild()

  return true, meta_entry
end

---Adds a custom HTTPS list URL to settings and triggers an immediate fetch.
---@param url string
---@param on_done? fun(report: table)
---@return boolean ok, string|nil err
function M.add_custom_url(url, on_done)
  local u = trim(url)
  if not is_https_url(u) then
    return false, "Custom list URL must start with https://"
  end
  local current = M.parse_custom_urls(settings.get("custom_list_urls", ""))
  for i = 1, #current do
    if current[i] == u then
      M.sync_all(true, on_done)
      return true, nil
    end
  end
  current[#current + 1] = u
  settings.set("custom_list_urls", table.concat(current, ", "))
  M.sync_all(true, on_done)
  return true, nil
end

---Removes a custom remote URL or locally imported list by exact URL, name, or partial match.
---@param target string
---@return boolean removed, string|nil label
function M.remove_custom_list(target)
  local q = trim(target)
  if q == "" then
    return false, nil
  end
  local q_lower = q:lower()

  -- 1. Check locally imported lists
  local local_meta = get_local_lists_meta()
  for i = 1, #local_meta do
    local m = local_meta[i]
    if m.id == q or (m.name and (m.name:lower() == q_lower or m.name:lower():find(q_lower, 1, true))) then
      local removed_name = m.name or m.id
      storage.delete("list_local_" .. m.id)
      table.remove(local_meta, i)
      save_local_lists_meta(local_meta)
      M.rebuild()
      return true, "local list '" .. removed_name .. "'"
    end
  end

  -- 2. Check custom remote URLs
  local urls = M.parse_custom_urls(settings.get("custom_list_urls", ""))
  for i = 1, #urls do
    local u = urls[i]
    if u == q or u:lower():find(q_lower, 1, true) then
      storage.delete(cache_key_for_id(custom_url_id(u)))
      table.remove(urls, i)
      settings.set("custom_list_urls", table.concat(urls, ", "))
      M.rebuild()
      return true, "custom URL " .. u
    end
  end

  return false, nil
end

local function format_age(updated_at_ms)
  if not updated_at_ms or updated_at_ms <= 0 then
    return "not yet synced"
  end
  local diff_s = math.max(0, math.floor((time.now_ms() - updated_at_ms) / 1000))
  if diff_s < 60 then
    return "just now"
  elseif diff_s < 3600 then
    return tostring(math.floor(diff_s / 60)) .. "m ago"
  elseif diff_s < 86400 then
    return tostring(math.floor(diff_s / 3600)) .. "h ago"
  end
  return tostring(math.floor(diff_s / 86400)) .. "d ago"
end

---Formats a human-readable overview of all active 3rd-party & custom filter lists.
---@return string
function M.format_status_report()
  local lines = {}
  local active_remotes = M.get_enabled_remote_lists()

  lines[#lines + 1] = string.format(
    "Active compiled rules: %d (%d source%s)",
    compiled_index.total_rules,
    #compiled_index.sources,
    #compiled_index.sources == 1 and "" or "s"
  )
  lines[#lines + 1] = ""

  if #active_remotes == 0 then
    lines[#lines + 1] = "Remote lists: none enabled"
  else
    lines[#lines + 1] = "Remote Subscriptions:"
    for i = 1, #active_remotes do
      local item = active_remotes[i]
      local cached = storage.get(cache_key_for_id(item.id))
      local count = (type(cached) == "table" and cached.rule_count) or 0
      local age = format_age(type(cached) == "table" and cached.updated_at_ms or 0)
      local err_suffix = last_errors[item.id] and (" [last error: " .. tostring(last_errors[item.id]) .. "]") or ""
      lines[#lines + 1] = string.format("• %s — %d rules (%s)%s", item.name, count, age, err_suffix)
    end
  end

  local local_meta = get_local_lists_meta()
  if #local_meta > 0 then
    lines[#lines + 1] = ""
    lines[#lines + 1] = "Local Imported Lists:"
    for i = 1, #local_meta do
      local m = local_meta[i]
      lines[#lines + 1] = string.format(
        "• %s — %d rules (%s, imported %s)",
        m.name, m.rule_count or 0, m.format or "auto", format_age(m.imported_at_ms)
      )
    end
  end

  return table.concat(lines, "\n")
end

return M
