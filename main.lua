-- Tracking Removal — C-Cord Plugin API v1
-- Automatically removes tracking parameters and unwraps redirect links when
-- opening links and when sending or editing messages, powered by auto-updating
-- 3rd-party filter lists (AdGuard #17, DandelionSprout, ClearURLs) and custom lists.

local cleaner = require("cleaner")
local lists = require("lists")
local transparency = require("transparency")

-- ============================================================================
-- Settings Schema (Settings -> Plugins -> Tracking Removal -> Configure)
-- ============================================================================

settings.schema({
  { type = "section", label = "Protection" },
  {
    key = "enabled",
    type = "toggle",
    label = "Enable Tracking Removal",
    description = "Master switch to enable or pause all automatic URL cleaning.",
    default = true,
  },
  {
    key = "clean_on_send",
    type = "toggle",
    label = "Clean Outgoing Messages",
    description = "Automatically sanitize links before your messages are sent to Discord.",
    default = true,
  },
  {
    key = "clean_on_edit",
    type = "toggle",
    label = "Clean Edited Messages",
    description = "Automatically sanitize links when editing existing messages.",
    default = true,
  },
  {
    key = "clean_on_link_open",
    type = "toggle",
    label = "Clean Opened Links",
    description = "Automatically sanitize links before opening them in your browser.",
    default = true,
  },

  { type = "section", label = "3rd-Party & Custom Filter Lists" },
  {
    key = "list_adguard",
    type = "toggle",
    label = "AdGuard URL Tracking Filter (#17)",
    description = "Daily community-maintained list (2,700+ rules including x.com ?a=, low breakage).",
    default = true,
  },
  {
    key = "list_dandelionsprout",
    type = "toggle",
    label = "DandelionSprout Legitimate URL Shortener",
    description = "Aggressive daily community $removeparam list (3,100+ rules).",
    default = false,
  },
  {
    key = "list_clearurls",
    type = "toggle",
    label = "ClearURLs Rules (JSON)",
    description = "Community-maintained ClearURLs provider ruleset.",
    default = false,
  },
  {
    key = "custom_list_urls",
    type = "text",
    label = "Custom Filter List URLs",
    description = "Comma-separated HTTPS URLs (AdGuard/uBlock $removeparam, ClearURLs JSON, or plain param lists). Also manageable via /cleanurl add-list & /cleanurl import.",
    placeholder = "https://example.com/my-tracking-list.txt",
    default = "",
  },
  {
    key = "auto_update_lists",
    type = "toggle",
    label = "Auto-Update Remote Lists",
    description = "Automatically refresh enabled 3rd-party and custom URL lists in the background.",
    default = true,
  },
  {
    key = "update_interval_hours",
    type = "slider",
    label = "Update Interval (Hours)",
    description = "How often to check remote filter lists for updates.",
    min = 1,
    max = 168,
    step = 1,
    default = 24,
  },

  { type = "section", label = "Sanitization Rules" },
  {
    key = "strict_canonical",
    type = "toggle",
    label = "Strict Canonical Cleaning",
    description = "On known post, video, track, and product links (X, YouTube, Spotify, TikTok, Instagram, Threads, Reddit, Amazon, eBay, Steam), keep only functional parameters so even newly invented trackers are stripped.",
    default = true,
  },
  {
    key = "use_builtin_rules",
    type = "toggle",
    label = "Built-In Fallback Rules",
    description = "Keep core built-in tracking rules active alongside 3rd-party lists (also ensures offline protection before initial sync).",
    default = true,
  },
  {
    key = "unwrap_redirects",
    type = "toggle",
    label = "Unwrap Redirect Links",
    description = "Extract true destinations from Google /url & AMP, YouTube /redirect, Facebook, Instagram, Reddit, Steam, Bing, Outlook SafeLinks, and affiliate redirects.",
    default = true,
  },
  {
    key = "clean_paths",
    type = "toggle",
    label = "Clean Tracking Path Segments",
    description = "Remove tracking path components such as Amazon /ref=... and StackOverflow sharer user IDs.",
    default = true,
  },
  {
    key = "shorten_amazon",
    type = "toggle",
    label = "Shorten Amazon Product URLs",
    description = "Rewrite Amazon product links to canonical /dp/ASIN form.",
    default = false,
  },
  {
    key = "clean_fragments",
    type = "toggle",
    label = "Clean Tracking Fragments",
    description = "Strip tracking parameters placed after # (e.g. #utm_source=..., #Echobox=...).",
    default = true,
  },
  {
    key = "skip_code_blocks",
    type = "toggle",
    label = "Preserve Code Blocks",
    description = "Leave URLs inside inline code (`...`) and fenced code blocks (```...```) untouched.",
    default = true,
  },

  { type = "section", label = "Feedback & Quick Overrides" },
  {
    key = "show_message_badge",
    type = "toggle",
    label = "Show (tracking removed) Indicator",
    description = "Attach a clickable (tracking removed) label to cleaned messages that opens a popup showing exactly what was modified. Does not alter C-Cord's (edited) text.",
    default = true,
  },
  {
    key = "badge_placement",
    type = "select",
    label = "Indicator Placement",
    description = "Choose where to display the clickable (tracking removed) indicator on cleaned messages.",
    default = "accessory",
    options = {
      { label = "Below message (accessory)", value = "accessory" },
      { label = "Message header (badge)", value = "badge" },
    },
  },
  {
    key = "show_toast",
    type = "toggle",
    label = "Show Toast Notifications",
    description = "Display a brief notification when trackers are removed or redirects unwrapped.",
    default = true,
  },
  {
    key = "custom_params",
    type = "text",
    label = "Extra Tracking Parameters",
    description = "Comma-separated parameter names to always strip (supports trailing * wildcard, e.g. promo_*).",
    placeholder = "my_tracker, promo_*, custom_ref",
    default = "",
  },
  {
    key = "ignored_domains",
    type = "text",
    label = "Ignored Domains",
    description = "Comma-separated domains (and their subdomains) to never modify.",
    placeholder = "example.com, internal.corp",
    default = "",
  },
})

-- ============================================================================
-- Cached Options, Filter List Compilation & Persistent Statistics
-- ============================================================================

local LIST_SETTING_KEYS = {
  list_adguard = true,
  list_dandelionsprout = true,
  list_clearurls = true,
  custom_list_urls = true,
}

local cached_opts = nil

local function build_options()
  local custom_exact, custom_prefixes = cleaner.parse_custom_params(settings.get("custom_params", ""))
  local ignored_domains = cleaner.parse_domain_list(settings.get("ignored_domains", ""))
  return {
    strict_canonical = settings.get("strict_canonical", true) ~= false,
    use_builtin_rules = settings.get("use_builtin_rules", true) ~= false,
    unwrap_redirects = settings.get("unwrap_redirects", true) ~= false,
    clean_paths = settings.get("clean_paths", true) ~= false,
    shorten_amazon = settings.get("shorten_amazon", false) == true,
    clean_fragments = settings.get("clean_fragments", true) ~= false,
    skip_code_blocks = settings.get("skip_code_blocks", true) ~= false,
    custom_exact = custom_exact,
    custom_prefixes = custom_prefixes,
    ignored_domains = ignored_domains,
    compiled_lists = lists.get_index(),
  }
end

local function get_options()
  if not cached_opts then
    cached_opts = build_options()
  end
  return cached_opts
end

local function invalidate_options()
  cached_opts = nil
end

-- Load any previously cached remote lists, local lists, and cleaned-message indicators at startup
lists.rebuild()
transparency.init()

settings.on_change(function(key, val)
  invalidate_options()
  log.debug("Setting updated: " .. tostring(key) .. " = " .. tostring(val))
  if key == "show_message_badge" or key == "badge_placement" then
    transparency.refresh_all_decorations()
  end
  if LIST_SETTING_KEYS[key] then
    lists.rebuild()
    invalidate_options()
    if settings.get("auto_update_lists", true) ~= false then
      lists.sync_all(false, function()
        invalidate_options()
      end)
    end
  end
end)

-- Schedule non-blocking initial sync (if lists are missing/stale) and periodic background refresh
time.after(2500, function()
  if settings.get("auto_update_lists", true) ~= false then
    lists.sync_all(false, function(report)
      invalidate_options()
      if report.updated > 0 then
        log.info(string.format(
          "Auto-updated %d filter list(s); %d total compiled rules active",
          report.updated, report.total_rules
        ))
      end
    end)
  end
end)

time.every(3600 * 1000, function()
  if settings.get("auto_update_lists", true) ~= false then
    lists.sync_all(false, function(report)
      if report.updated > 0 then
        invalidate_options()
      end
    end)
  end
end)

local function load_stats()
  local s = storage.get("stats")
  if type(s) ~= "table" then
    s = {}
  end
  return {
    urls_cleaned = tonumber(s.urls_cleaned) or 0,
    params_removed = tonumber(s.params_removed) or 0,
    redirects_unwrapped = tonumber(s.redirects_unwrapped) or 0,
    links_opened_cleaned = tonumber(s.links_opened_cleaned) or 0,
    messages_cleaned = tonumber(s.messages_cleaned) or 0,
  }
end

local stats = load_stats()

local function save_stats()
  storage.set("stats", stats)
end

local function plural(n, singular, plural_form)
  if n == 1 then
    return "1 " .. singular
  end
  return tostring(n) .. " " .. (plural_form or (singular .. "s"))
end

local function format_url_summary(info)
  local parts = {}
  if info.unwrapped_count > 0 then
    parts[#parts + 1] = "unwrapped " .. plural(info.unwrapped_count, "redirect")
  end
  if #info.removed_params > 0 then
    parts[#parts + 1] = "removed " .. plural(#info.removed_params, "tracker")
  end
  if info.path_cleaned then
    parts[#parts + 1] = "cleaned path"
  end
  if #parts == 0 then
    return "cleaned URL"
  end
  return table.concat(parts, ", ")
end

local function format_message_summary(msg_stats)
  local parts = {}
  if msg_stats.redirects_unwrapped > 0 then
    parts[#parts + 1] = "unwrapped " .. plural(msg_stats.redirects_unwrapped, "redirect")
  end
  if msg_stats.params_removed > 0 then
    parts[#parts + 1] = "stripped " .. plural(msg_stats.params_removed, "tracker")
  end
  if #parts == 0 then
    parts[#parts + 1] = "cleaned " .. plural(msg_stats.urls_cleaned, "link")
  else
    parts[#parts + 1] = "across " .. plural(msg_stats.urls_cleaned, "link")
  end
  return table.concat(parts, ", ")
end

-- ============================================================================
-- Interception Hooks: Outgoing Messages, Edited Messages, and Link Opens
-- ============================================================================

local function handle_message_hook(content, kind, meta)
  if settings.get("enabled", true) == false then
    return nil
  end
  if type(content) ~= "string" or content == "" then
    return nil
  end

  local cleaned, msg_stats = cleaner.clean_text(content, get_options())
  if not msg_stats.changed then
    return nil
  end

  stats.messages_cleaned = stats.messages_cleaned + 1
  stats.urls_cleaned = stats.urls_cleaned + msg_stats.urls_cleaned
  stats.params_removed = stats.params_removed + msg_stats.params_removed
  stats.redirects_unwrapped = stats.redirects_unwrapped + msg_stats.redirects_unwrapped
  save_stats()

  local summary = format_message_summary(msg_stats)
  log.info("[" .. kind .. "] " .. summary)

  if kind == "send" and meta and meta.channel_id then
    pcall(transparency.record_pending_send, meta.channel_id, content, cleaned, msg_stats, summary)
  elseif kind == "edit" and meta and meta.message_id then
    pcall(transparency.record_edit, meta.channel_id, meta.message_id, content, cleaned, msg_stats, summary)
  end

  if settings.get("show_toast", true) ~= false then
    ui.toast.show("Tracking Removal: " .. summary, "info")
  end

  return { content = cleaned }
end

hooks.on_before_send(function(data)
  if settings.get("clean_on_send", true) == false then
    return nil
  end
  if type(data) ~= "table" then
    return nil
  end
  local ok, res = pcall(handle_message_hook, data.content, "send", data)
  if not ok then
    log.warn("Error in on_before_send hook: " .. tostring(res))
    return nil
  end
  return res
end)

hooks.on_before_edit(function(data)
  if settings.get("clean_on_edit", true) == false then
    return nil
  end
  if type(data) ~= "table" then
    return nil
  end
  local ok, res = pcall(handle_message_hook, data.content, "edit", data)
  if not ok then
    log.warn("Error in on_before_edit hook: " .. tostring(res))
    return nil
  end
  return res
end)

-- Correlate cleaned sends to their message IDs and maintain "(tracking removed)" indicators
events.on("message.create", function(ev)
  local ok, err = pcall(transparency.on_message_create, ev)
  if not ok then
    log.warn("Error in message.create handler: " .. tostring(err))
  end
end)

events.on("message.update", function(ev)
  local ok, err = pcall(transparency.on_message_update, ev)
  if not ok then
    log.warn("Error in message.update handler: " .. tostring(err))
  end
end)

events.on("message.delete", function(ev)
  local ok, err = pcall(transparency.on_message_delete, ev)
  if not ok then
    log.warn("Error in message.delete handler: " .. tostring(err))
  end
end)

hooks.on_link_open(function(data)
  if settings.get("enabled", true) == false then
    return nil
  end
  if settings.get("clean_on_link_open", true) == false then
    return nil
  end
  if type(data) ~= "table" or type(data.url) ~= "string" or data.url == "" then
    return nil
  end

  local ok, cleaned, info = pcall(cleaner.clean_url, data.url, get_options())
  if not ok then
    log.warn("Error in on_link_open hook: " .. tostring(cleaned))
    return nil
  end
  if not info or not info.changed then
    return nil
  end

  stats.links_opened_cleaned = stats.links_opened_cleaned + 1
  stats.urls_cleaned = stats.urls_cleaned + 1
  stats.params_removed = stats.params_removed + #info.removed_params
  stats.redirects_unwrapped = stats.redirects_unwrapped + info.unwrapped_count
  save_stats()

  local summary = format_url_summary(info)
  log.debug("[open] " .. summary)

  if settings.get("show_toast", true) ~= false then
    ui.toast.show("Cleaned link before opening (" .. summary .. ")", "info")
  end

  return { url = cleaned }
end)

-- ============================================================================
-- Context Menu: Right-Click Any Link -> Copy Clean URL
-- ============================================================================

ui.contextMenu.add({
  id = "copy-clean-url",
  label = "Copy Clean URL (No Tracking)",
  target = "link",
  when = { has_url = true },
  divider_before = true,
  action = function(ctx)
    local raw_url = ctx and ctx.url
    if type(raw_url) ~= "string" or raw_url == "" then
      ui.toast.show("No URL found to clean", "warn")
      return
    end
    local cleaned, info = cleaner.clean_url(raw_url, get_options())
    clipboard.write(cleaned)
    if info.changed then
      stats.urls_cleaned = stats.urls_cleaned + 1
      stats.params_removed = stats.params_removed + #info.removed_params
      stats.redirects_unwrapped = stats.redirects_unwrapped + info.unwrapped_count
      save_stats()
      ui.toast.show("Copied clean URL (" .. format_url_summary(info) .. ")", "info")
    else
      ui.toast.show("Copied URL (already clean)", "info")
    end
  end,
})

-- ============================================================================
-- Slash Command: /cleanurl
-- ============================================================================

local function trim(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function extract_picked_file(res)
  if type(res) ~= "table" then
    return nil, nil
  end
  local entry = res
  if type(res.files) == "table" and type(res.files[1]) == "table" then
    entry = res.files[1]
  elseif type(res[1]) == "table" then
    entry = res[1]
  end
  local data = entry.data or entry.content or entry.bytes
  local name = entry.name or entry.filename or entry.path or "custom-list.txt"
  return name, data
end

local function run_manual_sync()
  if lists.is_syncing() then
    ui.toast.show("Filter list update already in progress...", "info")
    return
  end
  ui.toast.show("Updating filter lists...", "info")
  local started = lists.sync_all(true, function(report)
    invalidate_options()
    if report.failed > 0 and report.updated == 0 then
      ui.toast.show("Filter list update failed: " .. tostring(report.errors[1] or "network error"), "error")
    elseif report.failed > 0 then
      ui.toast.show(
        string.format("Updated %d list(s), %d failed (%d rules active)", report.updated, report.failed, report.total_rules),
        "warn"
      )
    else
      ui.toast.show(
        string.format("Updated %d list(s) — %d rules active", report.updated, report.total_rules),
        "info"
      )
    end
  end)
  if not started then
    ui.toast.show("No remote filter lists are currently enabled", "warn")
  end
end

local CMD_SUGGESTIONS = {
  { label = "lists", detail = "View active 3rd-party & custom filter lists", insert_text = "lists" },
  { label = "update", detail = "Force-update all enabled remote filter lists", insert_text = "update" },
  { label = "import", detail = "Import a local custom filter list (.txt / .json)", insert_text = "import" },
  { label = "add-list", detail = "Subscribe to a custom HTTPS filter list URL", insert_text = "add-list " },
  { label = "remove-list", detail = "Remove a custom remote or local filter list", insert_text = "remove-list " },
  { label = "inspect", detail = "Preview before/after for a URL in a dialog", insert_text = "inspect " },
  { label = "stats", detail = "Show lifetime tracking-removal statistics", insert_text = "stats" },
  { label = "toggle", detail = "Toggle automatic tracking removal on/off", insert_text = "toggle" },
  { label = "reset", detail = "Reset saved statistics counters", insert_text = "reset" },
}

commands.register({
  name = "cleanurl",
  description = "Manage tracking filter lists, inspect/clean URLs, toggle, or view stats",
  autocomplete = function(args)
    local q = trim(args):lower()
    local matches = {}
    for i = 1, #CMD_SUGGESTIONS do
      local item = CMD_SUGGESTIONS[i]
      if q == "" or item.label:sub(1, #q) == q then
        matches[#matches + 1] = item
      end
    end
    return matches
  end,
  run = function(args)
    local input = trim(args)
    local lower = input:lower()

    if input == "" or lower == "stats" then
      local state = (settings.get("enabled", true) ~= false) and "ON" or "OFF"
      local idx = lists.get_index()
      local rule_count = idx and idx.total_rules or 0
      ui.toast.show(
        string.format(
          "Tracking Removal [%s | %d list rules]: %d URLs cleaned, %d trackers stripped, %d redirects unwrapped",
          state,
          rule_count,
          stats.urls_cleaned,
          stats.params_removed,
          stats.redirects_unwrapped
        ),
        "info"
      )
      return nil
    end

    if lower == "toggle" then
      local next_state = (settings.get("enabled", true) == false)
      settings.set("enabled", next_state)
      ui.toast.show("Tracking Removal " .. (next_state and "enabled" or "paused"), "info")
      return nil
    end

    if lower == "lists" then
      async.spawn(function()
        local res = ui.dialog.confirm({
          title = "Active Filter Lists",
          message = lists.format_status_report(),
          confirm_label = "Update Now",
          cancel_label = "Close",
        })
        if res and res.accepted then
          run_manual_sync()
        end
      end)
      return nil
    end

    if lower == "update" then
      run_manual_sync()
      return nil
    end

    if lower == "import" then
      async.spawn(function()
        local res, err = ui.file.pick({
          title = "Import Tracking Filter List (.txt or .json)",
          filters = {
            { name = "Filter Lists", extensions = { "txt", "json" } },
          },
          multiple = false,
        })
        if err then
          ui.toast.show("File import failed: " .. tostring(err), "error")
          return
        end
        if not res then
          return
        end
        local name, data = extract_picked_file(res)
        if type(data) ~= "string" or data == "" then
          ui.toast.show("Could not read selected file data", "warn")
          return
        end
        local ok, result = lists.import_local_list(name, data)
        if ok then
          invalidate_options()
          ui.toast.show(
            string.format("Imported '%s' (%d rules, %s format)", result.name, result.rule_count, result.format),
            "info"
          )
        else
          ui.toast.show("Import failed: " .. tostring(result), "error")
        end
      end)
      return nil
    end

    local add_url = input:match("^[Aa][Dd][Dd]%-?[Ll][Ii][Ss][Tt]%s+(.+)$")
    if add_url then
      local ok, err = lists.add_custom_url(add_url, function(report)
        invalidate_options()
        if report.failed > 0 and report.updated == 0 then
          ui.toast.show("Failed to fetch custom list: " .. tostring(report.errors[1] or "error"), "error")
        else
          ui.toast.show(
            string.format("Custom list added & synced (%d rules active)", report.total_rules),
            "info"
          )
        end
      end)
      if not ok then
        ui.toast.show(tostring(err), "warn")
      else
        ui.toast.show("Added custom list, fetching...", "info")
      end
      return nil
    end

    local rem_target = input:match("^[Rr][Ee][Mm][Oo][Vv][Ee]%-?[Ll][Ii][Ss][Tt]%s+(.+)$")
    if rem_target then
      local removed, label = lists.remove_custom_list(rem_target)
      if removed then
        invalidate_options()
        ui.toast.show("Removed " .. tostring(label), "info")
      else
        ui.toast.show("No matching custom or local list found for '" .. trim(rem_target) .. "'", "warn")
      end
      return nil
    end

    if lower == "reset" then
      stats = {
        urls_cleaned = 0,
        params_removed = 0,
        redirects_unwrapped = 0,
        links_opened_cleaned = 0,
        messages_cleaned = 0,
      }
      save_stats()
      ui.toast.show("Tracking Removal statistics reset", "info")
      return nil
    end

    local inspect_target = input:match("^[Ii][Nn][Ss][Pp][Ee][Cc][Tt]%s+(.+)$")
    if inspect_target then
      inspect_target = trim(inspect_target)
      local cleaned, info = cleaner.clean_url(inspect_target, get_options())
      if not info.valid then
        ui.toast.show("Not a valid http(s) URL to inspect", "warn")
        return nil
      end
      local removed_list = (#info.removed_params > 0) and table.concat(info.removed_params, ", ") or "(none)"
      local details = table.concat({
        "Original:\n" .. info.original,
        "\nCleaned:\n" .. cleaned,
        "\nRemoved params: " .. removed_list,
        "Redirects unwrapped: " .. tostring(info.unwrapped_count),
        "Path cleaned: " .. (info.path_cleaned and "yes" or "no"),
        "Fragment cleaned: " .. (info.fragment_cleaned and "yes" or "no"),
      }, "\n")
      async.spawn(function()
        local res = ui.dialog.confirm({
          title = info.changed and "Tracking Removed" or "URL Already Clean",
          message = details,
          confirm_label = "Copy Clean URL",
          cancel_label = "Close",
        })
        if res and res.accepted then
          clipboard.write(cleaned)
          ui.toast.show("Copied clean URL to clipboard", "info")
        end
      end)
      return nil
    end

    -- Clean arbitrary URL or text and copy result to clipboard
    local cleaned_text, text_stats = cleaner.clean_text(input, get_options())
    if text_stats.urls_found == 0 then
      ui.toast.show("No http(s) URLs found in input", "warn")
      return nil
    end
    clipboard.write(cleaned_text)
    if text_stats.changed then
      ui.toast.show("Copied clean result (" .. format_message_summary(text_stats) .. ")", "info")
    else
      ui.toast.show("URL is already clean (copied to clipboard)", "info")
    end
    return nil
  end,
})

-- ============================================================================
-- Inter-Plugin RPC (Allow other plugins to sanitize URLs cleanly)
-- ============================================================================

plugin.expose("clean_url", function(url)
  if type(url) ~= "string" then
    return nil
  end
  local cleaned, info = cleaner.clean_url(url, get_options())
  return {
    url = cleaned,
    changed = info.changed,
    removed_params = info.removed_params,
    unwrapped_count = info.unwrapped_count,
  }
end, { allow_lower_class = true })

plugin.expose("clean_text", function(text)
  if type(text) ~= "string" then
    return nil
  end
  local cleaned, text_stats = cleaner.clean_text(text, get_options())
  return {
    text = cleaned,
    changed = text_stats.changed,
    urls_cleaned = text_stats.urls_cleaned,
    params_removed = text_stats.params_removed,
    redirects_unwrapped = text_stats.redirects_unwrapped,
  }
end, { allow_lower_class = true })

plugin.expose("list_status", function()
  local idx = lists.get_index()
  return {
    total_rules = idx and idx.total_rules or 0,
    sources = idx and idx.sources or {},
    syncing = lists.is_syncing(),
  }
end, { allow_lower_class = true })

local active_idx = lists.get_index()
log.info(string.format(
  "%s v%s ready (%d cached list rules loaded)",
  plugin.name, plugin.version, active_idx and active_idx.total_rules or 0
))
