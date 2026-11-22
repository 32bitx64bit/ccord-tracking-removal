-- Tracking Removal — Clickable "(tracking removed)" Message Indicator & Transparency Modal
-- Attaches a native C-Cord message decoration to messages cleaned by this plugin
-- and opens a transparent Before/After diff modal when clicked.
-- Never mutates or interferes with C-Cord's built-in "(edited)" indicator.

local M = {}

local MODAL_ID = "tracking-diff-modal"
local DECOR_PREFIX = "tr-msg-"
local STORAGE_KEY = "cleaned_messages"
local MAX_STORED_RECORDS = 60
local PENDING_TTL_MS = 30000

local records = {}
local pending_sends = {}
local active_modal_record = nil

local function trim(s)
  if type(s) ~= "string" then
    return ""
  end
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function plural(n, singular, plural_form)
  if n == 1 then
    return "1 " .. singular
  end
  return tostring(n) .. " " .. (plural_form or (singular .. "s"))
end

local function make_short_summary(msg_stats)
  local parts = {}
  if msg_stats.redirects_unwrapped > 0 then
    parts[#parts + 1] = plural(msg_stats.redirects_unwrapped, "redirect") .. " unwrapped"
  end
  if msg_stats.params_removed > 0 then
    parts[#parts + 1] = plural(msg_stats.params_removed, "tracker") .. " stripped"
  end
  if #parts == 0 then
    return plural(msg_stats.urls_cleaned, "link") .. " cleaned"
  end
  return table.concat(parts, ", ")
end

local function clone_changes(changes)
  local out = {}
  if type(changes) ~= "table" then
    return out
  end
  for i = 1, #changes do
    local c = changes[i]
    local rp = {}
    if type(c.removed_params) == "table" then
      for j = 1, #c.removed_params do
        rp[j] = tostring(c.removed_params[j])
      end
    end
    out[i] = {
      original = tostring(c.original or ""),
      cleaned = tostring(c.cleaned or ""),
      removed_params = rp,
      unwrapped_count = tonumber(c.unwrapped_count) or 0,
      path_cleaned = c.path_cleaned == true,
      fragment_cleaned = c.fragment_cleaned == true,
    }
  end
  return out
end

local function prune_records()
  local keys = {}
  for mid, rec in pairs(records) do
    keys[#keys + 1] = { id = mid, ts = tonumber(rec.cleaned_at) or 0 }
  end
  if #keys <= MAX_STORED_RECORDS then
    return
  end
  table.sort(keys, function(a, b) return a.ts < b.ts end)
  local to_drop = #keys - MAX_STORED_RECORDS
  for i = 1, to_drop do
    local mid = keys[i].id
    records[mid] = nil
    pcall(ui.decorate.remove, DECOR_PREFIX .. mid)
  end
end

local function save_records()
  prune_records()
  storage.set(STORAGE_KEY, records)
end

local function load_records()
  local saved = storage.get(STORAGE_KEY)
  if type(saved) ~= "table" then
    records = {}
    return
  end
  records = {}
  for mid, rec in pairs(saved) do
    if type(mid) == "string" and type(rec) == "table" and type(rec.changes) == "table" then
      records[mid] = rec
    end
  end
end

local function prune_pending(now)
  local kept = {}
  for i = 1, #pending_sends do
    if (now - pending_sends[i].created_at) <= PENDING_TTL_MS then
      kept[#kept + 1] = pending_sends[i]
    end
  end
  pending_sends = kept
end

local function safe_theme_color(token, fallback)
  if _G.theme and type(_G.theme.color) == "function" then
    local c = _G.theme.color(token)
    if type(c) == "string" and c ~= "" then
      return c
    end
  end
  return fallback
end

-- ============================================================================
-- Native Transparency Diff Modal (ui.panel slot = "modal")
-- ============================================================================

local function close_modal()
  active_modal_record = nil
  pcall(ui.panel.unmount, MODAL_ID)
end

local function build_change_card(idx, change, palette)
  local badges = {}
  if change.unwrapped_count > 0 then
    badges[#badges + 1] = {
      type = "badge",
      text = plural(change.unwrapped_count, "redirect") .. " unwrapped",
      color = palette.text_on_brand,
      bg = palette.brand,
    }
  end
  if change.path_cleaned then
    badges[#badges + 1] = {
      type = "badge",
      text = "path cleaned",
      color = palette.text_normal,
      bg = palette.bg_tertiary,
    }
  end
  if change.fragment_cleaned then
    badges[#badges + 1] = {
      type = "badge",
      text = "fragment cleaned",
      color = palette.text_normal,
      bg = palette.bg_tertiary,
    }
  end
  local max_badges = math.min(#change.removed_params, 12)
  for j = 1, max_badges do
    badges[#badges + 1] = {
      type = "badge",
      text = "-" .. change.removed_params[j],
      color = palette.danger,
      bg = palette.bg_tertiary,
    }
  end
  if #change.removed_params > max_badges then
    badges[#badges + 1] = {
      type = "badge",
      text = "+" .. tostring(#change.removed_params - max_badges) .. " more",
      color = palette.text_muted,
      bg = palette.bg_tertiary,
    }
  end

  local children = {
    {
      type = "row",
      gap = 6,
      align = "center",
      children = {
        { type = "text", text = "Link #" .. tostring(idx), bold = true, size = 13, color = palette.text_header },
        { type = "spacer", flex = 1 },
        { id = "copy-clean-" .. tostring(idx), type = "button", text = "Copy Clean" },
        { id = "copy-orig-" .. tostring(idx), type = "button", text = "Copy Original" },
      },
    },
  }

  if #badges > 0 then
    children[#children + 1] = {
      type = "row",
      gap = 4,
      align = "center",
      children = badges,
    }
  end

  children[#children + 1] = {
    type = "text",
    text = "Original (before cleaning):",
    size = 11,
    bold = true,
    color = palette.danger,
  }
  children[#children + 1] = {
    type = "box",
    bg = palette.bg_tertiary,
    border = palette.border_subtle,
    radius = 4,
    padding = 6,
    children = {
      { type = "text", text = change.original, size = 12, color = palette.text_muted, wrap = true },
    },
  }
  children[#children + 1] = {
    type = "text",
    text = "Sent to Discord (clean):",
    size = 11,
    bold = true,
    color = palette.green,
  }
  children[#children + 1] = {
    type = "box",
    bg = palette.bg_tertiary,
    border = palette.border_subtle,
    radius = 4,
    padding = 6,
    children = {
      { type = "text", text = change.cleaned, size = 12, color = palette.text_normal, wrap = true },
    },
  }

  return {
    type = "box",
    bg = palette.bg_secondary,
    border = palette.border_subtle,
    radius = 8,
    padding = 10,
    children = {
      {
        type = "col",
        gap = 6,
        children = children,
      },
    },
  }
end

local function format_fallback_text(record)
  local lines = {
    "Cleaned before sending to Discord (" .. tostring(record.short_summary or "tracking removed") .. ")",
    "",
  }
  for i = 1, #record.changes do
    local c = record.changes[i]
    lines[#lines + 1] = "Link #" .. tostring(i) .. ":"
    lines[#lines + 1] = "  Original: " .. c.original
    lines[#lines + 1] = "  Sent:     " .. c.cleaned
    if #c.removed_params > 0 then
      lines[#lines + 1] = "  Removed:  " .. table.concat(c.removed_params, ", ")
    end
    if c.unwrapped_count > 0 then
      lines[#lines + 1] = "  Unwrapped redirects: " .. tostring(c.unwrapped_count)
    end
    lines[#lines + 1] = ""
  end
  return table.concat(lines, "\n")
end

---Opens a native C-Cord modal displaying every link modification made to `record`.
---@param record table
function M.open_modal(record)
  if type(record) ~= "table" then
    return
  end

  close_modal()
  active_modal_record = record

  local palette = {
    bg_primary = safe_theme_color("bg_primary", "#1b1b20"),
    bg_secondary = safe_theme_color("bg_secondary", "#222228"),
    bg_tertiary = safe_theme_color("bg_tertiary", "#141417"),
    border_subtle = safe_theme_color("border_subtle", "#2a2a33"),
    text_header = safe_theme_color("text_header", "#f0f0f3"),
    text_normal = safe_theme_color("text_normal", "#d4d4d8"),
    text_muted = safe_theme_color("text_muted", "#9393a0"),
    text_on_brand = safe_theme_color("text_on_brand", "#ffffff"),
    brand = safe_theme_color("brand", "#6e7bf2"),
    danger = safe_theme_color("danger", "#ec565b"),
    green = safe_theme_color("status_online", "#3ba55d"),
  }

  local cards = {}
  for i = 1, #record.changes do
    cards[#cards + 1] = build_change_card(i, record.changes[i], palette)
  end

  local subtitle = (record.source == "edit")
    and "Sanitized before your edit was sent to Discord."
    or "Sanitized before your message was sent to Discord (Discord never saw the tracking params)."

  local root = {
    type = "col",
    gap = 10,
    padding = 14,
    children = {
      {
        type = "row",
        gap = 8,
        align = "center",
        children = {
          { type = "text", text = "Tracking Removed", bold = true, size = 16, color = palette.text_header },
          {
            type = "badge",
            text = record.short_summary or "cleaned",
            color = palette.text_on_brand,
            bg = palette.brand,
          },
        },
      },
      {
        type = "text",
        text = subtitle,
        size = 12,
        color = palette.text_muted,
        wrap = true,
      },
      { type = "divider", color = palette.border_subtle },
      {
        type = "scroll",
        max_height = 250,
        children = {
          {
            type = "col",
            gap = 8,
            children = cards,
          },
        },
      },
      { type = "divider", color = palette.border_subtle },
      {
        type = "row",
        gap = 8,
        align = "center",
        children = {
          { id = "copy-full-clean", type = "button", text = "Copy Clean Message" },
          { type = "spacer", flex = 1 },
          { id = "close-btn", type = "button", text = "Close", style = "brand" },
        },
      },
    },
  }

  local ok, mounted = pcall(ui.panel.mount, {
    id = MODAL_ID,
    slot = "modal",
    title = "Tracking Removed",
    width = 540,
    height = 410,
    root = root,
    on_event = function(ev)
      if type(ev) ~= "table" then
        return
      end
      if ev.kind == "close" or (ev.kind == "key_down" and ev.key == "Escape") then
        close_modal()
        return
      end
      if ev.kind ~= "click" then
        return
      end
      local nid = ev.node_id
      if nid == "close-btn" then
        close_modal()
        return
      end
      local cur = active_modal_record
      if not cur then
        return
      end
      if nid == "copy-full-clean" then
        clipboard.write(cur.cleaned or "")
        ui.toast.show("Copied clean message", "info")
        return
      end
      local clean_idx = type(nid) == "string" and tonumber(nid:match("^copy%-clean%-(%d+)$"))
      if clean_idx and cur.changes[clean_idx] then
        clipboard.write(cur.changes[clean_idx].cleaned)
        ui.toast.show("Copied clean URL", "info")
        return
      end
      local orig_idx = type(nid) == "string" and tonumber(nid:match("^copy%-orig%-(%d+)$"))
      if orig_idx and cur.changes[orig_idx] then
        clipboard.write(cur.changes[orig_idx].original)
        ui.toast.show("Copied original URL", "info")
        return
      end
    end,
  })

  if not ok or not mounted then
    -- Graceful fallback to native confirm dialog if modal mount fails
    async.spawn(function()
      local res = ui.dialog.confirm({
        title = "Tracking Removed",
        message = format_fallback_text(record),
        confirm_label = "Copy Clean Message",
        cancel_label = "Close",
      })
      if res and res.accepted then
        clipboard.write(record.cleaned or "")
        ui.toast.show("Copied clean message", "info")
      end
    end)
  end
end

-- ============================================================================
-- Message Decoration Attachment & Lifecycle
-- ============================================================================

function M.attach_decoration(message_id, record)
  if settings.get("show_message_badge", true) == false then
    return false
  end
  if type(message_id) ~= "string" or message_id == "" or type(record) ~= "table" then
    return false
  end

  local dec_id = DECOR_PREFIX .. message_id
  pcall(ui.decorate.remove, dec_id)

  local placement = settings.get("badge_placement", "accessory")
  local muted = safe_theme_color("text_muted", "#9393a0")

  local on_event = function(ev, target_id)
    if type(ev) == "table" and ev.kind == "click" then
      local rec = records[target_id or message_id] or record
      M.open_modal(rec)
    end
  end

  if placement == "badge" then
    return ui.decorate.message_badge({
      id = dec_id,
      target_id = message_id,
      widget = {
        id = "open-diff",
        type = "button",
        text = "(tracking removed)",
      },
      on_event = on_event,
    })
  end

  return ui.decorate.message_accessory({
    id = dec_id,
    target_id = message_id,
    widget = {
      type = "row",
      gap = 6,
      align = "center",
      children = {
        {
          id = "open-diff",
          type = "button",
          text = "(tracking removed)",
        },
        {
          type = "text",
          text = record.short_summary or "click to inspect",
          size = 11,
          color = muted,
        },
      },
    },
    on_event = on_event,
  })
end

function M.remove_decoration(message_id)
  if type(message_id) ~= "string" or message_id == "" then
    return
  end
  pcall(ui.decorate.remove, DECOR_PREFIX .. message_id)
end

function M.refresh_all_decorations()
  pcall(ui.decorate.clear)
  if settings.get("show_message_badge", true) == false then
    return
  end
  for mid, rec in pairs(records) do
    M.attach_decoration(mid, rec)
  end
end

---Records a cleaned outgoing message from `hooks.on_before_send` so it can be
---correlated to its snowflake `message_id` when `message.create` arrives.
function M.record_pending_send(channel_id, original, cleaned, msg_stats, summary)
  if type(channel_id) ~= "string" or channel_id == "" then
    return
  end
  local now = time.now_ms()
  prune_pending(now)
  pending_sends[#pending_sends + 1] = {
    channel_id = channel_id,
    original = original,
    cleaned = cleaned,
    summary = summary,
    short_summary = make_short_summary(msg_stats),
    changes = clone_changes(msg_stats.changes),
    created_at = now,
  }
end

---Records a cleaned message edit from `hooks.on_before_edit` (already has `message_id`).
function M.record_edit(channel_id, message_id, original, cleaned, msg_stats, summary)
  if type(message_id) ~= "string" or message_id == "" then
    return
  end
  local rec = {
    message_id = message_id,
    channel_id = channel_id or "",
    original = original,
    cleaned = cleaned,
    summary = summary,
    short_summary = make_short_summary(msg_stats),
    source = "edit",
    cleaned_at = time.now_ms(),
    changes = clone_changes(msg_stats.changes),
  }
  records[message_id] = rec
  save_records()
  M.attach_decoration(message_id, rec)
end

local function is_own_message(ev)
  if not (_G.store and type(_G.store.self) == "function") then
    return true
  end
  local ok, me = pcall(_G.store.self)
  if not ok or type(me) ~= "table" or not me.id then
    return true
  end
  if not ev.author_id then
    return true
  end
  return tostring(ev.author_id) == tostring(me.id)
end

---Handles `message.create` to bind pending cleaned sends to their real Discord `message_id`.
function M.on_message_create(ev)
  if type(ev) ~= "table" or type(ev.message_id) ~= "string" or ev.message_id == "" then
    return
  end
  if #pending_sends == 0 then
    return
  end
  if not is_own_message(ev) then
    return
  end

  local now = time.now_ms()
  prune_pending(now)

  local ev_content_trimmed = trim(ev.content)
  for i = 1, #pending_sends do
    local p = pending_sends[i]
    if p.channel_id == ev.channel_id and trim(p.cleaned) == ev_content_trimmed then
      table.remove(pending_sends, i)
      local rec = {
        message_id = ev.message_id,
        channel_id = ev.channel_id,
        original = p.original,
        cleaned = p.cleaned,
        summary = p.summary,
        short_summary = p.short_summary,
        source = "send",
        cleaned_at = now,
        changes = p.changes,
      }
      records[ev.message_id] = rec
      save_records()
      M.attach_decoration(ev.message_id, rec)
      return
    end
  end
end

---Handles `message.update` without ever interfering with C-Cord's native "(edited)" indicator.
---If the user manually edited the message and removed all previously cleaned links,
---removes our stale "(tracking removed)" indicator.
function M.on_message_update(ev)
  if type(ev) ~= "table" or type(ev.message_id) ~= "string" then
    return
  end
  local existing = records[ev.message_id]
  if not existing then
    return
  end
  if type(ev.content) ~= "string" then
    return
  end

  local still_present = false
  for i = 1, #existing.changes do
    local cleaned_url = existing.changes[i].cleaned
    if cleaned_url ~= "" and ev.content:find(cleaned_url, 1, true) then
      still_present = true
      break
    end
  end

  if not still_present then
    records[ev.message_id] = nil
    M.remove_decoration(ev.message_id)
    save_records()
  end
end

---Handles `message.delete` to clean up stored records and decorations.
function M.on_message_delete(ev)
  if type(ev) ~= "table" or type(ev.message_id) ~= "string" then
    return
  end
  if records[ev.message_id] then
    records[ev.message_id] = nil
    M.remove_decoration(ev.message_id)
    save_records()
  end
end

function M.get_record(message_id)
  return records[message_id]
end

function M.init()
  load_records()
  M.refresh_all_decorations()
end

return M
