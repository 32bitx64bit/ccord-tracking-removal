-- Strict C-Cord Lua 5.5 Sandbox & Lifecycle Integration Test for main.lua
-- Verifies manifest validity, sandbox compliance (no forbidden globals),
-- declared permissions, hooks, 3rd-party list auto-sync, custom URL/local import,
-- settings, storage, context menu, slash commands, and RPC.
-- Run from plugin root: lua5.5 tests/test_main.lua

local passed = 0
local failed = 0

local function assert_eq(name, actual, expected)
  if actual == expected then
    passed = passed + 1
  else
    failed = failed + 1
    io.stderr:write(string.format(
      "[FAIL] %s\n  expected: %q\n  actual:   %q\n",
      name, tostring(expected), tostring(actual)
    ))
  end
end

local function assert_true(name, cond)
  if cond then
    passed = passed + 1
  else
    failed = failed + 1
    io.stderr:write(string.format("[FAIL] %s (expected truthy)\n", name))
  end
end

-- ============================================================================
-- 1. Validate plugin.json against C-Cord manifest.c rules
-- ============================================================================
local mf = assert(io.open("plugin.json", "rb"))
local manifest_raw = mf:read("*a")
mf:close()

assert_true("plugin.json declares schema 1", manifest_raw:find('"schema"%s*:%s*1') ~= nil)
assert_true("plugin.json declares api 1", manifest_raw:find('"api"%s*:%s*1') ~= nil)
local manifest_id = manifest_raw:match('"id"%s*:%s*"([^"]+)"')
local manifest_name = manifest_raw:match('"name"%s*:%s*"([^"]+)"')
local manifest_ver = manifest_raw:match('"version"%s*:%s*"([^"]+)"')
local manifest_desc = manifest_raw:match('"description"%s*:%s*"([^"]+)"')
assert_true("plugin.json valid id format", manifest_id and manifest_id:match("^[a-z0-9][a-z0-9._-]*$") ~= nil and #manifest_id <= 64 and not manifest_id:find("..", 1, true))
assert_true("plugin.json valid name length (1..64)", manifest_name and #manifest_name >= 1 and #manifest_name <= 64)
assert_true("plugin.json valid SemVer", manifest_ver and manifest_ver:match("^%d+%.%d+%.%d+$") ~= nil)
assert_true("plugin.json description <= 200 bytes", manifest_desc and #manifest_desc <= 200)
assert_true("plugin.json declares network.http", manifest_raw:find('"network%.http"') ~= nil)

-- ============================================================================
-- 2. Build Strict C-Cord Lua 5.5 Sandbox Environment
-- ============================================================================
local function freeze(tbl)
  return setmetatable({}, {
    __index = tbl,
    __newindex = function()
      error("Attempt to mutate read-only C-Cord API table")
    end,
    __metatable = false,
  })
end

local state = {
  now_ms = 1763790000000,
  storage = {},
  settings = {},
  settings_defaults = {},
  settings_schema = nil,
  settings_listeners = {},
  hooks = {},
  events = {},
  decorations = {},
  panels = {},
  self_user = { id = "USER_SELF_123" },
  context_menus = {},
  commands = {},
  exposed = {},
  toasts = {},
  logs = {},
  timers = {},
  clipboard = nil,
  dialog_accept = true,
  last_dialog = nil,
  picked_file = nil,
  http_responses = {},
  http_calls = {},
}

local declared_perms = {
  ["messages.hook"] = true,
  ["notifications.hook"] = true,
  ["events.messages"] = true,
  ["store.read"] = true,
  ["ui.decorate"] = true,
  ["ui.panel"] = true,
  ["network.http"] = true,
}

local function require_perm(perm)
  if not declared_perms[perm] then
    error("[undeclared] Called API requiring undeclared permission: " .. perm)
  end
end

-- Pure-Lua Base64 encode/decode for sandbox emulation of `encoding`
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_MAP = {}
for i = 1, #B64 do B64_MAP[B64:byte(i)] = i - 1 end

local function mock_b64_encode(data)
  local out = {}
  local n = #data
  for i = 1, n, 3 do
    local b1 = data:byte(i)
    local b2 = data:byte(i + 1) or 0
    local b3 = data:byte(i + 2) or 0
    local triple = (b1 << 16) | (b2 << 8) | b3
    local c1 = ((triple >> 18) & 63) + 1
    local c2 = ((triple >> 12) & 63) + 1
    local c3 = ((triple >> 6) & 63) + 1
    local c4 = (triple & 63) + 1
    out[#out + 1] = B64:sub(c1, c1) .. B64:sub(c2, c2)
      .. ((i + 1 <= n) and B64:sub(c3, c3) or "=")
      .. ((i + 2 <= n) and B64:sub(c4, c4) or "=")
  end
  return table.concat(out)
end

local function mock_b64_decode(s)
  if type(s) ~= "string" or (#s % 4) ~= 0 then return nil end
  local out = {}
  for i = 1, #s, 4 do
    local a, b, c, d = s:byte(i, i + 3)
    local v1, v2 = B64_MAP[a], B64_MAP[b]
    if not v1 or not v2 then return nil end
    local p3, p4 = (c == 61), (d == 61)
    local v3 = p3 and 0 or B64_MAP[c]
    local v4 = p4 and 0 or B64_MAP[d]
    if (not p3 and not v3) or (not p4 and not v4) then return nil end
    local n = (v1 << 18) | (v2 << 12) | (v3 << 6) | v4
    out[#out + 1] = string.char((n >> 16) & 0xFF)
    if not p3 then out[#out + 1] = string.char((n >> 8) & 0xFF) end
    if not p4 then out[#out + 1] = string.char(n & 0xFF) end
  end
  return table.concat(out)
end

local safe_string = {}
for k, v in pairs(string) do
  if k ~= "dump" then
    safe_string[k] = v
  end
end

local sandbox_env
local loaded_modules = {}

local function sandbox_require(mod_name)
  assert(type(mod_name) == "string" and not mod_name:find("..", 1, true), "Invalid module name")
  if loaded_modules[mod_name] ~= nil then
    return loaded_modules[mod_name]
  end
  local path = mod_name:gsub("%.", "/") .. ".lua"
  local f = assert(io.open(path, "rb"), "Module not found: " .. path)
  local src = f:read("*a")
  f:close()
  local chunk = assert(load(src, "@" .. path, "t", sandbox_env))
  local res = chunk()
  if res == nil then res = true end
  loaded_modules[mod_name] = res
  return res
end

sandbox_env = {
  assert = assert,
  error = error,
  ipairs = ipairs,
  next = next,
  pairs = pairs,
  pcall = pcall,
  xpcall = xpcall,
  rawequal = rawequal,
  rawget = rawget,
  rawlen = rawlen,
  rawset = rawset,
  select = select,
  setmetatable = setmetatable,
  getmetatable = getmetatable,
  tonumber = tonumber,
  tostring = tostring,
  type = type,
  _VERSION = _VERSION,
  table = table,
  string = freeze(safe_string),
  math = math,
  utf8 = utf8,
  coroutine = coroutine,
  require = sandbox_require,

  plugin = freeze({
    id = manifest_id,
    name = manifest_name,
    version = manifest_ver,
    dir = "/mock/plugins/tracking-removal",
    expose = function(name, fn, opts)
      state.exposed[name] = { fn = fn, opts = opts }
      return true
    end,
  }),

  log = freeze({
    debug = function(m) state.logs[#state.logs + 1] = { level = "debug", msg = m } end,
    info = function(m) state.logs[#state.logs + 1] = { level = "info", msg = m } end,
    warn = function(m) state.logs[#state.logs + 1] = { level = "warn", msg = m } end,
    error = function(m) state.logs[#state.logs + 1] = { level = "error", msg = m } end,
  }),

  time = freeze({
    now_ms = function() return state.now_ms end,
    now_iso = function() return "2026-11-22T00:00:00Z" end,
    after = function(ms, fn)
      local id = #state.timers + 1
      state.timers[id] = { kind = "after", ms = ms, fn = fn }
      return id
    end,
    every = function(ms, fn)
      local id = #state.timers + 1
      state.timers[id] = { kind = "every", ms = ms, fn = fn }
      return id
    end,
    cancel = function(id)
      state.timers[id] = nil
      return true
    end,
  }),

  crypto = freeze({
    sha256 = function(s)
      local h1, h2 = 5381, 2166136261
      for i = 1, #s do
        local b = s:byte(i)
        h1 = ((h1 * 33) + b) % 4294967296
        h2 = ((h2 ~ b) * 16777619) % 4294967296
      end
      return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h1, h2, h1, h2, h1, h2, h1, h2)
    end,
  }),

  compress = freeze({
    gzip = function(data) return "GZ:" .. data end,
    gunzip = function(data)
      if type(data) == "string" and data:sub(1, 3) == "GZ:" then
        return data:sub(4)
      end
      return nil, "bad gzip"
    end,
  }),

  encoding = freeze({
    base64_encode = mock_b64_encode,
    base64_decode = mock_b64_decode,
  }),

  storage = freeze({
    get = function(k) return state.storage[k] end,
    set = function(k, v) state.storage[k] = v end,
    delete = function(k) state.storage[k] = nil end,
    keys = function()
      local out = {}
      for k in pairs(state.storage) do out[#out + 1] = k end
      return out
    end,
    clear = function() state.storage = {} end,
  }),

  settings = freeze({
    schema = function(fields)
      state.settings_schema = fields
      for _, f in ipairs(fields) do
        if f.key ~= nil and f.default ~= nil then
          state.settings_defaults[f.key] = f.default
          if state.settings[f.key] == nil then
            state.settings[f.key] = f.default
          end
        end
      end
      return true
    end,
    get = function(k, def)
      if state.settings[k] ~= nil then return state.settings[k] end
      if state.settings_defaults[k] ~= nil then return state.settings_defaults[k] end
      return def
    end,
    set = function(k, v)
      state.settings[k] = v
      for _, fn in ipairs(state.settings_listeners) do
        fn(k, v)
      end
    end,
    all = function()
      local copy = {}
      for k, v in pairs(state.settings) do copy[k] = v end
      return copy
    end,
    on_change = function(fn)
      state.settings_listeners[#state.settings_listeners + 1] = fn
    end,
  }),

  clipboard = freeze({
    write = function(txt) state.clipboard = txt end,
  }),

  async = freeze({
    spawn = function(fn, ...)
      local co = coroutine.create(fn)
      local ok, err = coroutine.resume(co, ...)
      assert(ok, err)
      return co
    end,
  }),

  ui = freeze({
    contextMenu = freeze({
      add = function(spec) state.context_menus[spec.id] = spec end,
      remove = function(id) state.context_menus[id] = nil end,
    }),
    toast = freeze({
      show = function(text, level)
        state.toasts[#state.toasts + 1] = { text = text, level = level or "info" }
      end,
    }),
    dialog = freeze({
      confirm = function(opts, cb)
        state.last_dialog = opts
        local res = { accepted = state.dialog_accept }
        if cb then cb(res); return nil end
        return res
      end,
    }),
    file = freeze({
      pick = function(_, cb)
        local res = state.picked_file
        if cb then cb(res, nil); return nil end
        return res, nil
      end,
    }),
    decorate = freeze({
      message_accessory = function(spec)
        require_perm("ui.decorate")
        state.decorations[spec.id] = { kind = "accessory", spec = spec }
        return true
      end,
      message_badge = function(spec)
        require_perm("ui.decorate")
        state.decorations[spec.id] = { kind = "badge", spec = spec }
        return true
      end,
      remove = function(id)
        require_perm("ui.decorate")
        state.decorations[id] = nil
        return true
      end,
      clear = function()
        require_perm("ui.decorate")
        state.decorations = {}
        return true
      end,
    }),
    panel = freeze({
      mount = function(spec)
        require_perm("ui.panel")
        state.panels[spec.id] = spec
        return true
      end,
      unmount = function(id)
        require_perm("ui.panel")
        state.panels[id] = nil
        return true
      end,
    }),
  }),

  theme = freeze({
    color = function(token)
      local map = {
        bg_primary = "#1b1b20", bg_secondary = "#222228", bg_tertiary = "#141417",
        border_subtle = "#2a2a33", text_header = "#f0f0f3", text_normal = "#d4d4d8",
        text_muted = "#9393a0", text_on_brand = "#ffffff", brand = "#6e7bf2",
        danger = "#ec565b", status_online = "#3ba55d",
      }
      return map[token]
    end,
  }),

  store = freeze({
    self = function()
      require_perm("store.read")
      return state.self_user
    end,
  }),

  events = freeze({
    on = function(name, fn)
      if name == "message.create" or name == "message.update" or name == "message.delete" then
        require_perm("events.messages")
      end
      state.events[name] = fn
    end,
    off = function(name)
      state.events[name] = nil
    end,
  }),

  commands = freeze({
    register = function(spec)
      state.commands[spec.name] = spec
      return true
    end,
    unregister = function(name)
      state.commands[name] = nil
      return true
    end,
  }),

  hooks = freeze({
    on_before_send = function(fn)
      require_perm("messages.hook")
      state.hooks.on_before_send = fn
    end,
    on_before_edit = function(fn)
      require_perm("messages.hook")
      state.hooks.on_before_edit = fn
    end,
    on_link_open = function(fn)
      require_perm("notifications.hook")
      state.hooks.on_link_open = fn
    end,
  }),

  net = freeze({
    http = freeze({
      get = function(url, _, cb)
        require_perm("network.http")
        state.http_calls[#state.http_calls + 1] = url
        local mock = state.http_responses[url]
        local resp, err
        if mock then
          resp, err = mock.resp, mock.err
        else
          resp, err = { status = 404, body = "" }, nil
        end
        if cb then cb(resp, err); return nil end
        return resp, err
      end,
    }),
  }),
}
sandbox_env._G = sandbox_env

-- Mock HTTP responses for AdGuard #17 failover (primary 500 -> mirror 200) & custom remote list
local ADGUARD_PRIMARY = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt"
local ADGUARD_MIRROR = "https://filters.adtidy.org/extension/ublock/filters/17.txt"
state.http_responses[ADGUARD_PRIMARY] = { resp = { status = 500, body = "Server Error" } }
state.http_responses[ADGUARD_MIRROR] = {
  resp = {
    status = 200,
    body = table.concat({
      "! AdGuard Filter 17 mock",
      "$removeparam=pjclid",
      "$removeparam=adguard_new_tracker",
      "||x.com^$removeparam=a",
      "@@||archive.*^$removeparam",
    }, "\n"),
  },
}
state.http_responses["https://lists.example.org/custom.txt"] = {
  resp = {
    status = 200,
    body = "# Custom remote list\nremote_secret_track\nmyservice.example:foo_track\n",
  },
}
state.http_responses["https://lists.example.org/broken.html"] = {
  resp = { status = 200, body = "<html><body>Rate Limited</body></html>" },
}

-- Load main.lua inside strict sandbox
local main_file = assert(io.open("main.lua", "rb"))
local main_src = main_file:read("*a")
main_file:close()
local main_chunk = assert(load(main_src, "@main.lua", "t", sandbox_env))
main_chunk()

-- ============================================================================
-- 3. Verify Registration, Auto-Sync Failover, Custom Lists & Local Import
-- ============================================================================
assert_true("settings schema registered", type(state.settings_schema) == "table" and #state.settings_schema >= 15)
assert_true("on_before_send registered", type(state.hooks.on_before_send) == "function")
assert_true("on_before_edit registered", type(state.hooks.on_before_edit) == "function")
assert_true("on_link_open registered", type(state.hooks.on_link_open) == "function")
assert_true("copy-clean-url context menu registered", state.context_menus["copy-clean-url"] ~= nil)
assert_true("/cleanurl command registered", state.commands["cleanurl"] ~= nil)
assert_true("RPC clean_url exposed", state.exposed["clean_url"] ~= nil)
assert_true("RPC list_status exposed", state.exposed["list_status"] ~= nil)
assert_true("startup auto-sync timer scheduled", #state.timers >= 2)

-- Fire startup auto-sync timer: primary fails with 500 -> mirror succeeds with 4 rules!
state.timers[1].fn()
local st = state.exposed["list_status"].fn()
assert_eq("mirror failover synced 4 AdGuard rules", st.total_rules, 4)

-- Verify synced AdGuard rule strips `adguard_new_tracker` (not in built-in rules!)
local res_ag = state.hooks.on_link_open({
  url = "https://example.org/page?adguard_new_tracker=abc&pjclid=99&keep=1",
})
assert_eq("synced AdGuard rule stripped via on_link_open", res_ag.url, "https://example.org/page?keep=1")

-- Verify synced AdGuard exception `@@||archive.*^$removeparam` protects Wayback Machine
local res_arch = state.hooks.on_link_open({
  url = "https://web.archive.org/web/2026/https://example.com/?utm_source=keep&pjclid=keep",
})
assert_eq("synced AdGuard archive.* exception respected", res_arch, nil)

-- Test `/cleanurl add-list` rejects non-HTTPS
local toast_before = #state.toasts
state.commands["cleanurl"].run("add-list http://insecure.example/list.txt")
assert_true("non-HTTPS custom list rejected", state.toasts[#state.toasts].level == "warn")
assert_true("toast emitted on rejection", #state.toasts > toast_before)

-- Test `/cleanurl add-list` with HTTPS custom remote list
state.commands["cleanurl"].run("add-list https://lists.example.org/custom.txt")
local res_remote = state.hooks.on_before_send({
  channel_id = "1",
  content = "Check https://myservice.example/p?foo_track=1&remote_secret_track=2&ok=3",
})
assert_eq(
  "custom remote list immediately cleans outgoing messages",
  res_remote.content,
  "Check https://myservice.example/p?ok=3"
)

-- Test `/cleanurl import` with native file picker (local custom list)
state.picked_file = {
  name = "my-local-filters.txt",
  data = "||localtest.example^$removeparam=local_spy\n$removeparam=global_local_spy\n",
}
state.commands["cleanurl"].run("import")
local res_local = state.hooks.on_link_open({
  url = "https://localtest.example/item?local_spy=1&global_local_spy=2&id=7",
})
assert_eq("imported local list immediately cleans links", res_local.url, "https://localtest.example/item?id=7")

-- Test `/cleanurl lists` opens status dialog containing all sources
state.dialog_accept = false
state.commands["cleanurl"].run("lists")
assert_true("/cleanurl lists opens dialog", state.last_dialog ~= nil and state.last_dialog.title == "Active Filter Lists")
assert_true("lists dialog mentions AdGuard", state.last_dialog.message:find("AdGuard", 1, true) ~= nil)
assert_true("lists dialog mentions local list", state.last_dialog.message:find("my-local-filters.txt", 1, true) ~= nil)

-- Test `/cleanurl remove-list` removes local list & custom URL
state.commands["cleanurl"].run("remove-list my-local-filters.txt")
local res_after_rm = state.hooks.on_link_open({
  url = "https://localtest.example/item?local_spy=1&id=7",
})
assert_eq("removed local list no longer strips local_spy", res_after_rm, nil)

state.commands["cleanurl"].run("remove-list lists.example.org")
local res_after_rm_url = state.hooks.on_link_open({
  url = "https://myservice.example/p?foo_track=1&ok=3",
})
assert_eq("removed custom URL no longer strips foo_track", res_after_rm_url, nil)

-- Test HTML error page does not overwrite cached AdGuard list on manual `/cleanurl update`
state.http_responses[ADGUARD_PRIMARY] = { resp = { status = 200, body = "<html>Cloudflare 522</html>" } }
state.http_responses[ADGUARD_MIRROR] = { resp = { status = 200, body = "<html>Bad Gateway</html>" } }
state.commands["cleanurl"].run("update")
local st_after_bad = state.exposed["list_status"].fn()
assert_eq("HTML error page did not clobber cached AdGuard rules", st_after_bad.total_rules, 4)

-- ============================================================================
-- 4. Verify Core Hooks, Context Menu, Slash Commands & RPC
-- ============================================================================
local res_send = state.hooks.on_before_send({
  channel_id = "123",
  content = "Watch https://youtu.be/dQw4w9WgXcQ?si=abc123&t=42 and https://x.com/AqueleJunio/status/2124282949608603764?a=zd4wZf288aIM6IVgipk&s=20!",
})
assert_eq(
  "on_before_send cleaned YT + X.com ?a= link",
  res_send.content,
  "Watch https://youtu.be/dQw4w9WgXcQ?t=42 and https://x.com/AqueleJunio/status/2124282949608603764!"
)

local res_edit = state.hooks.on_before_edit({
  channel_id = "123",
  message_id = "456",
  content = "Edited: https://www.google.com/url?q=https%3A%2F%2Fopen.spotify.com%2Ftrack%2F1%3Fsi%3Dtrackme",
})
assert_eq("on_before_edit unwrapped & cleaned", res_edit.content, "Edited: https://open.spotify.com/track/1")

local res_bing = state.hooks.on_link_open({
  url = "https://www.bing.com/ck/a?!&&p=1234&u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS9wYWdlP3V0bV9zb3VyY2U9YmluZyZvaz0x&ntb=1",
})
assert_eq("on_link_open unwrapped Bing base64 URL", res_bing.url, "https://example.com/page?ok=1")

-- Context menu
state.context_menus["copy-clean-url"].action({
  url = "https://www.reddit.com/r/lua/comments/1/post/?share_id=TRACK&context=2",
})
assert_eq("contextMenu copies clean URL", state.clipboard, "https://www.reddit.com/r/lua/comments/1/post/?context=2")

-- /cleanurl inspect dialog & autocomplete
state.clipboard = nil
state.dialog_accept = true
state.commands["cleanurl"].run("inspect https://youtu.be/abc?si=123&t=5")
assert_true("inspect opens confirm dialog", state.last_dialog ~= nil and state.last_dialog.title == "Tracking Removed")
assert_eq("inspect confirm copies clean URL", state.clipboard, "https://youtu.be/abc?t=5")
local ac = state.commands["cleanurl"].autocomplete("imp")
assert_eq("autocomplete matches import", #ac, 1)
assert_eq("autocomplete label is import", ac[1].label, "import")

-- Toggle off/on & reset
state.commands["cleanurl"].run("toggle")
assert_eq("enabled toggled off", sandbox_env.settings.get("enabled"), false)
assert_eq("disabled plugin passes link untouched", state.hooks.on_link_open({ url = "https://x.com/a/status/1?a=1&s=20" }), nil)
state.commands["cleanurl"].run("toggle")
state.commands["cleanurl"].run("reset")
assert_eq("stats reset to 0", state.storage.stats.urls_cleaned, 0)

-- ============================================================================
-- 5. Verify Clickable "(tracking removed)" Indicator, Modal Popup & Edit Safety
-- ============================================================================
assert_true("message.create event listener registered", type(state.events["message.create"]) == "function")
assert_true("message.update event listener registered", type(state.events["message.update"]) == "function")
assert_true("message.delete event listener registered", type(state.events["message.delete"]) == "function")

-- 5a. Send dirty message -> another user posts same clean text (ignored!) ->
--     C-Cord emits bit-63 local echo (ev.id) -> then confirmed real snowflake (ev.id)!
local dirty_msg = "Look https://x.com/AqueleJunio/status/2124282949608603764?a=zd4wZf288aIM6IVgipk&s=20 "
local send_out = state.hooks.on_before_send({ channel_id = "CHAN_99", content = dirty_msg })
assert_eq("dirty message cleaned before send", send_out.content, "Look https://x.com/AqueleJunio/status/2124282949608603764 ")

-- Someone else posts the same text (real C-Cord message.create payload uses `ev.id`, NOT `ev.message_id`)
state.events["message.create"]({
  channel_id = "CHAN_99",
  id = "1440000000000000001",
  author_id = "USER_STRANGER_999",
  content = "Look https://x.com/AqueleJunio/status/2124282949608603764",
})
assert_eq("other user's message not decorated", state.decorations["tr-msg-1440000000000000001"], nil)

-- C-Cord first emits an unconfirmed bit-63 local echo ID (>= 9223372036854775808)
local echo_id = "9223372036854775809"
state.events["message.create"]({
  channel_id = "CHAN_99",
  id = echo_id,
  author_id = "USER_SELF_123",
  content = "Look https://x.com/AqueleJunio/status/2124282949608603764",
})
assert_true("local echo gets immediate indicator", state.decorations["tr-msg-" .. echo_id] ~= nil)

-- 200ms later Discord confirms with the real snowflake ID -> echo decoration removed, real ID decorated & persisted!
local real_id = "1440000000000000099"
state.events["message.create"]({
  channel_id = "CHAN_99",
  id = real_id,
  author_id = "USER_SELF_123",
  content = "Look https://x.com/AqueleJunio/status/2124282949608603764",
})
assert_eq("temporary echo decoration cleaned up on confirmation", state.decorations["tr-msg-" .. echo_id], nil)
local dec = state.decorations["tr-msg-" .. real_id]
assert_true("confirmed send attaches (tracking removed) accessory", dec ~= nil and dec.kind == "accessory")
assert_eq("accessory button uses C-Cord `label` prop", dec.spec.widget.children[1].label, "(tracking removed)")
assert_eq("accessory button uses C-Cord `variant` prop", dec.spec.widget.children[1].variant, "secondary")

-- 5b. Click "(tracking removed)" using REAL C-Cord decor.event shape (`ev.type` + `ev.id`)
dec.spec.on_event({ type = "click", id = "open-diff" }, real_id)
local modal = state.panels["tracking-diff-modal"]
assert_true("clicking (tracking removed) mounts transparency modal", modal ~= nil and modal.slot == "modal")

-- Copy Clean URL & Copy Original URL inside modal using REAL C-Cord panel.event shape (`ev.type` + `ev.id`)
state.clipboard = nil
modal.on_event({ type = "click", id = "copy-clean-1" })
assert_eq("modal Copy Clean copies cleaned URL", state.clipboard, "https://x.com/AqueleJunio/status/2124282949608603764")
modal.on_event({ type = "click", id = "copy-orig-1" })
assert_eq("modal Copy Original copies original URL", state.clipboard, "https://x.com/AqueleJunio/status/2124282949608603764?a=zd4wZf288aIM6IVgipk&s=20")

-- Close modal using REAL C-Cord panel.event shape
modal.on_event({ type = "click", id = "close-btn" })
assert_eq("modal unmounts on Close click", state.panels["tracking-diff-modal"], nil)

-- 5c. User manually edits a regular uncleaned message (C-Cord sends `ev.id` on message.update) -> zero interference
assert_eq("manual edit of clean message passes untouched", state.hooks.on_before_edit({
  channel_id = "CHAN_99", message_id = "1440000000000000100", content = "just fixing a typo",
}), nil)
state.events["message.update"]({ channel_id = "CHAN_99", id = "1440000000000000100", content = "just fixing a typo" })
assert_eq("regular edited message gets no tracking decoration", state.decorations["tr-msg-1440000000000000100"], nil)

-- 5d. User manually edits confirmed message while keeping the clean link -> indicator preserved
state.events["message.update"]({
  channel_id = "CHAN_99",
  id = real_id,
  content = "Updated caption: https://x.com/AqueleJunio/status/2124282949608603764",
})
assert_true("manual edit keeping cleaned link preserves indicator", state.decorations["tr-msg-" .. real_id] ~= nil)

-- 5e. User manually edits confirmed message and removes the link completely -> stale indicator removed
state.events["message.update"]({
  channel_id = "CHAN_99",
  id = real_id,
  content = "Never mind, removed the link!",
})
assert_eq("manual edit removing link removes stale (tracking removed) indicator", state.decorations["tr-msg-" .. real_id], nil)

-- 5f. Switch placement to header badge & clean a message edit -> uses ui.decorate.message_badge with `label`
sandbox_env.settings.set("badge_placement", "badge")
state.hooks.on_before_edit({
  channel_id = "CHAN_99",
  message_id = "1440000000000000200",
  content = "New link https://youtu.be/abc?si=999&t=5",
})
local badge_dec = state.decorations["tr-msg-1440000000000000200"]
assert_true("badge_placement='badge' uses ui.decorate.message_badge", badge_dec ~= nil and badge_dec.kind == "badge")
assert_eq("header badge button uses C-Cord `label` prop", badge_dec.spec.widget.label, "(tracking removed)")

-- 5g. Message delete (C-Cord sends `ev.message_id`) cleans up decoration & stored record
state.events["message.delete"]({ channel_id = "CHAN_99", message_id = "1440000000000000200" })
assert_eq("message.delete removes decoration", state.decorations["tr-msg-1440000000000000200"], nil)

-- 5h. Disabling show_message_badge clears decorations immediately
state.hooks.on_before_edit({
  channel_id = "CHAN_99",
  message_id = "1440000000000000300",
  content = "Link https://youtu.be/xyz?si=123",
})
assert_true("decoration present before toggle off", state.decorations["tr-msg-1440000000000000300"] ~= nil)
sandbox_env.settings.set("show_message_badge", false)
assert_eq("disabling show_message_badge clears all decorations", state.decorations["tr-msg-1440000000000000300"], nil)

io.stdout:write(string.format("Main sandbox integration tests completed: %d passed, %d failed\n", passed, failed))
if failed > 0 then
  os.exit(1)
end
