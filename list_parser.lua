-- Tracking Removal — Multi-Format 3rd-Party Filter List Parser & Compiled Matcher
-- Pure Lua 5.5 sandbox-safe module.
-- Supports:
--   1. AdGuard / uBlock Origin `$removeparam` lists (e.g. AdGuard Filter #17, DandelionSprout)
--   2. ClearURLs JSON (`data.minify.json` / `data.min.json`)
--   3. Simple plain-text custom lists (`param`, `prefix_*`, `domain.com:param`, `@@domain.com`)

local rules = require("rules")

local M = {}

local SUBRESOURCE_OPTS = {
  xmlhttprequest = true,
  xhr = true,
  font = true,
  script = true,
  stylesheet = true,
  css = true,
  image = true,
  media = true,
  subdocument = true,
  object = true,
  ping = true,
  websocket = true,
  other = true,
  ["~document"] = true,
  ["~doc"] = true,
}

local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

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

local function host_matches_spec(host_lower, brand, spec)
  if spec:sub(-2) == ".*" then
    local spec_brand = spec:sub(1, -3)
    if spec_brand:find(".", 1, true) then
      -- Multi-label prefix like "sub.amazon.*" -> match prefix before brand TLD
      local prefix = spec_brand .. "."
      return host_lower:sub(1, #prefix) == prefix
        or host_lower:find("." .. prefix, 1, true) ~= nil
    end
    return brand == spec_brand
  end
  if host_lower == spec then
    return true
  end
  local slen = #spec
  return #host_lower > slen + 1 and host_lower:sub(-(slen + 1)) == "." .. spec
end

-- ============================================================================
-- Conservative JS/PCRE Regex -> Lua Pattern Translator
-- Returns `{ patterns = { lua_pat, ... }, ci = bool, full_pair = bool }` or nil
-- ============================================================================

local LUA_MAGIC = {
  ["^"] = true, ["$"] = true, ["("] = true, [")"] = true,
  ["%"] = true, ["."] = true, ["["] = true, ["]"] = true,
  ["*"] = true, ["+"] = true, ["-"] = true, ["?"] = true,
}

local function escape_lua_char(ch)
  if LUA_MAGIC[ch] then
    return "%" .. ch
  end
  return ch
end

-- Expands a single simple alternation group like `^(a|b|c)=` into multiple branch strings.
-- Returns nil if the regex uses unsupported group constructs or too many branches.
local function expand_simple_groups(re)
  if re:find("%(%?") then
    -- Handle only simple non-capturing `(?:...)` without lookarounds
    if re:find("%(%?[=!<]") then
      return nil
    end
    re = re:gsub("%(%?:", "(")
  end

  local branches = { re }
  local passes = 0
  while passes < 3 do
    passes = passes + 1
    local expanded = {}
    local did_expand = false
    for i = 1, #branches do
      local b = branches[i]
      -- Find innermost parenthesized group without nested parens
      local gs, ge, inner = b:find("%(([^%(%)]+)%)")
      if gs then
        -- Reject quantified multi-char groups like (abc)+ or (a|b)* unless single atom
        local after = b:sub(ge + 1, ge + 1)
        if after == "*" or after == "+" or after == "?" or after == "{" then
          return nil
        end
        local before = b:sub(1, gs - 1)
        local tail = b:sub(ge + 1)
        local parts = {}
        local pos = 1
        while pos <= #inner + 1 do
          local bar = inner:find("|", pos, true)
          if bar then
            parts[#parts + 1] = inner:sub(pos, bar - 1)
            pos = bar + 1
          else
            parts[#parts + 1] = inner:sub(pos)
            break
          end
        end
        if #expanded + #parts > 16 then
          return nil
        end
        for j = 1, #parts do
          expanded[#expanded + 1] = before .. parts[j] .. tail
        end
        did_expand = true
      else
        expanded[#expanded + 1] = b
      end
    end
    branches = expanded
    if not did_expand then
      break
    end
  end

  -- Handle top-level `a|b` without parens
  local final = {}
  for i = 1, #branches do
    local b = branches[i]
    if b:find("[%(%)]") then
      return nil
    end
    if b:find("|", 1, true) then
      local pos = 1
      local count = 0
      while pos <= #b + 1 do
        local bar = b:find("|", pos, true)
        count = count + 1
        if #final + count > 16 then
          return nil
        end
        if bar then
          final[#final + 1] = b:sub(pos, bar - 1)
          pos = bar + 1
        else
          final[#final + 1] = b:sub(pos)
          break
        end
      end
    else
      final[#final + 1] = b
    end
  end
  return final
end

local function translate_single_branch(re)
  local out = {}
  local len = #re
  local i = 1
  local last_atom = nil

  local function push_atom(atom)
    out[#out + 1] = atom
    last_atom = atom
  end

  while i <= len do
    local ch = re:sub(i, i)
    if ch == "\\" then
      if i == len then
        return nil
      end
      local nxt = re:sub(i + 1, i + 1)
      if nxt == "d" then
        push_atom("%d")
      elseif nxt == "D" then
        push_atom("%D")
      elseif nxt == "w" then
        push_atom("[%w_]")
      elseif nxt == "W" then
        push_atom("[^%w_]")
      elseif nxt == "s" then
        push_atom("%s")
      elseif nxt == "S" then
        push_atom("%S")
      elseif nxt:match("%d") or nxt == "b" or nxt == "B" then
        -- Backreferences or word boundaries unsupported in Lua patterns
        return nil
      else
        push_atom(escape_lua_char(nxt))
      end
      i = i + 2
    elseif ch == "[" then
      local j = i + 1
      local cls = { "[" }
      if j <= len and re:sub(j, j) == "^" then
        cls[#cls + 1] = "^"
        j = j + 1
      end
      local closed = false
      while j <= len do
        local c = re:sub(j, j)
        if c == "\\" and j < len then
          local nc = re:sub(j + 1, j + 1)
          if nc == "d" then cls[#cls + 1] = "%d"
          elseif nc == "w" then cls[#cls + 1] = "%w_"
          elseif nc == "s" then cls[#cls + 1] = "%s"
          elseif nc == "-" then cls[#cls + 1] = "%-"
          elseif nc == "]" then cls[#cls + 1] = "%]"
          elseif nc == "%" then cls[#cls + 1] = "%%"
          else cls[#cls + 1] = nc end
          j = j + 2
        elseif c == "]" and #cls > 1 then
          cls[#cls + 1] = "]"
          closed = true
          j = j + 1
          break
        elseif c == "%" then
          cls[#cls + 1] = "%%"
          j = j + 1
        else
          cls[#cls + 1] = c
          j = j + 1
        end
      end
      if not closed then
        return nil
      end
      push_atom(table.concat(cls))
      i = j
    elseif ch == "{" then
      local close = re:find("}", i + 1, true)
      if not close or not last_atom then
        return nil
      end
      local spec = re:sub(i + 1, close - 1)
      local exact = spec:match("^(%d+)$")
      local min_s, max_s = spec:match("^(%d+),(%d*)$")
      if exact then
        local n = tonumber(exact)
        if not n or n < 1 or n > 12 then
          return nil
        end
        for _ = 2, n do
          out[#out + 1] = last_atom
        end
      elseif min_s then
        local min_n = tonumber(min_s)
        local max_n = (max_s ~= "") and tonumber(max_s) or nil
        if not min_n or min_n > 12 or (max_n and (max_n < min_n or max_n > 12)) then
          return nil
        end
        if min_n == 0 then
          out[#out] = last_atom .. (max_n and "?" or "*")
          if max_n then
            for _ = 2, max_n do
              out[#out + 1] = last_atom .. "?"
            end
          end
        else
          for _ = 2, min_n do
            out[#out + 1] = last_atom
          end
          if max_n then
            for _ = min_n + 1, max_n do
              out[#out + 1] = last_atom .. "?"
            end
          else
            out[#out + 1] = last_atom .. "*"
          end
        end
      else
        return nil
      end
      last_atom = nil
      i = close + 1
    elseif ch == "*" or ch == "+" or ch == "?" then
      -- Handle lazy quantifiers (*?, +?, ??)
      local lazy = (i < len and re:sub(i + 1, i + 1) == "?")
      if not last_atom then
        return nil
      end
      if ch == "*" and lazy then
        out[#out] = last_atom .. "-"
        i = i + 2
      elseif ch == "+" and lazy then
        out[#out] = last_atom .. last_atom .. "-"
        i = i + 2
      elseif ch == "?" and lazy then
        out[#out] = last_atom .. "?"
        i = i + 2
      else
        out[#out] = last_atom .. ch
        i = i + 1
      end
      last_atom = nil
    elseif ch == "." then
      push_atom(".")
      i = i + 1
    elseif ch == "^" and i == 1 then
      out[#out + 1] = "^"
      last_atom = nil
      i = i + 1
    elseif ch == "$" and i == len then
      out[#out + 1] = "$"
      last_atom = nil
      i = i + 1
    elseif ch == "(" or ch == ")" or ch == "|" or ch == "}" then
      return nil
    else
      push_atom(escape_lua_char(ch))
      i = i + 1
    end
  end

  local lua_pat = table.concat(out)
  local ok = pcall(string.find, "", lua_pat)
  if not ok then
    return nil
  end
  return lua_pat
end

local function compile_regex(raw_regex, force_ci)
  -- Unescape AdGuard escaped commas `\,` and slashes `\/`
  local body = raw_regex:gsub("\\,", ","):gsub("\\/", "/")
  if force_ci then
    body = body:lower()
  end
  local branches = expand_simple_groups(body)
  if not branches or #branches == 0 then
    return nil
  end
  local patterns = {}
  for i = 1, #branches do
    local p = translate_single_branch(branches[i])
    if not p then
      return nil
    end
    patterns[#patterns + 1] = p
  end
  return {
    patterns = patterns,
    ci = force_ci == true,
  }
end

local function match_compiled_regex(compiled, target)
  local s = compiled.ci and target:lower() or target
  local pats = compiled.patterns
  for i = 1, #pats do
    if s:find(pats[i]) then
      return true
    end
  end
  return false
end

-- Compiles an Adblock URL wildcard pattern (supporting `*` and `^`) into a Lua pattern.
local function compile_adblock_url_pattern(pat)
  if not pat or pat == "" or pat == "*" then
    return nil
  end
  local out = {}
  local len = #pat
  local i = 1
  while i <= len do
    local ch = pat:sub(i, i)
    if ch == "*" then
      out[#out + 1] = ".*"
    elseif ch == "^" then
      if i == len then
        -- Trailing `^` matches a separator OR end of string; handled via two checks or `[/?&#=:]`
        out[#out + 1] = "[/%?&#=:]?"
      else
        out[#out + 1] = "[/%?&#=:]"
      end
    else
      out[#out + 1] = escape_lua_char(ch)
    end
    i = i + 1
  end
  local lua_pat = table.concat(out)
  local ok = pcall(string.find, "", lua_pat)
  if not ok then
    return nil
  end
  return lua_pat
end

-- ============================================================================
-- Compiled Index Structure
-- ============================================================================

function M.new_index()
  return {
    -- Stats
    total_rules = 0,
    skipped_rules = 0,
    sources = {},

    -- Global param rules (no domain/URL restriction)
    global_exact = {},        -- [param_lower] = true
    global_prefixes = {},     -- string[]
    global_regex = {},        -- { compiled, neg_domains? }[]

    -- Domain-indexed rules (exact host or suffix match)
    domain_exact = {},        -- [domain] = { params = set, rules = rule[] }
    -- Brand-indexed rules (e.g. "amazon.*" -> brand "amazon")
    brand_rules = {},         -- [brand] = { params = set, rules = rule[] }

    -- URL-conditioned rules indexed by target param name for O(1) lookup!
    url_by_param = {},        -- [param_lower] = rule[]
    -- Fallback URL-conditioned rules with regex or bare `$removeparam` (very small list)
    url_generic = {},         -- rule[]

    -- Exceptions (`@@...`)
    except_domains = {},      -- [domain] = true (skip all external rules on domain)
    except_brands = {},       -- [brand] = true
    except_domain_rules = {}, -- [domain] = rule[] (path or param-specific exceptions)
    except_brand_rules = {},  -- [brand] = rule[]
    except_by_param = {},     -- [param_lower] = rule[]
    except_generic = {},      -- rule[]

    -- Path cleaners extracted from ClearURLs `rawRules`
    path_cleaners = {},       -- [domain_or_brand] = { { pattern, is_brand }... }
  }
end

local function ensure_bucket(map, key)
  local b = map[key]
  if not b then
    b = { params = {}, rules = {} }
    map[key] = b
  end
  return b
end

local function add_list_entry(map, key, item)
  local list = map[key]
  if not list then
    list = {}
    map[key] = list
  end
  list[#list + 1] = item
end

-- ============================================================================
-- AdGuard / uBlock `$removeparam` Parser
-- ============================================================================

-- Splits Adblock options by unescaped commas (respecting `/regex/` and `\,`).
local function split_options(opts_str)
  local parts = {}
  local buf = {}
  local in_regex = false
  local escaped = false
  local len = #opts_str
  for i = 1, len do
    local ch = opts_str:sub(i, i)
    if escaped then
      buf[#buf + 1] = "\\" .. ch
      escaped = false
    elseif ch == "\\" then
      escaped = true
    elseif ch == "/" then
      in_regex = not in_regex
      buf[#buf + 1] = ch
    elseif ch == "," and not in_regex then
      parts[#parts + 1] = table.concat(buf)
      buf = {}
    else
      buf[#buf + 1] = ch
    end
  end
  if escaped then
    buf[#buf + 1] = "\\"
  end
  if #buf > 0 then
    parts[#parts + 1] = table.concat(buf)
  end
  return parts
end

-- Finds the `$` separating Adblock URL pattern from options (ignores `$` inside `/regex/`).
local function split_adblock_rule(line)
  -- Search backwards for `$` followed by option-like keywords containing `removeparam`
  local pos = #line
  while pos >= 1 do
    local dollar = nil
    for i = pos, 1, -1 do
      if line:sub(i, i) == "$" then
        dollar = i
        break
      end
    end
    if not dollar then
      return nil, nil
    end
    local opts = line:sub(dollar + 1)
    if opts:find("removeparam", 1, true) then
      return line:sub(1, dollar - 1), opts
    end
    pos = dollar - 1
  end
  return nil, nil
end

local function parse_domain_option(dom_str)
  local pos_domains = {}
  local neg_domains = {}
  for token in dom_str:gmatch("[^|]+") do
    local d = token:lower()
    if d:sub(1, 1) == "~" then
      local excl = d:sub(2)
      if excl ~= "" then
        neg_domains[#neg_domains + 1] = excl
      end
    elseif d ~= "" then
      pos_domains[#pos_domains + 1] = d
    end
  end
  return pos_domains, neg_domains
end

-- Parses an Adblock URL pattern (before `$`) into optional host/brand + path/url matcher.
local function parse_adblock_pattern(pat)
  if not pat or pat == "" or pat == "*" then
    return nil
  end
  local pat_lower = pat:lower()

  -- Domain-anchored: `||example.com^`, `||example.com/path`, `||amazon.*/dp/`
  if pat_lower:sub(1, 2) == "||" then
    local rest = pat_lower:sub(3)
    -- Extract domain part up to `^`, `/`, `?`, or end
    local sep = rest:find("[%^[/?]")
    local host_spec, tail
    if sep then
      host_spec = rest:sub(1, sep - 1)
      local sep_ch = rest:sub(sep, sep)
      if sep_ch == "^" then
        tail = rest:sub(sep + 1)
      else
        tail = rest:sub(sep)
      end
    else
      host_spec = rest
      tail = ""
    end

    if host_spec == "" or host_spec:find("*", 1, true) and host_spec:sub(-2) ~= ".*" then
      -- Wildcard inside hostname other than trailing `.*` -> treat as generic URL pattern
      return { url_pat = compile_adblock_url_pattern(pat_lower) }
    end

    local path_pat = nil
    if tail ~= "" and tail ~= "^" and tail ~= "*" then
      path_pat = compile_adblock_url_pattern(tail)
      if not path_pat then
        return { invalid = true }
      end
    end

    if host_spec:sub(-2) == ".*" then
      local prefix_part = host_spec:sub(1, -3)
      if not prefix_part:find(".", 1, true) then
        return { brand = prefix_part, path_pat = path_pat }
      end
      -- Multi-label brand wildcard like `luna.amazon.*` -> index under brand `amazon` with host_spec check
      local brand = prefix_part:match("([^%.]+)$")
      if brand and brand ~= "" then
        return { brand = brand, host_spec = host_spec, path_pat = path_pat }
      end
      return { invalid = true }
    end
    return { domain = host_spec, path_pat = path_pat }
  end

  -- Generic URL substring/wildcard pattern (`?from=glia^`, `ref=404media^`, `.com/*/status/`, etc.)
  local url_pat = compile_adblock_url_pattern(pat_lower)
  if not url_pat then
    return { invalid = true }
  end
  return { url_pat = url_pat }
end

local function parse_removeparam_value(raw_val)
  if raw_val == nil then
    return { kind = "all" }
  end
  local inverted = false
  local val = raw_val
  if val:sub(1, 1) == "~" then
    inverted = true
    val = val:sub(2)
  end
  if val == "" then
    return nil
  end
  -- Regex value: `/pattern/` or `/pattern/i`
  if val:sub(1, 1) == "/" then
    local body, flags = val:match("^/(.+)/([a-zA-Z]*)$")
    if not body then
      return nil
    end
    local ci = (flags:find("i", 1, true) ~= nil)
    -- Fast path: pure prefix regex like `/^at_custom/` or `/^cm_mmc/` (no special regex chars)
    if not inverted and not body:find("=", 1, true) then
      local simple_prefix = body:match("^%^([A-Za-z0-9_%-]+)$")
      if simple_prefix then
        return { kind = "prefix", prefix = simple_prefix:lower() }
      end
    end
    local compiled = compile_regex(body, true) -- case-insensitive matching for robustness
    if not compiled then
      return nil
    end
    return {
      kind = "regex",
      compiled = compiled,
      inverted = inverted,
      match_full = true,
      ci = ci,
    }
  end
  return {
    kind = "exact",
    param = val:lower(),
    inverted = inverted,
  }
end

local function add_domain_or_brand_rule(index, host_spec, rule_obj, is_exception)
  local is_brand = false
  local key = host_spec
  if host_spec:sub(-2) == ".*" then
    local prefix_part = host_spec:sub(1, -3)
    if not prefix_part:find(".", 1, true) then
      is_brand = true
      key = prefix_part
    else
      local b = prefix_part:match("([^%.]+)$")
      if not b or b == "" then
        return
      end
      is_brand = true
      key = b
      rule_obj = {
        spec = rule_obj.spec,
        path_pat = rule_obj.path_pat,
        url_pat = rule_obj.url_pat,
        neg_domains = rule_obj.neg_domains,
        host_spec = host_spec,
      }
    end
  end

  if is_exception then
    if rule_obj.spec.kind == "all" and not rule_obj.path_pat and not rule_obj.url_pat and not rule_obj.host_spec then
      if is_brand then
        index.except_brands[key] = true
      else
        index.except_domains[key] = true
      end
    else
      if is_brand then
        add_list_entry(index.except_brand_rules, key, rule_obj)
      else
        add_list_entry(index.except_domain_rules, key, rule_obj)
      end
    end
    return
  end

  local bucket = is_brand and ensure_bucket(index.brand_rules, key) or ensure_bucket(index.domain_exact, key)
  if rule_obj.spec.kind == "exact" and not rule_obj.spec.inverted
    and not rule_obj.path_pat and not rule_obj.url_pat and not rule_obj.host_spec
    and (not rule_obj.neg_domains or #rule_obj.neg_domains == 0)
  then
    bucket.params[rule_obj.spec.param] = true
  else
    bucket.rules[#bucket.rules + 1] = rule_obj
  end
end

function M.parse_adblock(text, index)
  index = index or M.new_index()
  local added = 0
  local skipped = 0

  for raw_line in text:gmatch("[^\r\n]+") do
    local line = trim(raw_line)
    -- Strip UTF-8 BOM if present on first line
    if line:sub(1, 3) == "\239\187\191" then
      line = trim(line:sub(4))
    end

    if line ~= "" and line:sub(1, 1) ~= "!" and line:sub(1, 1) ~= "[" and line:sub(1, 1) ~= "#" then
      -- Skip cosmetic / scriptlet / removeheader rules
      if not line:find("##", 1, true) and not line:find("#@#", 1, true) and line:find("removeparam", 1, true) then
        local is_exception = false
        if line:sub(1, 2) == "@@" then
          is_exception = true
          line = line:sub(3)
        end

        local pat_str, opts_str = split_adblock_rule(line)
        if opts_str then
          local parts = split_options(opts_str)
          local rp_found = false
          local rp_val = nil
          local subresource_only = false
          local pos_domains = {}
          local neg_domains = {}

          for i = 1, #parts do
            local opt = trim(parts[i])
            local opt_lower = opt:lower()
            if opt_lower == "removeparam" then
              rp_found = true
              rp_val = nil
            elseif opt_lower:sub(1, 12) == "removeparam=" then
              rp_found = true
              rp_val = opt:sub(13)
            elseif opt_lower:sub(1, 7) == "domain=" then
              pos_domains, neg_domains = parse_domain_option(opt:sub(8))
            elseif SUBRESOURCE_OPTS[opt_lower] then
              subresource_only = true
            end
          end

          if rp_found and not subresource_only then
            local spec = parse_removeparam_value(rp_val)
            local pat_info = parse_adblock_pattern(pat_str)

            -- Safety: never allow bare `$removeparam` (strip all) without a domain or URL condition
            if not spec or (pat_info and pat_info.invalid)
              or (not is_exception and spec.kind == "all" and not pat_info and #pos_domains == 0)
            then
              skipped = skipped + 1
            else
              local rule_obj = {
                spec = spec,
                path_pat = pat_info and pat_info.path_pat or nil,
                url_pat = pat_info and pat_info.url_pat or nil,
                host_spec = pat_info and pat_info.host_spec or nil,
                neg_domains = (#neg_domains > 0) and neg_domains or nil,
              }

              if pat_info and (pat_info.domain or pat_info.brand) then
                local host_spec = pat_info.host_spec or pat_info.domain or (pat_info.brand .. ".*")
                add_domain_or_brand_rule(index, host_spec, rule_obj, is_exception)
                added = added + 1
              elseif #pos_domains > 0 then
                for j = 1, #pos_domains do
                  add_domain_or_brand_rule(index, pos_domains[j], rule_obj, is_exception)
                end
                added = added + 1
              elseif pat_info and pat_info.url_pat then
                if is_exception then
                  if spec.kind == "exact" then
                    add_list_entry(index.except_by_param, spec.param, rule_obj)
                  else
                    index.except_generic[#index.except_generic + 1] = rule_obj
                  end
                else
                  if spec.kind == "exact" and not spec.inverted then
                    add_list_entry(index.url_by_param, spec.param, rule_obj)
                  else
                    index.url_generic[#index.url_generic + 1] = rule_obj
                  end
                end
                added = added + 1
              elseif not pat_info then
                -- Pure global rule (possibly with neg_domains)
                if is_exception then
                  if spec.kind == "exact" then
                    add_list_entry(index.except_by_param, spec.param, rule_obj)
                  else
                    index.except_generic[#index.except_generic + 1] = rule_obj
                  end
                  added = added + 1
                elseif spec.kind == "exact" and not spec.inverted and not rule_obj.neg_domains then
                  index.global_exact[spec.param] = true
                  added = added + 1
                elseif spec.kind == "prefix" and not rule_obj.neg_domains then
                  index.global_prefixes[#index.global_prefixes + 1] = spec.prefix
                  added = added + 1
                elseif spec.kind == "exact" and not spec.inverted then
                  add_list_entry(index.url_by_param, spec.param, rule_obj)
                  added = added + 1
                elseif spec.kind == "regex" or spec.kind == "prefix" then
                  index.global_regex[#index.global_regex + 1] = rule_obj
                  added = added + 1
                else
                  skipped = skipped + 1
                end
              else
                skipped = skipped + 1
              end
            end
          else
            skipped = skipped + 1
          end
        end
      end
    end
  end

  index.total_rules = index.total_rules + added
  index.skipped_rules = index.skipped_rules + skipped
  return index, added, skipped
end

-- ============================================================================
-- ClearURLs JSON (`data.minify.json`) Parser
-- ============================================================================

local function extract_clearurls_hosts(url_pattern)
  if type(url_pattern) ~= "string" then
    return nil
  end
  if url_pattern == ".*" or url_pattern == "^https?:\\/\\/.*$" then
    return { is_global = true }
  end
  local p = url_pattern:lower():gsub("\\/", "/")

  -- Match multi-TLD brand like `amazon(?:\.[a-z]{2,}){1,}` or `google(?:\.[a-z]{2,}){1,}`
  local brand = p:match("([a-z0-9%-]+)%(%?%:\\%.%[a%-z%]")
  if brand then
    local path_hint = p:match("%{1,%}(/[^$]+)")
    local path_pat = nil
    if path_hint and not path_hint:find("[%(%){}|]") then
      path_pat = translate_single_branch("^" .. path_hint)
    end
    return { hosts = { brand .. ".*" }, path_pat = path_pat }
  end

  -- Strip leading `^https?://` and optional subdomain prefix `(?:[a-z0-9-]+\.)*?`
  local clean = p:gsub("^%^https%?:?//", "")
  clean = clean:gsub("^%(%?%:[^%)]*%)%*?%??", "")
  clean = clean:gsub("^%(%?%:", "")

  -- Extract domain alternation like `(youtube\.com|youtu\.be)` or single domain `twitter.com` / `facebook\.com`
  local hosts = {}
  local seen = {}
  local function add_domain(raw_dom)
    local d = raw_dom:gsub("\\%.", "."):gsub("/.*$", "")
    if d:match("^[a-z0-9%-]+%.[a-z0-9%.%-]+$") and not d:find("%.%.") and not seen[d] then
      seen[d] = true
      hosts[#hosts + 1] = d
    end
  end

  local group = clean:match("^%(([^%(%)]+)%)")
  if group then
    for alt in group:gmatch("[^|]+") do
      add_domain(alt)
    end
  else
    -- Single domain possibly using escaped `\.` or raw `.`
    local dom_token = clean:match("^([a-z0-9%-\\\\%.]+)")
    if dom_token then
      add_domain(dom_token)
    end
  end

  if #hosts > 0 then
    return { hosts = hosts }
  end
  return nil
end

local function compile_clearurls_param_rule(rule_str)
  if type(rule_str) ~= "string" or rule_str == "" then
    return nil
  end
  -- ClearURLs prefixes many global rules with optional encoded `?`: `(?:%3F)?`
  local s = rule_str:gsub("^%(%?%:%%3[Ff]%)%?", "")
  if s == "" then
    return nil
  end
  -- Exact parameter name (only word/hyphen chars)
  if s:match("^[A-Za-z0-9_%-]+$") then
    return { kind = "exact", param = s:lower() }
  end
  -- Optional suffix group like `utm(?:_[a-z_]*)?` -> prefix `utm_`
  local pref_opt = s:match("^([A-Za-z0-9%-]+)%(%?%:_%[[^%]]+%]%*%)%?$")
  if pref_opt then
    return { kind = "prefix", prefix = pref_opt:lower() .. "_" }
  end
  -- Simple prefix like `utm_[a-z_]*`, `ga_[a-z_]+`, or `hsa_.*`
  local pref = s:match("^([A-Za-z0-9_%-]+)%.[%*%+]$")
    or s:match("^([A-Za-z0-9_%-]+)%[[^%]]+%][%*%+]$")
  if pref then
    return { kind = "prefix", prefix = pref:lower() }
  end
  local compiled = compile_regex("^" .. s .. "$", true)
  if compiled then
    return { kind = "regex", compiled = compiled, match_full = false }
  end
  return nil
end

function M.parse_clearurls(text, index, json_decode)
  index = index or M.new_index()
  local decode = json_decode or (_G.json and _G.json.decode)
  if type(decode) ~= "function" then
    return index, 0, 1
  end

  local data, err = decode(text)
  if type(data) ~= "table" or type(data.providers) ~= "table" then
    return index, 0, 1, err or "Invalid ClearURLs JSON"
  end

  local added = 0
  local skipped = 0

  for _, prov in pairs(data.providers) do
    if type(prov) == "table" and not prov.completeProvider then
      local host_info = extract_clearurls_hosts(prov.urlPattern)
      if host_info then
        local lists_to_merge = { prov.rules, prov.referralMarketing }
        for li = 1, #lists_to_merge do
          local rlist = lists_to_merge[li]
          if type(rlist) == "table" then
            for i = 1, #rlist do
              local spec = compile_clearurls_param_rule(rlist[i])
              if spec then
                if host_info.is_global then
                  if spec.kind == "exact" then
                    index.global_exact[spec.param] = true
                  elseif spec.kind == "prefix" then
                    index.global_prefixes[#index.global_prefixes + 1] = spec.prefix
                  elseif spec.kind == "regex" then
                    index.global_regex[#index.global_regex + 1] = { spec = spec }
                  end
                else
                  for hi = 1, #host_info.hosts do
                    add_domain_or_brand_rule(index, host_info.hosts[hi], {
                      spec = spec,
                      path_pat = host_info.path_pat,
                    }, false)
                  end
                end
                added = added + 1
              else
                skipped = skipped + 1
              end
            end
          end
        end
      else
        skipped = skipped + 1
      end
    end
  end

  index.total_rules = index.total_rules + added
  index.skipped_rules = index.skipped_rules + skipped
  return index, added, skipped
end

-- ============================================================================
-- Simple Plain-Text Custom List Parser
-- Supports:
--   `utm_source`               -> global exact param
--   `promo_*`                  -> global prefix
--   `x.com:a`                  -> domain-scoped param
--   `x.com:a,s,t`              -> multiple domain-scoped params
--   `@@example.com` / `!dom`   -> exempt domain
-- ============================================================================

function M.parse_plain(text, index)
  index = index or M.new_index()
  local added = 0
  local skipped = 0

  for raw_line in text:gmatch("[^\r\n]+") do
    local line = trim(raw_line)
    if line:sub(1, 3) == "\239\187\191" then
      line = trim(line:sub(4))
    end
    if line ~= "" and line:sub(1, 1) ~= "#" and line:sub(1, 1) ~= "!" then
      if line:sub(1, 2) == "@@" then
        local dom = trim(line:sub(3)):lower():gsub("^https?://", ""):gsub("/.*$", "")
        if dom ~= "" then
          if dom:sub(-2) == ".*" then
            index.except_brands[dom:sub(1, -3)] = true
          else
            index.except_domains[dom] = true
          end
          added = added + 1
        end
      elseif line:find(":", 1, true) then
        local dom, plist = line:match("^([^:]+):(.+)$")
        if dom and plist then
          dom = trim(dom):lower():gsub("^https?://", ""):gsub("/.*$", "")
          for tok in plist:gmatch("[^,%s]+") do
            local p = tok:lower()
            if p ~= "" then
              local spec
              if #p > 1 and p:sub(-1) == "*" then
                spec = { kind = "prefix", prefix = p:sub(1, -2) }
              else
                spec = { kind = "exact", param = p }
              end
              add_domain_or_brand_rule(index, dom, { spec = spec }, false)
              added = added + 1
            end
          end
        else
          skipped = skipped + 1
        end
      else
        local p = line:lower()
        if #p > 1 and p:sub(-1) == "*" then
          index.global_prefixes[#index.global_prefixes + 1] = p:sub(1, -2)
          added = added + 1
        elseif p:match("^[a-z0-9_%-%.]+$") then
          index.global_exact[p] = true
          added = added + 1
        else
          skipped = skipped + 1
        end
      end
    end
  end

  index.total_rules = index.total_rules + added
  index.skipped_rules = index.skipped_rules + skipped
  return index, added, skipped
end

---Auto-detects format (ClearURLs JSON, AdGuard/uBlock `$removeparam`, or plain list)
---and merges parsed rules into `index`.
---@param text string
---@param index? table
---@param opts? { json_decode?: fun(s: string): any }
---@return table index, integer added, integer skipped, string format
function M.parse_auto(text, index, opts)
  index = index or M.new_index()
  if type(text) ~= "string" or text == "" then
    return index, 0, 0, "empty"
  end
  local sample = text:sub(1, 4096)
  local first_nonspace = sample:match("^%s*(.)")
  if sample:sub(1, 3) == "\239\187\191" then
    first_nonspace = sample:sub(4):match("^%s*(.)")
  end

  if first_nonspace == "{" then
    local _, added, skipped = M.parse_clearurls(text, index, opts and opts.json_decode)
    return index, added, skipped, "clearurls"
  end

  if text:find("removeparam", 1, true) then
    local _, added, skipped = M.parse_adblock(text, index)
    return index, added, skipped, "adblock"
  end

  local _, added, skipped = M.parse_plain(text, index)
  return index, added, skipped, "plain"
end

-- ============================================================================
-- Fast Indexed Matching Against a Parsed URL
-- ============================================================================

local function rule_applies_to_url(rule, host_lower, brand, path_lower, url_lower)
  if rule.host_spec and not host_matches_spec(host_lower, brand, rule.host_spec) then
    return false
  end
  if rule.neg_domains then
    for i = 1, #rule.neg_domains do
      if host_matches_spec(host_lower, brand, rule.neg_domains[i]) then
        return false
      end
    end
  end
  if rule.path_pat and not path_lower:find(rule.path_pat) then
    return false
  end
  if rule.url_pat and not url_lower:find(rule.url_pat) then
    return false
  end
  return true
end

local function spec_matches_param(spec, param)
  local matched = false
  if spec.kind == "all" then
    matched = true
  elseif spec.kind == "exact" then
    matched = (param.key_lower == spec.param)
  elseif spec.kind == "prefix" then
    local p = spec.prefix
    matched = (#param.key_lower >= #p and param.key_lower:sub(1, #p) == p)
  elseif spec.kind == "regex" then
    local target = spec.match_full and param.raw or param.key_lower
    matched = match_compiled_regex(spec.compiled, target)
  end

  if spec.inverted then
    return not matched
  end
  return matched
end

---Creates a per-URL evaluation context against a compiled list index (fast O(labels) lookup).
---@param index table
---@param parsed table parsed URL from cleaner.parse_url
---@param full_url string
---@return table ctx
function M.prepare_url(index, parsed, full_url)
  local host_lower = parsed.host_lower
  local brand = extract_brand(host_lower)
  local path_lower = (parsed.path or ""):lower()
  local url_lower = full_url:lower()

  -- Check whole-domain / whole-brand exceptions (`@@||archive.*^$removeparam`)
  if brand and index.except_brands[brand] then
    return { exempt_all = true }
  end

  local dom_buckets = {}
  local except_rules = {}

  local candidate = host_lower
  while candidate and candidate ~= "" do
    if index.except_domains[candidate] then
      return { exempt_all = true }
    end
    local er = index.except_domain_rules[candidate]
    if er then
      for i = 1, #er do
        if rule_applies_to_url(er[i], host_lower, brand, path_lower, url_lower) then
          if er[i].spec.kind == "all" then
            return { exempt_all = true }
          end
          except_rules[#except_rules + 1] = er[i]
        end
      end
    end
    local b = index.domain_exact[candidate]
    if b then
      dom_buckets[#dom_buckets + 1] = b
    end
    local dot = candidate:find(".", 1, true)
    if not dot then
      break
    end
    candidate = candidate:sub(dot + 1)
  end

  if brand then
    local ebr = index.except_brand_rules[brand]
    if ebr then
      for i = 1, #ebr do
        if rule_applies_to_url(ebr[i], host_lower, brand, path_lower, url_lower) then
          if ebr[i].spec.kind == "all" then
            return { exempt_all = true }
          end
          except_rules[#except_rules + 1] = ebr[i]
        end
      end
    end
    local bb = index.brand_rules[brand]
    if bb then
      dom_buckets[#dom_buckets + 1] = bb
    end
  end

  return {
    exempt_all = false,
    index = index,
    host_lower = host_lower,
    brand = brand,
    path_lower = path_lower,
    url_lower = url_lower,
    dom_buckets = dom_buckets,
    except_rules = except_rules,
  }
end

---Evaluates whether `param` should be stripped according to the compiled 3rd-party lists.
---@param ctx table from M.prepare_url
---@param param table { raw, key_lower, ... }
---@return boolean should_strip, boolean is_exempt
function M.match_param(ctx, param)
  if not ctx or ctx.exempt_all then
    return false, true
  end

  local index = ctx.index
  local key = param.key_lower

  -- Step 1: Check parameter-level exceptions (`@@...`)
  for i = 1, #ctx.except_rules do
    if spec_matches_param(ctx.except_rules[i].spec, param) then
      return false, true
    end
  end
  local ep = index.except_by_param[key]
  if ep then
    for i = 1, #ep do
      if rule_applies_to_url(ep[i], ctx.host_lower, ctx.brand, ctx.path_lower, ctx.url_lower) then
        return false, true
      end
    end
  end
  for i = 1, #index.except_generic do
    local eg = index.except_generic[i]
    if rule_applies_to_url(eg, ctx.host_lower, ctx.brand, ctx.path_lower, ctx.url_lower)
      and spec_matches_param(eg.spec, param)
    then
      return false, true
    end
  end

  -- Step 2: Check global exact & prefix rules (O(1) / tiny array)
  if index.global_exact[key] then
    return true, false
  end
  local gprefs = index.global_prefixes
  for i = 1, #gprefs do
    local p = gprefs[i]
    if #key >= #p and key:sub(1, #p) == p then
      return true, false
    end
  end

  -- Step 3: Check domain & brand buckets
  for i = 1, #ctx.dom_buckets do
    local b = ctx.dom_buckets[i]
    if b.params[key] then
      return true, false
    end
    local brules = b.rules
    for j = 1, #brules do
      local r = brules[j]
      if rule_applies_to_url(r, ctx.host_lower, ctx.brand, ctx.path_lower, ctx.url_lower)
        and spec_matches_param(r.spec, param)
      then
        return true, false
      end
    end
  end

  -- Step 4: Check URL-conditioned rules indexed by this exact param name (O(1) lookup!)
  local up = index.url_by_param[key]
  if up then
    for i = 1, #up do
      if rule_applies_to_url(up[i], ctx.host_lower, ctx.brand, ctx.path_lower, ctx.url_lower) then
        return true, false
      end
    end
  end

  -- Step 5: Check global regex & generic URL rules
  local gr = index.global_regex
  for i = 1, #gr do
    local r = gr[i]
    if rule_applies_to_url(r, ctx.host_lower, ctx.brand, ctx.path_lower, ctx.url_lower)
      and spec_matches_param(r.spec, param)
    then
      return true, false
    end
  end
  local ug = index.url_generic
  for i = 1, #ug do
    local r = ug[i]
    if rule_applies_to_url(r, ctx.host_lower, ctx.brand, ctx.path_lower, ctx.url_lower)
      and spec_matches_param(r.spec, param)
    then
      return true, false
    end
  end

  return false, false
end

return M
