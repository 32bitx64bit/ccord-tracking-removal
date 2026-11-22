# Tracking Removal (C-Cord Extension)

Automatically strips tracking parameters, cleans tracking path segments/fragments, and unwraps redirect links in **C-Cord** — both **when opening links** and **before sending or editing Discord messages**.

Powered by **auto-updating 3rd-party community filter lists** (AdGuard URL Tracking Filter #17 by default, plus optional DandelionSprout and ClearURLs), **custom remote URL subscriptions**, **local file imports**, and built-in redirect unwrapping & strict canonical cleaning.

## Features

- **Automatic outgoing & edited message sanitization (`messages.hook`)**: Strips tracking parameters and unwraps redirectors before messages are sent to Discord.
- **Automatic link-open sanitization (`notifications.hook`)**: Cleans URLs before C-Cord opens them in your browser.
- **Auto-Updating 3rd-Party Filter Lists (`network.http`)**:
  - **AdGuard URL Tracking Filter (#17)** *(enabled by default)* — Daily community-maintained `$removeparam` list (2,700+ rules including `x.com ?a=`, with automatic mirror failover and `@@` safety exceptions like Wayback Machine `archive.*`).
  - **DandelionSprout's Actually Legitimate URL Shortener** *(optional toggle)* — Aggressive daily community list (3,100+ rules).
  - **ClearURLs Rules (JSON)** *(optional toggle)* — Popular ClearURLs provider ruleset.
  - All remote lists are gzip-compressed in local plugin storage for instant offline startup and refreshed automatically in the background (default every 24h, configurable).
- **Custom List Import (Remote URLs & Local Files)**:
  - Subscribe to any custom HTTPS list via Settings (**Custom Filter List URLs**) or `/cleanurl add-list <https://...>`.
  - Import local `.txt` or `.json` files via `/cleanurl import` (OS file picker).
  - Auto-detects **AdGuard / uBlock Origin `$removeparam`**, **ClearURLs JSON**, and **simple plain-text lists** (`utm_source`, `promo_*`, `x.com:a,s`, `@@exempt.com`).
- **Redirect Unwrapping & Strict Canonical Cleaning** *(handles what Adblock lists cannot do alone)*:
  - Unwraps Google `/url` & AMP, YouTube `/redirect`, Facebook (`l.facebook.com`), Instagram (`l.instagram.com`), Reddit (`out.reddit.com`), Steam (`steamcommunity.com/linkfilter`), Bing (`/ck/a` Base64), DuckDuckGo (`/l/`), Yahoo (`/RU=`), Outlook SafeLinks, Disqus, Tumblr, VK, SoundCloud (`gate.sc`), Pocket, Slack, and affiliate redirectors (including nested redirects).
  - **Strict Canonical Cleaning** (enabled by default): On canonical post, video, track, and product paths (X `/status/`, YouTube `/watch`/`/shorts`/`youtu.be`, Spotify, TikTok, Instagram, Threads, Reddit `/comments/`, Amazon `/dp/`, eBay `/itm/`, Steam Store), keeps only known functional parameters so even newly rotated tracking tokens are stripped immediately.
  - Cleans tracking `#fragments` (`#utm_*`, `#Echobox=...`) and tracking path segments (Amazon `/ref=...`, StackOverflow sharer user IDs `/q/<id>/<uid>`).
- **Safe by Design**:
  - Preserves Discord CDN signed URLs (`cdn.discordapp.com`, `media.discordapp.net`), OAuth endpoints (`accounts.google.com`, etc.), GitHub `?ref=`, Spotify collaborative playlist invite tokens (`pt`), scroll-to-text highlights (`#:~:text=...`), SPA hash routes (`#/route`), and exact encoding of untouched parameters.
  - Preserves Discord Markdown (`[label](url)`, `<url>`, `||url||`, `**bold**`, balanced parentheses) and skips inline code / fenced code blocks by default.
- **Right-Click Context Menu**: Right-click any link → **Copy Clean URL (No Tracking)**.
- **Slash Command (`/cleanurl`)**:
  - `/cleanurl lists` — View active 3rd-party & custom lists, rule counts, and sync status (with **Update Now** button)
  - `/cleanurl update` — Force-update all enabled remote lists immediately
  - `/cleanurl import` — Import a local `.txt` or `.json` custom list via file picker
  - `/cleanurl add-list <https://...>` — Subscribe to a custom HTTPS filter list URL
  - `/cleanurl remove-list <name-or-url>` — Remove a custom remote or local list
  - `/cleanurl inspect <url>` — Preview before/after URL and removed parameters in a modal
  - `/cleanurl <url or text>` — Clean immediately and copy to clipboard
  - `/cleanurl stats` / `toggle` / `reset` — View stats, pause/resume, or reset counters

## Permissions

Declares **API Class 3** permissions strictly needed for link interception and 3rd-party list updates:

- `messages.hook` — Intercept and rewrite outgoing and edited messages before send.
- `notifications.hook` — Intercept and rewrite URLs before opening links.
- `network.http` — Fetch and auto-update enabled 3rd-party & custom HTTPS filter lists.

## Installation & Development

1. **Install from C-Cord Plugin Catalog**: Search for **Tracking Removal** under **Settings → Plugins → Discover**, or open `ccord://plugins/install/io.github.32bitx64bit.tracking-removal`.
2. **Or install `.cce` from GitHub Releases**: Download `io.github.32bitx64bit.tracking-removal-1.1.0.cce` from [Releases](https://github.com/32bitx64bit/ccord-tracking-removal/releases) and install under **Settings → Plugins**, then approve the permissions prompt.
3. **Or run directly from source in dev mode**:
   ```bash
   ccord --plugin-dir "/path/to/parent-folder-containing-plugin" --plugin-dev
   ```
4. **Run syntax checks and tests**:
   ```bash
   luac5.5 -p rules.lua list_parser.lua lists.lua cleaner.lua main.lua
   lua5.5 tests/test_cleaner.lua
   lua5.5 tests/test_main.lua
   ```
5. **Repackage `.cce`**:
   ```bash
   zip -r9 io.github.32bitx64bit.tracking-removal-1.1.0.cce . -x ".git/*" ".github/*" "tests/*" "*.cce" "*.zip" ".*"
   ```
