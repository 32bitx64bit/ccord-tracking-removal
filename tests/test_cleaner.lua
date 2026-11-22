-- Comprehensive unit test suite for Tracking Removal (Lua 5.5)
-- Run from plugin root: lua5.5 tests/test_cleaner.lua

local cleaner = require("cleaner")

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

local function test_url(name, input, expected, opts)
  local actual = cleaner.clean_url(input, opts)
  assert_eq(name, actual, expected)
end

local function test_text(name, input, expected, opts)
  local actual = cleaner.clean_text(input, opts)
  assert_eq(name, actual, expected)
end

-- ============================================================================
-- 1. X.com / Twitter & Embed Fixers
-- ============================================================================
test_url(
  "X.com share link (s & t stripped)",
  "https://x.com/rustlang/status/1234567890?s=20&t=AbCdEfGhIjKlMnOpQrStUv",
  "https://x.com/rustlang/status/1234567890"
)
test_url(
  "X.com new ?a= share tracking link stripped",
  "https://x.com/AqueleJunio/status/2124282949608603764?a=zd4wZf288aIM6IVgipk&s=20",
  "https://x.com/AqueleJunio/status/2124282949608603764"
)
test_url(
  "X.com ?a= stripped even with strict_canonical=false",
  "https://x.com/AqueleJunio/status/2124282949608603764?a=zd4wZf288aIM6IVgipk&s=20",
  "https://x.com/AqueleJunio/status/2124282949608603764",
  { strict_canonical = false }
)
test_url(
  "X.com profile ?a= & s= stripped",
  "https://x.com/AqueleJunio?a=zd4wZf288aIM6IVgipk&s=20",
  "https://x.com/AqueleJunio"
)
test_url(
  "X.com strict canonical strips unknown future tracking params on /status/",
  "https://x.com/user/status/9876543210?z=future_tracker&sh_id=xyz&s=20",
  "https://x.com/user/status/9876543210"
)
test_url(
  "Twitter.com with ref_src & ref_url",
  "https://twitter.com/user/status/999?ref_src=twsrc%5Etfw&ref_url=https%3A%2F%2Fexample.com&s=46&t=xyz",
  "https://twitter.com/user/status/999"
)
test_url(
  "X.com search preserves q & f while stripping src",
  "https://x.com/search?q=ccord&src=typed_query&f=live",
  "https://x.com/search?q=ccord&f=live"
)
test_url(
  "fxtwitter / vxtwitter / fixupx share links",
  "https://fxtwitter.com/user/status/42?s=20&t=abc123",
  "https://fxtwitter.com/user/status/42"
)

-- ============================================================================
-- 2. YouTube
-- ============================================================================
test_url(
  "youtu.be strips si, preserves t",
  "https://youtu.be/dQw4w9WgXcQ?si=1a2b3c4d5e6f7g8h&t=42",
  "https://youtu.be/dQw4w9WgXcQ?t=42"
)
test_url(
  "youtube.com watch strips si, pp, feature, ab_channel; keeps v, list, index, t",
  "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PL123&index=3&si=trackme&pp=ygU1&feature=shared&ab_channel=Rick&t=15s",
  "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PL123&index=3&t=15s"
)
test_url(
  "YouTube Shorts strips si & feature",
  "https://www.youtube.com/shorts/abcdef12345?si=987654321&feature=share",
  "https://www.youtube.com/shorts/abcdef12345"
)
test_url(
  "YouTube Music strips si",
  "https://music.youtube.com/watch?v=abc123&si=xyz987",
  "https://music.youtube.com/watch?v=abc123"
)
test_url(
  "YouTube linked comment (lc) preserved",
  "https://www.youtube.com/watch?v=abc123&lc=UgzCommentId&si=xyz",
  "https://www.youtube.com/watch?v=abc123&lc=UgzCommentId"
)
test_url(
  "YouTube /redirect unwrapped and destination cleaned",
  "https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhq&q=https%3A%2F%2Fx.com%2Fdev%2Fstatus%2F1%3Fs%3D20%26t%3Dxyz&v=abc",
  "https://x.com/dev/status/1"
)

-- ============================================================================
-- 3. Google (Search, ccTLDs, /url, AMP, Docs/Drive, Maps, Play Store, Accounts)
-- ============================================================================
test_url(
  "Google Search strips tracking params while preserving q & udm",
  "https://www.google.com/search?q=lua+5.5&sca_esv=123&source=hp&ei=abc&iflsig=def&ved=0ahUKE&uact=5&oq=lua+5.5&gs_lcrp=xyz&sclient=gws-wiz&udm=14",
  "https://www.google.com/search?q=lua+5.5&udm=14"
)
test_url(
  "Google UK ccTLD search cleaned",
  "https://www.google.co.uk/search?q=privacy&ved=123&ei=456&rlz=1C1GCEA",
  "https://www.google.co.uk/search?q=privacy"
)
test_url(
  "Google /url redirect unwrapped & target trackers stripped",
  "https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKE&url=https%3A%2F%2Fexample.com%2Fpost%3Futm_source%3Dgoogle%26id%3D7&usg=AOvVaw",
  "https://example.com/post?id=7"
)
test_url(
  "Google /amp/s/ wrapper unwrapped & cleaned",
  "https://www.google.com/amp/s/example.com/news/story?utm_source=amp&amp_js_v=0.1&page=2",
  "https://example.com/news/story?page=2"
)
test_url(
  "AMP Project CDN wrapper unwrapped",
  "https://example-com.cdn.ampproject.org/c/s/example.com/article?usqp=mq331AQ",
  "https://example.com/article"
)
test_url(
  "Google Docs strips usp=sharing, preserves resourcekey & gid",
  "https://docs.google.com/spreadsheets/d/1ABC/edit?usp=sharing&resourcekey=0-xyz&gid=12345#gid=12345",
  "https://docs.google.com/spreadsheets/d/1ABC/edit?resourcekey=0-xyz&gid=12345#gid=12345"
)
test_url(
  "Google Maps strips g_ep & entry, keeps q",
  "https://maps.google.com/?q=Paris&entry=ttu&g_ep=EgoyMDI0",
  "https://maps.google.com/?q=Paris"
)
test_url(
  "Google Accounts OAuth URL is immune",
  "https://accounts.google.com/o/oauth2/v2/auth?client=web&source=login&utm_source=keep",
  "https://accounts.google.com/o/oauth2/v2/auth?client=web&source=login&utm_source=keep"
)
test_url(
  "Spoofed google.evil.com does not trigger Google brand rules",
  "https://google.evil.com/page?ved=keep_me&utm_source=strip_me",
  "https://google.evil.com/page?ved=keep_me"
)

-- ============================================================================
-- 4. Reddit, Instagram, Facebook, Threads, TikTok
-- ============================================================================
test_url(
  "Reddit strips share_id & utm_*, keeps context",
  "https://www.reddit.com/r/linux/comments/abc123/cool_post/?utm_source=share&utm_medium=web3x&share_id=UNIQUE_TRACKER&context=3",
  "https://www.reddit.com/r/linux/comments/abc123/cool_post/?context=3"
)
test_url(
  "Reddit out.reddit.com unwrapped",
  "https://out.reddit.com/t3_abc?url=https%3A%2F%2Fexample.org%2Fpage%3Ffbclid%3D123&token=xyz",
  "https://example.org/page"
)
test_url(
  "Instagram strips igsh, keeps img_index",
  "https://www.instagram.com/p/C1234567890/?igsh=MTIzNDU2Nzg5MA==&img_index=2",
  "https://www.instagram.com/p/C1234567890/?img_index=2"
)
test_url(
  "Instagram l.instagram.com unwrapped",
  "https://l.instagram.com/?u=https%3A%2F%2Fexample.com%2F%3Futm_campaign%3Dig&e=AT123",
  "https://example.com/"
)
test_url(
  "Facebook strips fbclid, mibextid, encoded __cft__[0], __tn__",
  "https://www.facebook.com/story.php?story_fbid=123&id=456&mibextid=abc&__cft__%5B0%5D=AZV123&__tn__=%2CO%2CP-R",
  "https://www.facebook.com/story.php?story_fbid=123&id=456"
)
test_url(
  "Facebook l.facebook.com unwrapped",
  "https://l.facebook.com/l.php?u=https%3A%2F%2Fyoutu.be%2Fabc%3Fsi%3D123%26t%3D9&h=AT0abc",
  "https://youtu.be/abc?t=9"
)
test_url(
  "Threads strips xmt",
  "https://www.threads.net/@user/post/ABC123?xmt=AQGz12345",
  "https://www.threads.net/@user/post/ABC123"
)
test_url(
  "TikTok strips user_id, _t, _r, checksum, is_from_webapp",
  "https://www.tiktok.com/@creator/video/7123456789?_t=8abc&_r=1&is_from_webapp=1&sender_device=pc&user_id=999999&checksum=deadbeef",
  "https://www.tiktok.com/@creator/video/7123456789"
)

-- ============================================================================
-- 5. Amazon, eBay, AliExpress, Temu, Etsy, Walmart
-- ============================================================================
test_url(
  "Amazon strips /ref=... path and tracking params, keeps th=1",
  "https://www.amazon.com/Cool-Gadget/dp/B09XS7JWHH/ref=sr_1_3?crid=1ABC&dib=eyJ&dib_tag=se&keywords=gadget&qid=1700000&sprefix=gad&sr=8-3&tag=aff-20&th=1",
  "https://www.amazon.com/Cool-Gadget/dp/B09XS7JWHH?th=1"
)
test_url(
  "Amazon shorten_amazon canonicalizes to /dp/ASIN",
  "https://www.amazon.co.uk/Cool-Gadget/dp/B09XS7JWHH/ref=sr_1_3?qid=123&psc=1",
  "https://www.amazon.co.uk/dp/B09XS7JWHH?psc=1",
  { shorten_amazon = true }
)
test_url(
  "eBay strips _trkparms, _trksid, mkcid; keeps var",
  "https://www.ebay.com/itm/123456789?hash=item123&_trkparms=abc&_trksid=p2047675&mkcid=1&var=555",
  "https://www.ebay.com/itm/123456789?var=555"
)
test_url(
  "AliExpress strips spm, algo_pvid, pdp_npi",
  "https://www.aliexpress.com/item/1005001234567.html?spm=a2g0o.productlist&algo_pvid=abc&pdp_npi=123",
  "https://www.aliexpress.com/item/1005001234567.html"
)
test_url(
  "Temu strips _x_* and refer_page_* prefixes",
  "https://www.temu.com/goods.html?goods_id=12345&_x_sessn_id=secret&_x_ads_channel=google&refer_page_name=home",
  "https://www.temu.com/goods.html?goods_id=12345"
)
test_url(
  "Etsy strips click_key, ga_*, ref; keeps variation0",
  "https://www.etsy.com/listing/123456/handmade-mug?click_key=abc&ref=sr_gallery&ga_order=most_relevant&variation0=999",
  "https://www.etsy.com/listing/123456/handmade-mug?variation0=999"
)

-- ============================================================================
-- 6. Spotify, SoundCloud, Steam, Twitch, LinkedIn, Substack, Medium, News, SO
-- ============================================================================
test_url(
  "Spotify strips si & context",
  "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT?si=abc123def456&context=spotify%3Aplaylist%3A123",
  "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT"
)
test_url(
  "Spotify strips unknown future params on tracks while preserving pt on collab playlists",
  "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M?si=track123&pt=collab_secret&future_x=1",
  "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M?pt=collab_secret"
)
test_url(
  "YouTube strict canonical strips unknown future params while keeping v & t",
  "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42&future_yt_token=xyz123",
  "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42"
)
test_url(
  "SoundCloud strips si, keeps playlist 'in'",
  "https://soundcloud.com/artist/track?si=xyz123&in=artist/sets/album&utm_source=clipboard",
  "https://soundcloud.com/artist/track?in=artist/sets/album"
)
test_url(
  "Steam store strips snr, linkfilter unwrapped",
  "https://store.steampowered.com/app/440/Team_Fortress_2/?snr=1_7_15__13",
  "https://store.steampowered.com/app/440/Team_Fortress_2/"
)
test_url(
  "Steam linkfilter unwrapped",
  "https://steamcommunity.com/linkfilter/?u=https%3A%2F%2Fexample.com%2F%3Futm_source%3Dsteam",
  "https://example.com/"
)
test_url(
  "LinkedIn strips trk, lipi, rcm",
  "https://www.linkedin.com/in/someone/?trk=public_profile&lipi=urn%3Ali&rcm=abc",
  "https://www.linkedin.com/in/someone/"
)
test_url(
  "Substack strips sharer r= and triedRedirect",
  "https://newsletter.substack.com/p/great-article?r=1a2b3c&utm_campaign=post&triedRedirect=true",
  "https://newsletter.substack.com/p/great-article"
)
test_url(
  "Medium strips source & gi, preserves Friend Link sk",
  "https://medium.com/@author/story-123?source=friends_link&sk=friendkey123&gi=abc",
  "https://medium.com/@author/story-123?sk=friendkey123"
)
test_url(
  "NYTimes strips smid & emc, preserves unlocked_article_code",
  "https://www.nytimes.com/2026/01/01/world/story.html?unlocked_article_code=1.ABC&smid=url-share&emc=edit_nn",
  "https://www.nytimes.com/2026/01/01/world/story.html?unlocked_article_code=1.ABC"
)
test_url(
  "StackOverflow strips sharer user ID from /q/<id>/<uid> and /a/<id>/<uid>",
  "https://stackoverflow.com/a/12345678/9876543",
  "https://stackoverflow.com/a/12345678"
)
test_url(
  "StackOverflow preserves full /questions/<id>/<slug>",
  "https://stackoverflow.com/questions/12345678/how-to-parse-urls",
  "https://stackoverflow.com/questions/12345678/how-to-parse-urls"
)

-- ============================================================================
-- 7. Advanced Redirect Unwrappers (Bing base64, Outlook SafeLinks, DDG, Yahoo, Disqus, Nested)
-- ============================================================================
-- "https://example.com/page?utm_source=bing&ok=1" -> base64url:
-- aHR0cHM6Ly9leGFtcGxlLmNvbS9wYWdlP3V0bV9zb3VyY2U9YmluZyZvaz0x
test_url(
  "Bing /ck/a base64url unwrapped & cleaned",
  "https://www.bing.com/ck/a?!&&p=1234&u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS9wYWdlP3V0bV9zb3VyY2U9YmluZyZvaz0x&ntb=1",
  "https://example.com/page?ok=1"
)
test_url(
  "Outlook SafeLinks unwrapped & cleaned",
  "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fyoutu.be%2FdQw4w9WgXcQ%3Fsi%3Dabc%26t%3D10&data=05%7C01&sdata=xyz&reserved=0",
  "https://youtu.be/dQw4w9WgXcQ?t=10"
)
test_url(
  "DuckDuckGo /l/ redirect unwrapped",
  "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2F%3Ffbclid%3D999&rut=abc",
  "https://example.com/"
)
test_url(
  "Yahoo /RU= redirect unwrapped",
  "https://r.search.yahoo.com/_ylt=Awr/RV=2/RE=1700000/RO=10/RU=https%3A%2F%2Fexample.com%2Fnews%3Fgclid%3D123/RK=2/RS=abc-",
  "https://example.com/news"
)
test_url(
  "Disqus redirect unwrapped & signature hash stripped",
  "https://disq.us/url?url=https%3A%2F%2Fexample.com%2Fpost%3Futm_medium%3Ddisqus%3AaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456&cuid=123",
  "https://example.com/post"
)
test_url(
  "Nested multi-hop redirect (SafeLinks -> Google /url -> X.com)",
  "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%253A%252F%252Fx.com%252Fuser%252Fstatus%252F7%253Fs%253D20%2526t%253Dabc&data=1",
  "https://x.com/user/status/7"
)
test_url(
  "Cyclic redirect terminates safely without infinite loop",
  "https://www.google.com/url?q=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%253A%252F%252Fexample.com%252F%253Futm_source%253Dx",
  "https://example.com/"
)

-- ============================================================================
-- 8. Fragments & Safety / Preservation Invariants
-- ============================================================================
test_url(
  "Tracking fragment stripped completely",
  "https://example.com/article#utm_source=twitter&utm_medium=social",
  "https://example.com/article"
)
test_url(
  "Tracking fragment stripped while preserving non-tracking fragment param",
  "https://example.com/article#page=2&utm_source=twitter",
  "https://example.com/article#page=2"
)
test_url(
  "Normal anchor fragment untouched",
  "https://example.com/docs?utm_source=test#installation-guide",
  "https://example.com/docs#installation-guide"
)
test_url(
  "Scroll-to-text fragment (#:~:text=...) untouched",
  "https://example.com/page?fbclid=123#:~:text=hello%20world",
  "https://example.com/page#:~:text=hello%20world"
)
test_url(
  "SPA hash route (#/route?tab=1) untouched",
  "https://example.com/#/dashboard?utm_source=ignored_in_spa",
  "https://example.com/#/dashboard?utm_source=ignored_in_spa"
)
test_url(
  "Discord CDN signed URL completely immune",
  "https://cdn.discordapp.com/attachments/123/456/image.png?ex=6789abcd&is=67885a4d&hm=deadbeef&utm_source=never_touch",
  "https://cdn.discordapp.com/attachments/123/456/image.png?ex=6789abcd&is=67885a4d&hm=deadbeef&utm_source=never_touch"
)
test_url(
  "GitHub ?ref=main preserved while utm_* stripped",
  "https://github.com/org/repo/blob/main/README.md?ref=main&utm_source=discord&plain=1",
  "https://github.com/org/repo/blob/main/README.md?ref=main&plain=1"
)
test_url(
  "WordPress ?s=search preserved (s only stripped on X/FB/IG/etc.)",
  "https://myblog.example.org/?s=privacy+tools&fbclid=12345",
  "https://myblog.example.org/?s=privacy+tools"
)
test_url(
  "Already clean URL returned byte-for-byte identical",
  "https://example.com/search?q=a+b&tag=c%2Fd&empty=",
  "https://example.com/search?q=a+b&tag=c%2Fd&empty="
)

-- ============================================================================
-- 9. Custom Params & Ignored Domains
-- ============================================================================
local custom_exact, custom_prefixes = cleaner.parse_custom_params("my_ref, promo_*, SECRET_TRACK")
local ignored = cleaner.parse_domain_list("keepme.org, https://internal.corp/path")
local custom_opts = {
  custom_exact = custom_exact,
  custom_prefixes = custom_prefixes,
  ignored_domains = ignored,
}
test_url(
  "Custom exact and wildcard params stripped",
  "https://shop.example.com/item?id=42&my_ref=abc&promo_code=SAVE&secret_track=1",
  "https://shop.example.com/item?id=42",
  custom_opts
)
test_url(
  "Ignored domain & subdomain untouched",
  "https://sub.keepme.org/page?utm_source=test&fbclid=123",
  "https://sub.keepme.org/page?utm_source=test&fbclid=123",
  custom_opts
)

-- ============================================================================
-- 10. Discord Message Text Processing (Markdown, Spoilers, Code Blocks, Punctuation)
-- ============================================================================
test_text(
  "Prose with trailing punctuation",
  "Check this out https://x.com/user/status/123?s=20&t=abc! Pretty cool, right?",
  "Check this out https://x.com/user/status/123! Pretty cool, right?"
)
test_text(
  "Angle-bracket suppressed embed",
  "See <https://youtu.be/dQw4w9WgXcQ?si=12345&t=30> for details.",
  "See <https://youtu.be/dQw4w9WgXcQ?t=30> for details."
)
test_text(
  "Discord spoiler tags preserved",
  "Spoiler: ||https://x.com/user/status/42?s=20&t=xyz||",
  "Spoiler: ||https://x.com/user/status/42||"
)
test_text(
  "Masked Markdown link with balanced parentheses",
  "Read [Lua](https://en.wikipedia.org/wiki/Lua_(programming_language)?utm_source=discord) now!",
  "Read [Lua](https://en.wikipedia.org/wiki/Lua_(programming_language)) now!"
)
test_text(
  "Parenthesized URL in prose",
  "Look here (https://open.spotify.com/track/123?si=abcdef) later.",
  "Look here (https://open.spotify.com/track/123) later."
)
test_text(
  "Bold and strikethrough Markdown around URLs preserved",
  "**Check https://x.com/a/status/1?s=20** and ~~https://youtu.be/xyz?si=999~~",
  "**Check https://x.com/a/status/1** and ~~https://youtu.be/xyz~~"
)
test_text(
  "Inline code and fenced code blocks skipped by default",
  "Try `https://example.com/?utm_source=keep` and:\n```lua\nlocal u = \"https://x.com/a/status/1?s=20\"\n```\nBut clean https://x.com/a/status/1?s=20.",
  "Try `https://example.com/?utm_source=keep` and:\n```lua\nlocal u = \"https://x.com/a/status/1?s=20\"\n```\nBut clean https://x.com/a/status/1."
)
test_text(
  "Question mark after URL preserved",
  "Did you watch https://youtu.be/abc?si=123?",
  "Did you watch https://youtu.be/abc?"
)
test_text(
  "Multiple URLs in one UTF-8 message",
  "🔥 https://youtu.be/abc?si=123 & https://github.com/a/b?ref=main & https://www.google.com/url?q=https%3A%2F%2Fexample.com%2F%3Ffbclid%3D1.",
  "🔥 https://youtu.be/abc & https://github.com/a/b?ref=main & https://example.com/."
)

-- Summary
-- ============================================================================
-- 11. 3rd-Party & Custom Filter List Parser (AdGuard, ClearURLs, Plain Text)
-- ============================================================================
local list_parser = require("list_parser")

local sample_adblock = [[
! Title: Sample AdGuard / uBlock Filter
$removeparam=pjclid
$removeparam=tgclid
$removeparam=/^at_custom/
$removeparam=/^source=googleps$/
$removeparam=promo,domain=shop.example|store.example
$removeparam=aid,domain=~safe.example
||x.com^$removeparam=a
||luna.amazon.*^$removeparam=ref
||go.mysku.ru^$removeparam=~r
||campaigns.example.com^$xmlhttprequest,removeparam=xhr_only
?from=glia^$removeparam=from
@@||archive.*^$removeparam
@@^mkt_unsubscribe=$removeparam=mkt_tok
]]

local ag_idx, ag_added, ag_skipped, ag_fmt = list_parser.parse_auto(sample_adblock)
assert_eq("Adblock format auto-detected", ag_fmt, "adblock")
assert_eq("Adblock parsed expected rule count", ag_added, 12)
assert_eq("Adblock skipped subresource-only rule", ag_skipped, 1)

local ag_opts = {
  compiled_lists = ag_idx,
  use_builtin_rules = false,
  strict_canonical = false,
}

test_url(
  "Adblock global exact & prefix regex stripped",
  "https://example.org/p?pjclid=1&tgclid=2&at_custom7=hi&keep=ok",
  "https://example.org/p?keep=ok",
  ag_opts
)
test_url(
  "Adblock key=value regex strips only matching value",
  "https://example.org/p?source=googleps&ok=1",
  "https://example.org/p?ok=1",
  ag_opts
)
test_url(
  "Adblock key=value regex keeps non-matching value",
  "https://example.org/p?source=organic&ok=1",
  "https://example.org/p?source=organic&ok=1",
  ag_opts
)
test_url(
  "Adblock domain= option matches listed domains only",
  "https://sub.shop.example/item?promo=123&id=5",
  "https://sub.shop.example/item?id=5",
  ag_opts
)
test_url(
  "Adblock negated domain (~safe.example) respected",
  "https://safe.example/page?aid=keep",
  "https://safe.example/page?aid=keep",
  ag_opts
)
test_url(
  "Adblock negated domain still strips on other domains",
  "https://other.example/page?aid=strip&id=1",
  "https://other.example/page?id=1",
  ag_opts
)
test_url(
  "Adblock multi-label brand wildcard (||luna.amazon.*^) does not leak globally",
  "https://github.com/org/repo?ref=main",
  "https://github.com/org/repo?ref=main",
  ag_opts
)
test_url(
  "Adblock multi-label brand wildcard matches luna.amazon.co.uk",
  "https://luna.amazon.co.uk/game?ref=strip&id=1",
  "https://luna.amazon.co.uk/game?id=1",
  ag_opts
)
test_url(
  "Adblock inverted removeparam=~r keeps only r",
  "https://go.mysku.ru/go?r=target&track=1&foo=2",
  "https://go.mysku.ru/go?r=target",
  ag_opts
)
test_url(
  "Adblock subresource-only ($xmlhttprequest) rule skipped",
  "https://campaigns.example.com/p?xhr_only=keep",
  "https://campaigns.example.com/p?xhr_only=keep",
  ag_opts
)
test_url(
  "Adblock URL-conditioned rule (?from=glia^$removeparam=from)",
  "https://news.example/article?from=glia&id=2",
  "https://news.example/article?id=2",
  ag_opts
)
test_url(
  "Adblock whole-brand exception (@@||archive.*^$removeparam) protects Wayback Machine",
  "https://web.archive.org/web/2025/https://example.com/?pjclid=1&utm_source=keep",
  "https://web.archive.org/web/2025/https://example.com/?pjclid=1&utm_source=keep",
  { compiled_lists = ag_idx, use_builtin_rules = true }
)
test_url(
  "Adblock param-level exception (@@^mkt_unsubscribe=$removeparam=mkt_tok)",
  "https://mail.example/unsub?mkt_unsubscribe=1&mkt_tok=keep_me",
  "https://mail.example/unsub?mkt_unsubscribe=1&mkt_tok=keep_me",
  { compiled_lists = ag_idx, use_builtin_rules = true }
)

-- Plain-text custom list format
local sample_plain = [[
# My custom privacy list
my_global_tracker
promo_*
custom.example:secret_id,share_*
@@exempt.example
]]
local pl_idx, pl_added, _, pl_fmt = list_parser.parse_auto(sample_plain)
assert_eq("Plain format auto-detected", pl_fmt, "plain")
assert_eq("Plain parsed 5 rules", pl_added, 5)
local pl_opts = { compiled_lists = pl_idx, use_builtin_rules = false, strict_canonical = false }

test_url(
  "Plain custom list strips global, wildcard, and domain-scoped params",
  "https://custom.example/page?my_global_tracker=1&promo_abc=2&secret_id=3&share_tok=4&ok=5",
  "https://custom.example/page?ok=5",
  pl_opts
)
test_url(
  "Plain custom list @@exempt.example protects domain",
  "https://exempt.example/page?my_global_tracker=1&promo_abc=2",
  "https://exempt.example/page?my_global_tracker=1&promo_abc=2",
  pl_opts
)

-- ClearURLs JSON format
local mock_clearurls_tbl = {
  providers = {
    globalRules = {
      urlPattern = ".*",
      rules = { "(?:%3F)?utm(?:_[a-z_]*)?", "(?:%3F)?fbclid" },
    },
    youtube = {
      urlPattern = "^https?:\\/\\/(?:[a-z0-9-]+\\.)*?(youtube\\.com|youtu\\.be)",
      rules = { "si", "feature" },
    },
  },
}
local cu_idx, cu_added, _, cu_fmt = list_parser.parse_auto("{\"providers\":{}}", nil, {
  json_decode = function() return mock_clearurls_tbl end,
})
assert_eq("ClearURLs JSON format auto-detected", cu_fmt, "clearurls")
assert_eq("ClearURLs parsed 4 rules", cu_added, 4)
local cu_opts = { compiled_lists = cu_idx, use_builtin_rules = false, strict_canonical = false }

test_url(
  "ClearURLs globalRules & youtube alternation rules clean URLs",
  "https://youtu.be/abc?si=123&utm_source=x&fbclid=9&t=42",
  "https://youtu.be/abc?t=42",
  cu_opts
)

io.stdout:write(string.format("Tests completed: %d passed, %d failed\n", passed, failed))
if failed > 0 then
  os.exit(1)
end
