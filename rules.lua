-- Tracking Removal — Ruleset for C-Cord Plugin API v1
-- Covers universal tracking parameters, per-service rules across popular sites,
-- path cleaners, fragment cleaners, and redirect unwrappers.

local M = {}

local function set(list)
  local t = {}
  for i = 1, #list do
    t[list[i]] = true
  end
  return t
end

-- Domains that must never have query parameters modified (signed URLs, OAuth, CDNs).
M.immune_domains = set({
  "cdn.discordapp.com",
  "media.discordapp.net",
  "images-ext-1.discordapp.net",
  "images-ext-2.discordapp.net",
  "accounts.google.com",
  "oauth2.googleapis.com",
  "login.microsoftonline.com",
  "appleid.apple.com",
  "auth0.com",
})

-- Exact lowercase tracking parameters stripped globally across all non-immune sites.
M.global_exact = set({
  -- Google Ads / Analytics / Search click & shopping IDs
  "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
  "gad_source", "gad_campaignid", "gad_campaign",
  "srsltid", "_ga", "_gl", "_gac", "_gid",
  "gs_lcrp", "gs_lcp",
  "amp_js_v", "amp_gsa", "amp_r", "usqp",

  -- Meta (Facebook / Instagram)
  "fbclid", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source",
  "action_object_map", "action_type_map", "action_ref_map",
  "mibextid", "igshid", "igsh",

  -- Ad click IDs (Microsoft, X, TikTok, LinkedIn, Pinterest, Reddit, Snapchat, Quora, Nextdoor, Yandex)
  "msclkid", "twclid", "ttclid",
  "li_fat_id", "lipi", "licu",
  "epik", "rdt_cid", "sccid", "sc_cid", "qclid", "ndclid",
  "yclid", "ymclid", "ysclid", "_openstat",
  "guce_referrer", "guce_referrer_sig", "guccounter",

  -- Email, CRM, and Marketing Automation
  "mc_cid", "mc_eid", "mkt_tok",
  "_hsenc", "_hsmi", "hsctatracking", "__hsfp", "__hssc", "__hstc",
  "_kx", "_ke",
  "ck_subscriber_id", "ml_subscriber", "ml_subscriber_hash",
  "wickedid", "drip_email", "drip_subscriber_id",
  "s_cid", "s_kwcid", "ef_id", "icid", "cmpid", "ncid",
  "xtor", "xtref", "xtloc", "echobox",

  -- AT Internet / Piano Analytics
  "at_medium", "at_campaign", "at_campaign_type", "at_campaign_group",
  "at_custom1", "at_custom2", "at_custom3", "at_custom4",
  "at_creation", "at_variant", "at_format",
  "at_link_id", "at_link_type", "at_link_origin",
  "at_ptr_name", "at_bbc_team",

  -- Affiliate & Mobile Attribution
  "irclickid", "irgwc", "sscid", "zanpid", "awc",
  "cjevent", "cjdata", "rb_clickid", "sclid",
  "ref_src", "ref_url",
  "_branch_match_id", "_branch_referrer",
  "af_xp", "af_c_id", "af_adset", "af_ad", "af_siteid",
  "adj_t", "adj_campaign", "adj_adgroup", "adj_creative",

  -- BBC / Webtrekk / Amazon widget / Shopify recommendations / YouTube embed telemetry
  "ns_mchannel", "ns_source", "ns_campaign", "ns_linkname", "ns_fee",
  "wt_mc", "wt_mc_o", "wt_zmc", "wt_t", "wt_ga", "wt_gac",
  "pf_rd_r", "pf_rd_p", "pf_rd_m", "pf_rd_s", "pf_rd_t", "pf_rd_i",
  "pd_rd_r", "pd_rd_w", "pd_rd_wg", "pd_rd_i",
  "pr_prod_strat", "pr_rec_id", "pr_rec_pid", "pr_ref_pid", "pr_seq",
  "syclid", "shpxid",
  "source_ve_path", "embeds_referring_euri", "embeds_referring_origin",
})

-- Unambiguous tracking parameter prefixes stripped globally.
M.global_prefixes = {
  "utm_",
  "mtm_",
  "pk_",
  "piwik_",
  "matomo_",
  "hsa_",
  "_ga_",
  "oly_",
  "vero_",
  "hmb_",
}

-- Tracking parameters safe to strip when placed in key=value fragments (e.g. #utm_source=x).
M.fragment_exact = set({
  "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "twclid", "ttclid",
  "igshid", "igsh", "mc_cid", "mc_eid", "mkt_tok",
  "xtor", "xtref", "echobox", "smid",
  "at_medium", "at_campaign", "at_custom1", "at_custom2", "at_custom3", "at_custom4",
})

M.fragment_prefixes = {
  "utm_",
  "mtm_",
  "pk_",
  "piwik_",
  "matomo_",
  "hsa_",
}

-- Known two-label public suffix SLDs used for safe multi-TLD brand matching (e.g. google.co.uk).
M.known_slds = set({
  "co", "com", "org", "net", "ne", "or", "ac", "gov", "edu",
})

-- Path cleaner helpers
local function clean_amazon_path(path, opts)
  if not path or path == "" then
    return path, false
  end
  local new_path = path
  local changed = false

  if opts and opts.shorten_amazon then
    local asin_pat = "([A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])"
    local p = new_path .. "/"
    local asin = p:match("/[Dd][Pp]/" .. asin_pat .. "/")
      or p:match("/[Gg][Pp]/[Pp][Rr][Oo][Dd][Uu][Cc][Tt]/" .. asin_pat .. "/")
      or p:match("/[Gg][Pp]/[Aa][Ww]/[Dd]/" .. asin_pat .. "/")
    if asin then
      local canonical = "/dp/" .. asin
      if canonical ~= new_path then
        return canonical, true
      end
      return new_path, false
    end
  end

  -- Strip trailing or mid-path /ref=... tracking segments
  local stripped = new_path:gsub("/[Rr][Ee][Ff]=[^/]*", "")
  if stripped ~= new_path then
    if stripped == "" then
      stripped = "/"
    end
    new_path = stripped
    changed = true
  end

  return new_path, changed
end

local function clean_stackoverflow_path(path)
  if not path or path == "" then
    return path, false
  end
  -- Share button generates /q/<question_id>/<sharer_user_id> or /a/<answer_id>/<sharer_user_id>
  local kind, post_id = path:match("^/([qa])/(%d+)/(%d+)/?$")
  if kind and post_id then
    return "/" .. kind .. "/" .. post_id, true
  end
  return path, false
end

-- Reusable rule definitions for services shared across multiple domains
local rule_x = {
  params = set({
    "a", "s", "t", "ct", "rw", "src", "ref_src", "ref_url", "cxt", "cn",
    "ref", "via", "original_referer", "partner", "mx",
  }),
  strict_paths = {
    {
      patterns = {
        "^/[^/]+/status/%d+",
        "^/i/web/status/%d+",
        "^/i/status/%d+",
      },
      keep = set({ "lang" }),
    },
  },
}

local youtube_params = set({
  "si", "feature", "pp", "kw", "app", "ab_channel", "attr_tag",
  "cbrd", "ucbcb", "itct", "ved", "ei",
  "source_ve_path", "embeds_referring_euri", "embeds_referring_origin",
})

local rule_youtube = {
  params = youtube_params,
  strict_paths = {
    {
      patterns = { "^/watch/?$" },
      keep = set({
        "v", "t", "list", "index", "start", "end", "lc",
        "hl", "gl", "cc_load_policy", "cc_lang_pref", "has_verified", "bpctr",
      }),
    },
    {
      patterns = { "^/shorts/[^/]+", "^/live/[^/]+" },
      keep = set({ "t" }),
    },
    {
      patterns = { "^/playlist/?$" },
      keep = set({ "list" }),
    },
  },
}

local rule_youtu_be = {
  params = youtube_params,
  strict_paths = {
    {
      patterns = { "^/[^/]+/?$" },
      keep = set({ "t", "list", "index", "start", "end" }),
    },
  },
}

local rule_google = {
  params = set({
    "ved", "ei", "oq", "gs_lcrp", "gs_lcp", "gs_lp", "gs_l", "gs_ssp",
    "sclient", "sca_esv", "sca_upv", "source", "sourceid", "aqs", "rlz",
    "uact", "bih", "biw", "dpr", "sxsrf", "sa", "psi", "iflsig", "gws_rd",
    "usg", "esrc", "rct", "cd", "cad", "pcampaignid", "cshid", "prmd",
    "client", "channel", "ie", "oe", "fbs", "pq", "cp", "pf", "pccc",
    "sei", "vet", "ictx", "fir",
    "usp", "g_ep", "entry", "g_st", "coh", "skid", "referrer",
  }),
}

local rule_reddit = {
  params = set({
    "share_id", "rdt", "rdt_cid", "ref", "ref_source", "ref_campaign",
    "correlation_id", "chain_id", "experiment_d2x_2020ify_buttons",
    "sh", "st", "deep_link_value", "chainedposts", "impression_id",
  }),
  strict_paths = {
    {
      patterns = {
        "^/r/[^/]+/comments/[^/]+",
        "^/comments/[^/]+",
        "^/user/[^/]+/comments/[^/]+",
      },
      keep = set({ "context", "sort", "depth", "showmore" }),
    },
  },
}

local rule_facebook = {
  params = set({
    "mibextid", "ref", "refid", "refsrc", "ref_type", "ref_component",
    "ref_page", "tracking", "notif_id", "notif_t", "acontext",
    "comment_tracking", "fs", "eav", "paipv", "rdid", "share_url",
    "sfnsn", "s", "__tn__", "hc_ref", "hc_location", "fref", "pnref",
    "rc", "eid", "dti", "epa", "av", "m_entstream_source",
  }),
  prefixes = { "__cft__", "__xts__", "xts[" },
}

local rule_instagram = {
  params = set({
    "igsh", "igshid", "r", "ref", "ig_rid", "ig_mid",
    "ig_web_copy_link", "ig_web_button_share_sheet", "s",
  }),
  strict_paths = {
    {
      patterns = {
        "^/p/[^/]+",
        "^/reel/[^/]+",
        "^/reels/[^/]+",
        "^/tv/[^/]+",
      },
      keep = set({ "img_index" }),
    },
  },
}

local rule_threads = {
  params = set({ "xmt", "slof", "igsh", "igshid" }),
  strict_paths = {
    {
      patterns = { "^/@[^/]+/post/[^/]+" },
      keep = set({}),
    },
  },
}

local rule_tiktok = {
  params = set({
    "_t", "_r", "is_from_webapp", "sender_device", "sender_web_id", "web_id",
    "share_app_id", "share_author_id", "share_link_id", "share_item_id",
    "sharer_language", "social_share_type", "source", "timestamp",
    "u_code", "ug_btm", "ugbiz_name", "user_id", "sec_uid", "sec_user_id",
    "checksum", "tt_from", "enter_from", "enter_method", "is_copy_url",
    "refer", "referer_url", "referer_video_id", "rid", "preview_pb",
    "mid", "region",
  }),
  strict_paths = {
    {
      patterns = {
        "^/@[^/]+/video/%d+",
        "^/@[^/]+/photo/%d+",
      },
      keep = set({ "t", "lang" }),
    },
  },
}

local rule_amazon = {
  params = set({
    "ref", "ref_", "qid", "sr", "sprefix", "crid", "dib", "dib_tag",
    "keywords", "dchild", "tag", "linkcode", "linkid", "camp", "creative",
    "creativeasin", "ascsubtag", "asc_contentid", "asc_contenttype",
    "asc_campaign", "content-id", "hvadid", "hvpos", "hvnetw", "hvrand",
    "hvpone", "hvptwo", "hvqmt", "hvdev", "hvdvcmdl", "hvlocint", "hvlocphy",
    "hvtargid", "hydadcr", "mcid", "sbo", "ufe", "ie", "encoding", "_encoding",
    "rnid", "spla", "sp_csd", "social_share", "starsleft", "skiptwisterog",
    "aref", "aaxitk", "hsa_cr_id", "lp_asins", "lp_mat_key", "lp_query",
    "lp_slot", "store_ref", "qualifier",
    "pf_rd_r", "pf_rd_p", "pf_rd_m", "pf_rd_s", "pf_rd_t", "pf_rd_i",
    "pd_rd_r", "pd_rd_w", "pd_rd_wg", "pd_rd_i",
  }),
  path_cleaner = clean_amazon_path,
  strict_paths = {
    {
      patterns = {
        "/dp/[a-z0-9]+",
        "/gp/product/[a-z0-9]+",
        "/gp/aw/d/[a-z0-9]+",
      },
      keep = set({ "th", "psc", "smid", "m", "aod", "language", "currency" }),
    },
  },
}

local rule_spotify = {
  params = set({
    "si", "context", "sp_cid", "nd", "dlsi", "pi", "go", "dl_branch",
  }),
  strict_paths = {
    {
      -- Preserve collaborator invite token `pt` on Spotify playlists
      patterns = {
        "^/playlist/[^/]+",
        "^/intl%-[a-z%-]+/playlist/[^/]+",
      },
      keep = set({ "t", "pt" }),
    },
    {
      patterns = {
        "^/track/[^/]+",
        "^/album/[^/]+",
        "^/artist/[^/]+",
        "^/episode/[^/]+",
        "^/show/[^/]+",
        "^/intl%-[a-z%-]+/track/[^/]+",
        "^/intl%-[a-z%-]+/album/[^/]+",
        "^/intl%-[a-z%-]+/artist/[^/]+",
        "^/intl%-[a-z%-]+/episode/[^/]+",
        "^/intl%-[a-z%-]+/show/[^/]+",
      },
      keep = set({ "t" }),
    },
  },
}

local rule_ebay = {
  params = set({
    "hash", "_trkparms", "_trksid", "amdata", "epid",
    "mkcid", "mkrid", "campid", "toolid", "customid", "mkevt", "mkpid",
    "emsid", "mktype", "norover", "siteid", "ul_noapp", "ff3", "pub",
    "rmvsb", "chn", "itmmeta", "itmprp", "skc", "shqty", "isgtr",
    "ul_ref", "rt",
  }),
  strict_paths = {
    {
      patterns = { "^/itm/" },
      keep = set({ "var", "nordt", "orig_cvip" }),
    },
  },
}

local rule_aliexpress = {
  params = set({
    "spm", "algo_pvid", "algo_exp_id", "pdp_npi", "pdp_ext_f",
    "curpageloguid", "utparam-url", "sourcetype", "srcsns", "spreadtype",
    "biztype", "social_params", "aff_fcid", "aff_fsk", "aff_platform", "sk",
    "aff_trace_key", "terminal_id", "afsmartredirect", "gatewayadapt",
    "gps-id", "scm", "scm_id", "scm-url", "pvid", "tt", "businesstype",
    "shareid", "src", "albbt", "isdl", "aff_short_key", "ws_ab_test",
    "btsid", "search_web_type",
  }),
}

local rule_stackoverflow = {
  params = set({ "rq", "cb" }),
  path_cleaner = clean_stackoverflow_path,
}

local rule_wsj = {
  params = set({
    "mod", "reflink", "cx_testid", "cx_testvariant", "cx_artpos", "ns",
  }),
}

local rule_mercadolibre = {
  params = set({
    "pdp_filters", "position", "search_layout", "type", "tracking_id",
    "is_advertising", "ad_domain", "ad_position", "ad_click_id", "sid",
    "polycard_client",
  }),
  prefixes = { "matt_", "cq_" },
}

-- Domain suffix rules: matches exact domain and any subdomain (*.domain).
M.domains = {
  -- X / Twitter & popular embed fixers
  ["x.com"] = rule_x,
  ["twitter.com"] = rule_x,
  ["fxtwitter.com"] = rule_x,
  ["vxtwitter.com"] = rule_x,
  ["fixupx.com"] = rule_x,
  ["fixvx.com"] = rule_x,
  ["xcancel.com"] = rule_x,
  ["twittpr.com"] = rule_x,

  -- YouTube
  ["youtube.com"] = rule_youtube,
  ["youtu.be"] = rule_youtu_be,
  ["youtube-nocookie.com"] = rule_youtube,

  -- Reddit
  ["reddit.com"] = rule_reddit,
  ["redd.it"] = rule_reddit,

  -- Meta (Facebook, Instagram, Threads)
  ["facebook.com"] = rule_facebook,
  ["fb.com"] = rule_facebook,
  ["fb.watch"] = rule_facebook,
  ["instagram.com"] = rule_instagram,
  ["threads.net"] = rule_threads,
  ["threads.com"] = rule_threads,

  -- TikTok
  ["tiktok.com"] = rule_tiktok,

  -- Music & Media
  ["spotify.com"] = rule_spotify,
  ["soundcloud.com"] = { params = set({ "si", "ref" }) },
  ["twitch.tv"] = { params = set({ "tt_content", "tt_medium", "tt_email_id", "referrer" }) },
  ["netflix.com"] = { params = set({ "tctx", "trackid", "trkid", "s" }) },
  ["bilibili.com"] = {
    params = set({
      "spm_id_from", "vd_source", "from_spmid", "share_source", "share_medium",
      "share_plat", "share_session_id", "share_tag", "share_times", "bbid",
      "ts", "unique_k", "buvid", "is_story_h5", "mid", "plat_id", "up_id",
      "from", "seid", "msource", "refer_from",
    }),
  },
  ["bandcamp.com"] = {
    params = set({
      "from", "search_item_id", "search_item_type", "search_match_part",
      "search_page_id", "search_page_no", "search_rank", "search_sig",
    }),
  },
  ["imdb.com"] = { params = set({ "ref_" }) },
  ["apple.com"] = { params = set({ "itscg", "itsct", "at", "ct", "pt" }) },

  -- Gaming
  ["steampowered.com"] = {
    params = set({ "snr", "curator_clanid" }),
    strict_paths = {
      {
        patterns = { "^/app/%d+", "^/sub/%d+", "^/bundle/%d+" },
        keep = set({ "l", "cc" }),
      },
    },
  },
  ["steamcommunity.com"] = { params = set({ "snr", "curator_clanid" }) },

  -- Shopping
  ["temu.com"] = {
    params = set({ "top_gallery_url", "spec_gallery_id", "oak_rsrc", "is_back", "no_cache_id" }),
    prefixes = { "_x_", "refer_page_" },
  },
  ["etsy.com"] = {
    params = set({
      "click_key", "click_sum", "ref", "ga_order", "ga_search_type",
      "ga_view_type", "ga_search_query", "organic_search_click",
      "pro", "frs", "sts", "dd_referrer", "et_rid",
    }),
  },
  ["walmart.com"] = {
    params = set({
      "athena", "adid", "wmlspartner", "wl0", "wl1", "wl2", "wl3", "wl4",
      "wl5", "wl6", "wl7", "wl8", "wl9", "wl10", "wl11", "wl12", "wl13",
      "veh", "c", "clickid", "sourceid", "affiliates_ad_id", "campaign_id",
      "sharedid", "sid", "spqs", "adsredirect", "from",
    }),
    prefixes = { "ath" },
  },
  ["target.com"] = { params = set({ "lnk", "afid", "ref", "clkid", "cpng", "lnm" }) },
  ["bestbuy.com"] = { params = set({ "ref", "loc", "acmpid", "mpid", "intl" }) },
  ["newegg.com"] = {
    params = set({
      "cm_sp", "cm_mmc", "nm_mc", "afc-ran-com",
      "ranmid", "raneaid", "ransiteid", "source",
    }),
  },

  -- Professional, Publishing & Social
  ["linkedin.com"] = {
    params = set({
      "trk", "trkinfo", "trackingid", "refid", "midtoken", "midsig",
      "ebp", "recommendedflavor", "originalsubdomain", "original_referer",
      "rcm", "otptoken", "upsellorderorigin", "contexturn", "origin",
    }),
  },
  ["substack.com"] = {
    params = set({ "r", "triedredirect", "isfreemail", "publication_id", "post_id", "s" }),
  },
  ["medium.com"] = { params = set({ "source", "gi" }) },
  ["tumblr.com"] = { params = set({ "source" }) },
  ["vk.com"] = { params = set({ "from", "ref" }) },

  -- Search Engines
  ["bing.com"] = {
    params = set({
      "cvid", "form", "sp", "pq", "sc", "sk", "qs", "ghc", "lq", "pc",
      "ocid", "refig", "ei", "ved",
    }),
  },
  ["msn.com"] = { params = set({ "cvid", "ocid", "ei", "pc" }) },
  ["duckduckgo.com"] = { params = set({ "t" }) },

  -- Developer & Q&A
  ["github.com"] = { params = set({ "ref_cta", "ref_loc", "ref_page", "email_source" }) },
  ["gitlab.com"] = { params = set({ "ref_cta", "ref_loc", "ref_page", "email_source" }) },
  ["stackoverflow.com"] = rule_stackoverflow,
  ["stackexchange.com"] = rule_stackoverflow,
  ["superuser.com"] = rule_stackoverflow,
  ["serverfault.com"] = rule_stackoverflow,
  ["askubuntu.com"] = rule_stackoverflow,
  ["mathoverflow.net"] = rule_stackoverflow,

  -- News
  ["nytimes.com"] = {
    params = set({
      "smid", "smtyp", "emc", "campaign_id", "instance_id", "segment_id",
      "user_id", "regi_id", "te", "nl", "action", "module", "pgtype", "region",
    }),
  },
  ["washingtonpost.com"] = { params = set({ "wpisrc", "wpmk", "itid" }) },
  ["wsj.com"] = rule_wsj,
  ["barrons.com"] = rule_wsj,
  ["marketwatch.com"] = rule_wsj,
  ["bloomberg.com"] = { params = set({ "srnd", "leadsource", "sref", "embedded-checkout" }) },
  ["forbes.com"] = { params = set({ "sh" }) },
  ["theguardian.com"] = { params = set({ "cmp", "ref" }) },
  ["reuters.com"] = { params = set({ "taid" }) },
  ["cnn.com"] = { params = set({ "iid" }) },

  -- Travel, Learning, Crowdfunding, Misc
  ["booking.com"] = {
    params = set({
      "aid", "label", "sid", "srpvid", "ucfs", "arphpl", "hpos", "hapos",
      "sr_order", "from_sustainable_property_sr", "matching_block_id",
      "ref_is_wl", "all_sr_blocks",
    }),
  },
  ["airbnb.com"] = {
    params = set({
      "source_impression_id", "federated_search_id", "search_mode",
      "previous_page_section_name", "c", "af", "s", "unique_share_id",
    }),
  },
  ["kickstarter.com"] = { params = set({ "ref" }) },
  ["indiegogo.com"] = { params = set({ "ref" }) },
  ["producthunt.com"] = { params = set({ "ref", "bc" }) },
  ["gofundme.com"] = { params = set({ "attribution_id", "ts", "rcid" }) },
  ["gumroad.com"] = { params = set({ "recommended_by" }) },
  ["goodreads.com"] = { params = set({ "from_search", "from_srp", "qid", "rank", "ac", "ref" }) },
  ["udemy.com"] = { params = set({ "src", "kw", "ranmid", "raneaid", "ransiteid", "lsnpubid" }) },
  ["zillow.com"] = { params = set({ "rtoken" }) },
}

-- Multi-TLD brand rules (e.g. google.co.uk, amazon.de, ebay.com.au).
M.brands = {
  ["google"] = rule_google,
  ["amazon"] = rule_amazon,
  ["ebay"] = rule_ebay,
  ["aliexpress"] = rule_aliexpress,
  ["pinterest"] = { params = set({ "invite_code", "sender", "sfo", "mt", "nic_v3" }) },
  ["yahoo"] = { params = set({ "fr", "fr2", "soc_src", "soc_trk", "ylt", "ylu", "ylc", "_guc_consent_skip" }) },
  ["bbc"] = { params = set({ "ocid", "ns_mchannel", "ns_source", "ns_campaign", "ns_linkname", "ns_fee", "xtor" }) },
  ["yandex"] = { params = set({ "clid", "from" }) },
  ["mercadolibre"] = rule_mercadolibre,
  ["mercadolivre"] = rule_mercadolibre,
  ["shopee"] = { params = set({ "sp_atk", "xptdk", "uls_trackid" }) },
}

-- Redirect unwrapper definitions.
-- Each entry specifies how to recognize a tracking redirector and extract its true destination URL.
M.redirects = {
  -- Google /url and /aclk redirects (all Google ccTLDs)
  {
    brand = "google",
    path_prefixes = { "/url", "/aclk" },
    params = { "q", "url", "adurl" },
  },
  -- Google AdServices
  {
    domains = { "googleadservices.com" },
    path_prefixes = { "/pagead/aclk" },
    params = { "adurl" },
  },
  -- Google AMP wrapper: google.<tld>/amp/s/<host>/<path> or /amp/<host>/<path>
  {
    brand = "google",
    path_prefixes = { "/amp/" },
    extract = function(parsed)
      local rest = parsed.path:match("^/amp/s/(.+)$")
      local target_scheme = "https://"
      if not rest then
        rest = parsed.path:match("^/amp/(.+)$")
        target_scheme = "http://"
      end
      if not rest or rest == "" then
        return nil
      end
      local url = rest
      if not url:match("^[Hh][Tt][Tt][Pp][Ss]?://") then
        url = target_scheme .. url
      end
      if parsed.has_query and parsed.query_raw ~= "" then
        url = url .. (url:find("?", 1, true) and "&" or "?") .. parsed.query_raw
      end
      if parsed.has_fragment and parsed.fragment ~= nil then
        url = url .. "#" .. parsed.fragment
      end
      return url
    end,
  },
  -- AMP Project CDN: *.cdn.ampproject.org/c/s/<target> or /v/s/<target>
  {
    domains = { "cdn.ampproject.org" },
    path_prefixes = { "/c/", "/v/" },
    extract = function(parsed)
      local rest = parsed.path:match("^/[cv]/s/(.+)$")
      local target_scheme = "https://"
      if not rest then
        rest = parsed.path:match("^/[cv]/(.+)$")
        target_scheme = "http://"
      end
      if not rest or rest == "" then
        return nil
      end
      local url = target_scheme .. rest
      if parsed.has_query and parsed.query_raw ~= "" then
        url = url .. "?" .. parsed.query_raw
      end
      if parsed.has_fragment and parsed.fragment ~= nil then
        url = url .. "#" .. parsed.fragment
      end
      return url
    end,
  },
  -- YouTube outbound description/card redirect
  {
    domains = { "youtube.com" },
    path_prefixes = { "/redirect" },
    params = { "q" },
  },
  -- Facebook / Messenger outbound redirect
  {
    exact_hosts = set({ "l.facebook.com", "lm.facebook.com", "l.messenger.com" }),
    path_prefixes = { "/l.php" },
    params = { "u" },
  },
  -- Instagram outbound redirect
  {
    exact_hosts = set({ "l.instagram.com" }),
    params = { "u" },
  },
  -- Reddit outbound redirect
  {
    exact_hosts = set({ "out.reddit.com" }),
    params = { "url" },
  },
  -- Steam link filter
  {
    domains = { "steamcommunity.com" },
    path_prefixes = { "/linkfilter" },
    params = { "u", "url" },
  },
  -- Outlook / Microsoft Defender SafeLinks
  {
    domains = { "safelinks.protection.outlook.com" },
    params = { "url" },
  },
  -- DuckDuckGo outbound redirect
  {
    domains = { "duckduckgo.com" },
    path_prefixes = { "/l/" },
    params = { "uddg" },
  },
  -- Bing click redirect (u=a1<base64url>)
  {
    domains = { "bing.com" },
    path_prefixes = { "/ck/a" },
    extract = function(parsed, helpers)
      local u = helpers.get_param(parsed, "u")
      if not u then
        return nil
      end
      u = helpers.percent_decode(u)
      if u:sub(1, 2) == "a1" then
        local decoded = helpers.base64url_decode(u:sub(3))
        if decoded and decoded:match("^[Hh][Tt][Tt][Pp][Ss]?://") then
          return decoded
        end
      elseif u:match("^[Hh][Tt][Tt][Pp][Ss]?://") then
        return u
      end
      return nil
    end,
  },
  -- Yahoo search redirect (/RU=<encoded>/RK=...)
  {
    brand = "yahoo",
    extract = function(parsed, helpers)
      local ru = parsed.path:match("/RU=([^/]+)")
      if not ru then
        return nil
      end
      return helpers.percent_decode_url(ru)
    end,
  },
  -- SoundCloud outbound redirect
  {
    exact_hosts = set({ "gate.sc", "exit.sc" }),
    params = { "url" },
  },
  -- Tumblr outbound redirect
  {
    exact_hosts = set({ "t.umblr.com" }),
    path_prefixes = { "/redirect" },
    params = { "z" },
  },
  -- VK outbound redirect
  {
    domains = { "vk.com" },
    path_prefixes = { "/away.php" },
    params = { "to" },
  },
  -- Disqus redirect (appends :<hash> suffix to target URL)
  {
    exact_hosts = set({ "disq.us" }),
    path_prefixes = { "/url" },
    extract = function(parsed, helpers)
      local raw_u = helpers.get_param(parsed, "url")
      if not raw_u then
        return nil
      end
      local target = helpers.percent_decode_url(raw_u)
      if not target then
        return nil
      end
      -- Strip Disqus trailing signature hash (:16+ non-numeric base64url chars)
      local stripped, hash = target:match("^(.-):([A-Za-z0-9_%-]+)$")
      if stripped and hash and #hash >= 16 and not hash:match("^%d+$") and stripped:match("^[Hh][Tt][Tt][Pp][Ss]?://[^/]+") then
        target = stripped
      end
      return target
    end,
  },
  -- Pocket redirect
  {
    domains = { "getpocket.com" },
    path_prefixes = { "/redirect" },
    params = { "url" },
  },
  -- Slack redirect
  {
    domains = { "slack-redir.net" },
    path_prefixes = { "/link" },
    params = { "url" },
  },
  -- Zhihu / QQ / GMX / Web.de / href.li redirects
  {
    exact_hosts = set({ "link.zhihu.com" }),
    params = { "target" },
  },
  {
    exact_hosts = set({ "c.pc.qq.com" }),
    params = { "pfurl" },
  },
  {
    domains = { "deref-gmx.net", "deref-web.de" },
    params = { "redirecturl" },
  },
  {
    exact_hosts = set({ "href.li" }),
    extract = function(parsed, helpers)
      if parsed.has_query and parsed.query_raw ~= "" then
        local target = helpers.percent_decode_url(parsed.query_raw)
        if target and target:match("^[Hh][Tt][Tt][Pp][Ss]?://") then
          return target
        end
      end
      return nil
    end,
  },
  -- Common affiliate redirect networks
  {
    exact_hosts = set({ "go.skimresources.com", "go.redirectingat.com" }),
    params = { "url" },
  },
  {
    domains = { "click.linksynergy.com" },
    params = { "murl" },
  },
  {
    domains = { "awin1.com" },
    path_prefixes = { "/cread.php" },
    params = { "ued" },
  },
  {
    domains = { "anrdoezrs.net", "kqzyfj.com", "jdoqocy.com", "tkqlhce.com", "dpbolvw.net" },
    params = { "url" },
  },
  {
    exact_hosts = set({ "clicks.trx-hub.com" }),
    params = { "q" },
  },
}

return M
