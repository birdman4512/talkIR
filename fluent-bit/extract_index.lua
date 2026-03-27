-- extract_index.lua
-- Called by the Fluent Bit Lua filter for every log record.
-- Handles Velociraptor collections and flat JSON files alike.

-- ─── Metadata files to silently drop ─────────────────────────────────────────
-- Velociraptor writes these alongside artefact data; they are not log events.
local SKIP_BASENAMES = {
    ["log.json"]                = true,   -- collection progress log (NDJSON, not artefact data)
    ["collection_context.json"] = true,   -- excluded via Exclude_Path but belt-and-suspenders
    ["requests.json"]           = true,
}

-- ─── Timestamp field priority order ──────────────────────────────────────────
-- Each artefact type uses a different field; we normalise to @timestamp.
local TIMESTAMP_FIELDS = {
    "EventTime",                    -- Windows Event Logs, RDPAuth, PowerShell
    "visit_time",                   -- Browser history
    "last_visit_time",              -- Browser history fallback
    "Created0x10",                  -- NTFS MFT (creation time from $STANDARD_INFORMATION)
    "LastModified0x10",             -- NTFS MFT (last modified)
    "CreationTime",                 -- Prefetch
    "LastWrite",                    -- Registry artefacts
}

-- ─── Suspicious PowerShell indicators ────────────────────────────────────────
local PS_INDICATORS = {
    "invoke%-expression", "iex%s", "iex%(", "downloadstring", "downloadfile",
    "frombase64string", "%-encodedcommand", "%-enc%s", "%-enc$",
    "bypass", "unrestricted", "hidden", "noprofile",
    "mimikatz", "invoke%-mimikatz", "sekurlsa", "lsadump",
    "powersploit", "powerup", "powerview", "invoke%-shellcode",
    "virtualalloc", "writeprocessmemory", "createthread", "loadlibrary",
    "shellcode", "meterpreter", "reflective",
}

-- ─── MFT: file extensions worth keeping ──────────────────────────────────────
local MFT_KEEP_EXT = {
    exe=true, dll=true, sys=true, drv=true,
    ps1=true, psm1=true, psd1=true,
    bat=true, cmd=true, com=true, pif=true,
    vbs=true, vbe=true, js=true,  jse=true,
    hta=true, scr=true, cpl=true, msi=true,
    msc=true, lnk=true,
}

-- ─── Helpers ─────────────────────────────────────────────────────────────────

local function basename(path)
    return path:match("([^/\\]+)$") or path
end

-- Extract hostname from a Velociraptor collection folder name.
-- "Collection-DC01_MARIOPLUMBING_LOCAL-2024-08-04T..." → "dc01"
-- Falls back to the folder name if not a Velociraptor path.
local function extract_host(path)
    -- Try Velociraptor pattern: Collection-HOSTNAME_DOMAIN-timestamp
    local host = path:match("[/\\]Collection%-([^_/\\]+)")
    if host then return host:lower() end
    -- Try folder immediately above the file as a generic hostname
    local folder = path:match("[/\\]([^/\\]+)[/\\][^/\\]+$")
    if folder and folder ~= "results" then return folder:lower() end
    return ""
end

-- Derive a clean index-safe name from a filename stem.
-- "Windows.EventLogs.RDPAuth" → "windows.eventlogs.rdpauth"
local function clean_name(stem)
    return stem:lower():gsub("[^a-z0-9._%-]", "_"):gsub("__+", "_")
end

-- Flatten a nested table one level deep into the parent record.
-- {Hash = {MD5="abc", SHA256="def"}} → {Hash_MD5="abc", Hash_SHA256="def"}
local function flatten_into(record, prefix, nested)
    if type(nested) ~= "table" then return end
    for k, v in pairs(nested) do
        if type(v) ~= "table" and type(v) ~= "userdata" then
            record[prefix .. "_" .. k] = v
        end
    end
end

-- Convert Autoruns time format "YYYYMMDD-HHMMSS" → "YYYY-MM-DDTHH:MM:SSZ"
local function autoruns_time(t)
    if type(t) ~= "string" then return nil end
    local y,mo,d,h,mi,s = t:match("^(%d%d%d%d)(%d%d)(%d%d)%-(%d%d)(%d%d)(%d%d)$")
    if y then return y.."-"..mo.."-"..d.."T"..h..":"..mi..":"..s.."Z" end
    return nil
end

-- ─── Main filter function ─────────────────────────────────────────────────────

function set_index(tag, timestamp, record)
    local path  = record["filename"] or ""
    local fname = basename(path)

    -- Drop Velociraptor metadata files
    if SKIP_BASENAMES[fname] then
        return -1, 0, 0
    end

    -- Strip extension to get artefact stem
    local stem = fname:match("^(.-)%.json$") or fname

    -- Silently drop Fluent Bit state files or empty stems
    if stem == "" or stem == fname then
        return -1, 0, 0
    end

    -- ── Index name and metadata fields ────────────────────────────────────────
    local artifact = clean_name(stem)
    local host     = extract_host(path)

    record["velociraptor_artifact"] = artifact

    if host ~= "" then
        record["host"]      = host
        record["log_index"] = host .. "-" .. artifact
    else
        record["log_index"] = artifact
    end

    -- ── Timestamp normalisation ───────────────────────────────────────────────
    -- Try standard ISO fields first
    local ts_set = false
    for _, field in ipairs(TIMESTAMP_FIELDS) do
        local v = record[field]
        if v and v ~= "" and v ~= "null" then
            record["@timestamp"] = v
            ts_set = true
            break
        end
    end
    -- Autoruns uses a non-ISO format; convert it
    if not ts_set and record["Time"] then
        local converted = autoruns_time(record["Time"])
        if converted then
            record["@timestamp"] = converted
        end
    end

    -- ── Flatten nested objects ────────────────────────────────────────────────
    -- Netstat enriched: Hash.MD5 / Hash.SHA256 / Authenticode.Trusted
    if type(record["Hash"]) == "table" then
        flatten_into(record, "Hash", record["Hash"])
        record["Hash"] = nil
    end
    if type(record["Authenticode"]) == "table" then
        flatten_into(record, "Authenticode", record["Authenticode"])
        record["Authenticode"] = nil
    end
    -- _ExtraInfo is internal Velociraptor metadata — drop it
    record["_ExtraInfo"] = nil

    -- ── PowerShell suspicious pattern detection ───────────────────────────────
    local script_text = record["ScriptBlockText"] or record["CommandLine"] or ""
    if script_text ~= "" then
        local lower = script_text:lower()
        local found = {}
        for _, pat in ipairs(PS_INDICATORS) do
            if lower:find(pat) then
                found[#found + 1] = pat:gsub("%%", "")
            end
        end
        if #found > 0 then
            record["ps_suspicious"] = true
            record["ps_indicators"] = table.concat(found, ",")
        else
            record["ps_suspicious"] = false
        end
    end

    -- ── MFT noise reduction ───────────────────────────────────────────────────
    -- MFT exports are 250k+ rows per host; keep only forensically interesting files.
    if artifact:find("ntfs%.mft") or artifact:find("ntfs_mft") then
        local ospath  = (record["OSPath"] or ""):lower()
        local has_ads = record["HasADS"] == true
        local ext     = ospath:match("%.(%w+)$")
        local is_exec = ext and MFT_KEEP_EXT[ext] or false

        -- Also keep anything in temp, appdata, downloads, or public paths
        local interesting_path = ospath:find("\\temp\\") or
                                  ospath:find("\\tmp\\")  or
                                  ospath:find("\\appdata\\") or
                                  ospath:find("\\downloads\\") or
                                  ospath:find("\\public\\") or
                                  ospath:find("\\programdata\\")

        if not has_ads and not is_exec and not interesting_path then
            return -1, 0, 0
        end
    end

    return 1, timestamp, record
end
