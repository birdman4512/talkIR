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
    "TimeCreated",                  -- Windows.EventLogs.Evtx (Velociraptor hoists to top level)
    "Timestamp",                    -- Netstat / NetstatEnriched
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

-- Safe string: return s if it's a non-empty string, else nil
local function str(s)
    if type(s) == "string" and s ~= "" and s ~= "null" and s ~= "-" then
        return s
    end
    return nil
end

-- ─── ECS normalisation ───────────────────────────────────────────────────────
-- Adds standard ECS fields alongside the original fields so the LLM can query
-- using well-known names (source.ip, user.name, process.name, etc.) regardless
-- of the underlying Velociraptor field naming conventions.
-- Original fields are preserved for backward compatibility.

local function ecs_enrich(artifact, record)

    -- ── Windows.Network.Netstat ───────────────────────────────────────────────
    -- Velociraptor emits flat dotted keys: "Laddr.IP", "Laddr.Port", etc.
    if artifact:find("network%.netstat") and not artifact:find("enriched") then
        local src_ip   = str(record["Laddr.IP"])
        local src_port = record["Laddr.Port"]
        local dst_ip   = str(record["Raddr.IP"])
        local dst_port = record["Raddr.Port"]
        if src_ip then
            record["source"] = { ip = src_ip, port = src_port }
        end
        if dst_ip and dst_ip ~= "0.0.0.0" then
            record["destination"] = { ip = dst_ip, port = dst_port }
        end
        if str(record["Name"]) then
            record["process"] = { name = record["Name"], pid = record["Pid"] }
        end
        if str(record["Type"]) then
            record["network"] = {
                transport = record["Type"]:lower(),
                direction = "egress",
            }
        end
    end

    -- ── Windows.Network.NetstatEnriched ──────────────────────────────────────
    -- Velociraptor emits SrcIP/SrcPort/DestIP/DestPort (closer to ECS already)
    if artifact:find("netstatenriched") then
        local src_ip = str(record["SrcIP"])
        local dst_ip = str(record["DestIP"])
        if src_ip then
            record["source"] = { ip = src_ip, port = record["SrcPort"] }
        end
        if dst_ip and dst_ip ~= "0.0.0.0" then
            record["destination"] = { ip = dst_ip, port = record["DestPort"] }
        end
        local proc_name = str(record["Name"])
        if proc_name then
            local proc = {
                name        = proc_name,
                pid         = record["Pid"],
                executable  = str(record["Path"]),
                command_line= str(record["CommandLine"]),
            }
            if record["Ppid"] then
                proc["parent"] = { pid = record["Ppid"] }
            end
            record["process"] = proc
        end
        local username = str(record["Username"])
        if username then
            -- Strip domain prefix for the ECS user.name field
            local bare = username:match("\\(.+)$") or username
            record["user"] = { name = bare, full = username }
        end
        if str(record["Type"]) then
            record["network"] = { transport = record["Type"]:lower() }
        end
        -- Code signature from flattened Authenticode
        local trusted = record["Authenticode_Trusted"]
        if trusted then
            record["code_signature"] = {
                trusted  = (trusted == "trusted"),
                subject_name = str(record["Authenticode_SubjectName"]),
            }
        end
    end

    -- ── Windows.EventLogs.RDPAuth ─────────────────────────────────────────────
    if artifact:find("rdpauth") then
        local computer = str(record["Computer"])
        if computer then
            record["host"] = { name = computer:lower() }
        end
        local username = str(record["UserName"])
        local domain   = str(record["DomainName"])
        if username then
            record["user"] = { name = username, domain = domain }
        end
        local src_ip = str(record["SourceIP"])
        if src_ip and src_ip ~= "LOCAL" then
            record["source"] = { ip = src_ip }
        end
        record["event"] = {
            code     = record["EventID"] and tostring(record["EventID"]) or nil,
            category = "authentication",
        }
        record["network"] = { protocol = "rdp" }
    end

    -- ── Windows.EventLogs.Evtx ───────────────────────────────────────────────
    -- Velociraptor hoists EventID, TimeCreated, Channel, EventRecordID to the
    -- top level.  Computer and UserID live inside the nested System table.
    if artifact:find("eventlogs%.evtx") then
        local sys = record["System"]
        if type(sys) == "table" then
            local computer = str(sys["Computer"])
            if computer then
                record["host"] = { name = computer:lower() }
                record["host_name"] = computer:lower()
            end
            local sec = sys["Security"]
            if type(sec) == "table" and str(sec["UserID"]) then
                record["user"] = { id = sec["UserID"] }
            end
            local exec = sys["Execution"]
            if type(exec) == "table" then
                record["process"] = { pid = exec["ProcessID"], thread = { id = exec["ThreadID"] } }
            end
        end
        local eid = record["EventID"]
        if eid then
            record["event"] = { code = tostring(eid) }
        end

        -- Extract EventData for common Security EventIDs so the LLM can query
        -- user.name, source.ip, process.name etc. without knowing raw field paths.
        local ed = record["EventData"]
        if type(ed) == "table" and eid then

            -- ── Logon events: 4624 success, 4625 failure, 4648 explicit cred ──
            if eid == 4624 or eid == 4625 or eid == 4648 then
                local tuser  = str(ed["TargetUserName"])  or str(ed["SubjectUserName"])
                local tdomain = str(ed["TargetDomainName"]) or str(ed["SubjectDomainName"])
                if tuser and tuser ~= "-" and not tuser:match("%$$") then
                    record["user"] = {
                        name   = tuser,
                        domain = tdomain,
                        id     = str(ed["TargetUserSid"]),
                    }
                end
                local raw_ip = str(ed["IpAddress"])
                if raw_ip and raw_ip ~= "-" then
                    raw_ip = raw_ip:gsub("^::ffff:", "")  -- strip IPv6-mapped IPv4 prefix
                    if raw_ip ~= "::1" and raw_ip ~= "127.0.0.1" and raw_ip ~= "-" then
                        record["source"] = {
                            ip   = raw_ip,
                            port = tonumber(tostring(ed["IpPort"] or "")),
                        }
                    end
                end
                local ws = str(ed["WorkstationName"])
                if ws and ws ~= "-" then
                    record["source"] = record["source"] or {}
                    record["source"]["domain"] = ws
                end
                local logon_type = ed["LogonType"]
                if logon_type then
                    record["winlog"] = { logon = { type = tostring(logon_type) } }
                end
                if record["event"] then
                    record["event"]["category"] = "authentication"
                    record["event"]["outcome"]  = (eid == 4624) and "success" or "failure"
                    record["event"]["type"]     = (eid == 4624) and "start"   or "denied"
                end

            -- ── Process creation: 4688 ─────────────────────────────────────────
            elseif eid == 4688 then
                local newproc = str(ed["NewProcessName"])
                if newproc then
                    local procname = newproc:match("([^\\]+)$") or newproc
                    local parent   = str(ed["ParentProcessName"])
                    record["process"] = {
                        name         = procname,
                        executable   = newproc,
                        command_line = str(ed["CommandLine"]),
                        pid          = tonumber(tostring(ed["NewProcessId"] or "")),
                        parent       = {
                            name = parent and (parent:match("([^\\]+)$") or parent),
                            pid  = tonumber(tostring(ed["ProcessId"] or "")),
                        },
                    }
                end
                local suser = str(ed["SubjectUserName"])
                if suser and suser ~= "-" then
                    record["user"] = {
                        name   = suser,
                        domain = str(ed["SubjectDomainName"]),
                        id     = str(ed["SubjectUserSid"]),
                    }
                end
                if record["event"] then
                    record["event"]["category"] = "process"
                    record["event"]["type"]     = "start"
                end

            -- ── Account management: 4720 create, 4726 delete, 4738 change, 4740 lockout ──
            elseif eid == 4720 or eid == 4726 or eid == 4738 or eid == 4740 then
                local tuser = str(ed["TargetUserName"])
                local suser = str(ed["SubjectUserName"])
                local uobj  = {}
                if tuser then uobj["target"] = { name = tuser } end
                if suser and suser ~= "-" then
                    uobj["name"]   = suser
                    uobj["domain"] = str(ed["SubjectDomainName"])
                end
                if next(uobj) then record["user"] = uobj end
                if record["event"] then
                    record["event"]["category"] = "iam"
                    record["event"]["type"]     = eid == 4720 and "creation"
                                                or eid == 4726 and "deletion"
                                                or "change"
                end

            -- ── Object / file access: 4663, 4656 ──────────────────────────────
            elseif eid == 4663 or eid == 4656 then
                local objname = str(ed["ObjectName"])
                if objname then
                    record["file"] = {
                        path = objname,
                        name = objname:match("([^\\]+)$") or objname,
                    }
                end
                local suser = str(ed["SubjectUserName"])
                if suser and suser ~= "-" then
                    record["user"] = {
                        name   = suser,
                        domain = str(ed["SubjectDomainName"]),
                    }
                end
                if record["event"] then record["event"]["category"] = "file" end

            -- ── Service installation: 4697 ────────────────────────────────────
            elseif eid == 4697 then
                local svcname = str(ed["ServiceName"])
                local svcfile = str(ed["ServiceFileName"])
                if svcname then record["service"] = { name = svcname } end
                if svcfile then
                    record["file"] = {
                        path = svcfile,
                        name = svcfile:match("([^\\]+)$") or svcfile,
                    }
                end
                if record["event"] then record["event"]["category"] = "configuration" end

            -- ── Scheduled task: 4698 creation, 4699 deletion ─────────────────
            elseif eid == 4698 or eid == 4699 then
                local taskname = str(ed["TaskName"])
                local suser    = str(ed["SubjectUserName"])
                if taskname then
                    record["winlog"] = { event_data = { task_name = taskname } }
                end
                if suser and suser ~= "-" then
                    record["user"] = { name = suser, domain = str(ed["SubjectDomainName"]) }
                end
                if record["event"] then
                    record["event"]["category"] = "configuration"
                    record["event"]["type"]     = eid == 4698 and "creation" or "deletion"
                end

            -- ── PowerShell script block via Evtx channel: 4104 ───────────────
            elseif eid == 4104 then
                local sbt = str(ed["ScriptBlockText"])
                if sbt then
                    record["powershell"] = { script_block_text = sbt }
                end
                if record["event"] then record["event"]["category"] = "process" end

            end  -- EventID dispatch
        end  -- EventData table check
    end

    -- ── Windows.EventLogs.PowershellScriptblock / PowershellModule ───────────
    if artifact:find("powershell") then
        local computer = str(record["Computer"])
        if computer then
            record["host"] = { name = computer:lower() }
        end
        local sid = str(record["SecurityID"])
        if sid then
            record["user"] = { id = sid }
        end
        if record["EventID"] then
            record["event"] = { code = tostring(record["EventID"]), category = "process" }
        end
        -- ScriptBlock text goes into ECS powershell field
        local sbt = str(record["ScriptBlockText"])
        if sbt then
            record["powershell"] = { script_block_text = sbt }
        end
    end

    -- ── Windows.Forensics.Prefetch ────────────────────────────────────────────
    if artifact:find("prefetch") then
        local exe = str(record["Executable"])
        if exe then
            record["process"] = { name = exe }
        end
        if str(record["OSPath"]) then
            record["file"] = { path = record["OSPath"] }
        end
    end

    -- ── Windows.NTFS.MFT ─────────────────────────────────────────────────────
    if artifact:find("ntfs") then
        local ospath = str(record["OSPath"])
        if ospath then
            local fname = ospath:match("([^\\]+)$") or ospath
            local ext   = fname:match("%.(%w+)$")
            record["file"] = {
                path      = ospath,
                name      = fname,
                extension = ext,
                size      = record["FileSize"],
                created   = str(record["Created0x10"]),
                mtime     = str(record["LastModified0x10"]),
                accessed  = str(record["LastAccess0x10"]),
                attributes = { ads = record["HasADS"] },
            }
        end
    end

    -- ── Windows.Sysinternals.Autoruns ─────────────────────────────────────────
    if artifact:find("autoruns") then
        local img = str(record["Image Path"])
        if img then
            local fname = img:match("([^\\]+)$") or img
            record["file"] = { path = img, name = fname }
        end
        local reg_path = str(record["Entry Location"])
        if reg_path then
            record["registry"] = { path = reg_path, data = { strings = {str(record["Entry"])} } }
        end
        -- Signer → code_signature
        local signer = str(record["Signer"])
        if signer then
            record["code_signature"] = { subject_name = signer }
        end
    end

    -- ── Browser history (Chrome / Firefox / Edge) ─────────────────────────────
    if artifact:find("chrome%.history") or artifact:find("firefox%.history") or artifact:find("edge%.history") then
        local username = str(record["User"])
        if username then
            record["user"] = { name = username }
        end
        local url = str(record["url_visited"])
        if url then
            record["url"] = { original = url }
        end
    end

    -- ── Generic: EventID → event.code for any remaining event log artefacts ───
    if not record["event"] and record["EventID"] then
        record["event"] = { code = tostring(record["EventID"]) }
    end
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

    -- host.name as ECS nested object (overridden by artifact-specific Computer
    -- field in ecs_enrich below where more accurate data is available)
    if host ~= "" then
        record["host"] = { name = host }
    end
    record["log_index"] = artifact

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

    -- ── ECS normalisation ─────────────────────────────────────────────────────
    ecs_enrich(artifact, record)

    return 1, timestamp, record
end
