-- extract_index.lua
-- Called by the Fluent Bit Lua filter for every log record.
-- Reads the full file path injected by Path_Key (e.g. /logs/auth.json),
-- strips the directory and extension, lowercases the result, and
-- writes it to record["log_index"] for use by Logstash_Prefix_Key.
--
-- Examples:
--   /logs/auth.json          → auth
--   /logs/windows_security.json → windows_security
--   /logs/sub/firewall.json  → firewall

function set_index(tag, timestamp, record)
    local path = record["filename"] or ""

    -- Extract basename: everything after the last / or \
    local basename = path:match("([^/\\]+)$") or path

    -- Strip extension (everything from the last dot to end)
    local name = basename:match("^(.-)%.%w+$") or basename

    -- Lowercase and replace any non-alphanumeric/underscore/hyphen chars
    name = name:lower():gsub("[^a-z0-9_%-]", "_")

    -- Fallback to "unknown" so no record goes without an index
    if name == "" then
        name = "unknown"
    end

    record["log_index"] = name
    return 1, timestamp, record
end
