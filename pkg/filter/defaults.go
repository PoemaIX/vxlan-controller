package filter

// DefaultOutputMcastScript allows all multicast by default.
// To use a preset filter, set output_mcast in config:
//
//	filters:
//	  output_mcast: |
//	    local f = require("filter")
//	    filter = f.filter_home_lan
//
// Available presets: filter_allow_all, filter_ix_lan, filter_home_lan, filter_isp
// Returns: bool accepted, string reason, string detail
const DefaultOutputMcastScript = `
-- local f = require("filter")
-- filter = f.filter_home_lan
function filter(pkt)
  return true
end
`

// DefaultInputMcastScript accepts all inbound multicast on the rx path.
// Tx-side filtering is preferred; input filter is for defensive/untrusted scenarios.
const DefaultInputMcastScript = `
function filter(pkt)
  return true, nil, nil
end
`

// DefaultRouteScript accepts all routes.
const DefaultRouteScript = `
function filter(route)
  return true, nil, nil
end
`

const (
	DefaultPerMACRate    = 64.0   // packets per second per source MAC
	DefaultPerClientRate = 1000.0 // packets per second per client total
)

// DefaultAddrSelectV4 selects the best IPv4 address from an interface.
// Priority: public IP > prev_ip > private IP. Skips IPv6 addresses.
const DefaultAddrSelectV4 = `
function select(info)
  local addrs = info.addrs
  if #addrs == 0 then return nil end

  local public, prev, private = nil, nil, nil
  for i = 1, #addrs do
    local a = addrs[i]
    if a.ip:find(":") then goto continue end  -- skip v6

    local b1 = tonumber(a.ip:match("^(%d+)"))
    local b2 = tonumber(a.ip:match("^%d+%.(%d+)"))
    local is_private = (b1 == 10)
      or (b1 == 172 and b2 >= 16 and b2 <= 31)
      or (b1 == 192 and b2 == 168)
      or (b1 == 100 and b2 >= 64 and b2 <= 127)

    if a.ip == info.prev_ip then prev = a.ip end
    if is_private then
      private = private or a.ip
    else
      public = public or a.ip
    end
    ::continue::
  end

  return public or prev or private
end
`

// DefaultAddrSelectV6 selects the best IPv6 address from an interface.
// Filters out: deprecated, link-local, IPv4 addresses.
// Priority: public IP (prefer higher valid_lft, then prefix_len closest to /64) > prev_ip > ULA/private.
const DefaultAddrSelectV6 = `
function select(info)
  local addrs = info.addrs
  if #addrs == 0 then return nil end

  local best_pub = nil
  local best_pub_vlft = -1
  local best_pub_diff = 999
  local prev, private = nil, nil

  for i = 1, #addrs do
    local a = addrs[i]
    if not a.ip:find(":") then goto continue end   -- skip v4
    if a.deprecated then goto continue end          -- skip deprecated
    local low = a.ip:lower()
    if low:match("^fe80") then goto continue end    -- skip link-local

    if a.ip == info.prev_ip then prev = a.ip end

    local is_ula = low:match("^f[cd]")
    if is_ula then
      private = private or a.ip
    else
      -- public: prefer higher valid_lft, then prefix_len closest to /64
      local vlft = a.valid_lft or 0
      local diff = math.abs(a.prefix_len - 64)
      if vlft > best_pub_vlft
        or (vlft == best_pub_vlft and diff < best_pub_diff) then
        best_pub = a.ip
        best_pub_vlft = vlft
        best_pub_diff = diff
      end
    end
    ::continue::
  end

  return best_pub or prev or private
end
`
