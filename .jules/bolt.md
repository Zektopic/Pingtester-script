## 2026-04-19 - Avoid .compressed over str() for ipaddress optimization
**Learning:** Python's standard `ipaddress` module's `.compressed` property on `IPv4Address` objects literally just returns `str(self)`. Using it instead of `str()` avoids zero overhead and actually adds the minor overhead of a property lookup and an extra function call.
**Action:** Do not micro-optimize `str(ip_obj)` to `ip_obj.compressed` expecting performance gains, as they are functionally equivalent strings and `.compressed` may add lookup overhead for IPv4 addresses.

## 2026-04-19 - Type check and property access over getattr()
**Learning:** In fast-path validation blocks handling polymorphic object types (like `IPv4Address` vs `IPv6Address`), using an explicit type check followed by direct attribute access (e.g., `type(ip_obj) is ipaddress.IPv6Address and ip_obj.scope_id`) is faster than using `getattr(ip_obj, 'scope_id', None)`.
**Action:** Replace `getattr` with exact `type() is X` checks and direct property access in hot-paths where specific types are known to hold unique properties (like IPv6's `ipv4_mapped` or `scope_id`), to bypass the internal dictionary lookup and exception handling overhead of dynamic attribute access.
## 2026-04-19 - Type check and property access over getattr()
**Learning:** In fast-path validation blocks handling polymorphic object types (like `IPv4Address` vs `IPv6Address`), using an explicit type check followed by direct attribute access (e.g., `type(ip_obj) is ipaddress.IPv6Address and ip_obj.scope_id`) is faster than using `getattr(ip_obj, 'scope_id', None)`.
**Action:** Replace `getattr` with exact `type() is X` checks and direct property access in hot-paths where specific types are known to hold unique properties (like IPv6's `ipv4_mapped` or `scope_id`), to bypass the internal dictionary lookup and exception handling overhead of dynamic attribute access.

## 2026-05-15 - Prevent redundant IPv4Address instantiations during SSRF checks
**Learning:** Python's `ipaddress` module's properties for embedded IPv4 addresses (`ipv4_mapped`, `sixtofour`, and `teredo`) compute and instantiate new `IPv4Address` objects every time they are accessed. Doing `if ip_obj.ipv4_mapped is not None: mapped = ip_obj.ipv4_mapped` parses and instantiates the embedded IPv4 object twice, which causes unnecessary overhead.
**Action:** When working with these `ipaddress` properties, cache them to local variables first before checking `is not None` using a nested `if/else` structure to avoid redundant object instantiations and parsing.

## 2024-05-09 - Redundant attributes in Python ipaddress
**Learning:** By definition in Python's `ipaddress` module, `is_private`, `is_loopback`, `is_link_local`, `is_unspecified`, and `is_reserved` inherently evaluate as `is_global = False`. Evaluating them sequentially in an SSRF blocklist is highly redundant and slow.
**Action:** When validating IPs for global routability, replace long chains like `ip.is_private or ip.is_loopback or ...` with a significantly faster logical reduction: `not ip.is_global or ip.is_multicast or (type(ip) is ipaddress.IPv6Address and ip.is_site_local)`. This reduces 8 checks down to 3 and yields massive performance gains on public IPs.
