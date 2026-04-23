## 2026-04-19 - Avoid .compressed over str() for ipaddress optimization
**Learning:** Python's standard `ipaddress` module's `.compressed` property on `IPv4Address` objects literally just returns `str(self)`. Using it instead of `str()` avoids zero overhead and actually adds the minor overhead of a property lookup and an extra function call.
**Action:** Do not micro-optimize `str(ip_obj)` to `ip_obj.compressed` expecting performance gains, as they are functionally equivalent strings and `.compressed` may add lookup overhead for IPv4 addresses.

## 2026-04-19 - Type check and property access over getattr()
**Learning:** In fast-path validation blocks handling polymorphic object types (like `IPv4Address` vs `IPv6Address`), using an explicit type check followed by direct attribute access (e.g., `type(ip_obj) is ipaddress.IPv6Address and ip_obj.scope_id`) is faster than using `getattr(ip_obj, 'scope_id', None)`.
**Action:** Replace `getattr` with exact `type() is X` checks and direct property access in hot-paths where specific types are known to hold unique properties (like IPv6's `ipv4_mapped` or `scope_id`), to bypass the internal dictionary lookup and exception handling overhead of dynamic attribute access.
## 2026-04-19 - Type check and property access over getattr()
**Learning:** In fast-path validation blocks handling polymorphic object types (like `IPv4Address` vs `IPv6Address`), using an explicit type check followed by direct attribute access (e.g., `type(ip_obj) is ipaddress.IPv6Address and ip_obj.scope_id`) is faster than using `getattr(ip_obj, 'scope_id', None)`.
**Action:** Replace `getattr` with exact `type() is X` checks and direct property access in hot-paths where specific types are known to hold unique properties (like IPv6's `ipv4_mapped` or `scope_id`), to bypass the internal dictionary lookup and exception handling overhead of dynamic attribute access.
