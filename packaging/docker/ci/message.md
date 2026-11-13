Container proof alert from `mnotify teams send` (card MN-P01).

This body travelled through the real send path — config, guard, file-backend
webhook lookup, HTTPS POST — inside the Alpine image. The channel behind it is a
local TLS stub on the CI runner, not a real Teams channel.
