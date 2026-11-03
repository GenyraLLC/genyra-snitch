# Synthetic GeoIP fixture

`GeoIP2-City-Test.mmdb` comes from
https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoIP2-City-Test.mmdb.
It is public generated test data, not a captured connection or user database.
Copyright 2013–2026 MaxMind, Inc.; distributed under the accompanying MIT license.
Used to test atomic replacement while existing read-only mappings remain live.

Fetched 2026-11-03. Manual GeoIP updates must replace the file atomically rather
than truncate or modify a database currently mapped by a collector.
