-- wrk -t4 -c2000 -d10s --script=example/pyhttp/wrk.lua --latency http://127.0.0.1:12345/ls

wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
-- wrk.headers["Connection"] = "close"
wrk.body = "{}"
