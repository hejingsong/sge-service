-- wrk -t2 -c12 -d10 --script=stress.lua --latency http://127.0.0.1:12345/get_config

wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Connection"] = "close"
wrk.body = "{\"a\": 1}"
