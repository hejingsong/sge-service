import json
import request


PARSE_INCOMPLETE = 0
PARSE_COMPLETE = 1
PARSE_ERROR = 2


def parse_start_line(msg):
    [method, path, version] = msg.split(" ")
    return (method, path, version)

def parse_header(str_header):
    headers = {}
    lines = str_header.split("\r\n")
    for line in lines:
        [field, value] = line.split(":", 1)
        k = field.strip().lower()
        headers[k] = value.strip()
    return headers

def parse_http_header(header):
    [str_start_line, str_header] = header.split("\r\n", 1)
    (method, path, version) = parse_start_line(str_start_line)
    headers = parse_header(str_header)
    req_info = {
        "method": method,
        "path": path,
        "version": version
    }
    return (True, {"len": len(header), "req_info": req_info, "headers": headers})

def parse_disposition(disp):
    items = disp.split(b";")
    disposition = items[0].strip()
    params = {}
    for opt in items[1:]:
        k, v = opt.split(b"=")
        params[k.strip().decode()] = v.strip().strip(b'"').decode()
    return disposition, params

def parse_multipart_form_data(boundary, data, args):
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    final_boundary_index = data.rfind("--" + boundary + "--")
    if final_boundary_index == -1:
        return False
    parts = data[:final_boundary_index].split("--" + boundary + "\r\n")
    for part in parts:
        if not part:
            continue
        eoh = part.find("\r\n\r\n")
        if eoh == -1:
            continue
        headers = parse_header(part[:eoh])
        disp = headers.get("content-disposition", "")
        disposition, disp_params = parse_disposition(disp)
        if disposition != "form-data" or not part.endswith("\r\n"):
            continue
        value = part[eoh + 4 : -2]
        if value == 'undefined':
            value = None
        if not disp_params.get("name"):
            continue
        name = disp_params["name"]
        if disp_params.get("filename"):
            if not name in args:
                args[name] = []
            ctype = headers.get("content-type", "application/unknown")
            args[name].append({
                "filename": disp_params["filename"],
                "content": value,
                "type": ctype
            })
        else:
            args[name] = value
    return True

def parse_request_body(headers, str_body):
    if not "content-length" in headers or not "content-type" in headers:
        return (False, PARSE_INCOMPLETE)

    body_len = int(headers["content-length"])
    if len(str_body) != body_len:
        return (False, PARSE_INCOMPLETE)

    body = {}
    content_type = headers['content-type']
    if content_type.find("application/x-www-form-urlencoded") != -1:
        items = str_body.split("&")
        for item in items:
            [field, value] = item.split("=")
            k = field.strip()
            body[k] = value.strip()
        return (True, {"len": body_len, "body": body})

    if content_type.find("multipart/form-data") != -1:
        args = {}
        flag = True
        fields = content_type.split(";")
        for field in fields:
            k, sep, v = field.strip().partition("=")
            if k != "boundary" or not v:
                continue
            flag = parse_multipart_form_data(v, str_body, args)
            if not flag:
                break
        if not flag:
            return (False, PARSE_INCOMPLETE)
        body = args
        return (True, {"len": body_len, "body": body})

    if content_type.find("application/json") != -1:
        body = json.loads(str_body)
        return (True, {"len": body_len, "body": body})
    return (False, PARSE_INCOMPLETE)

def parse_http_message(msg):
    if msg.find("\r\n\r\n") == -1:
        return (False, PARSE_INCOMPLETE)

    [header, body] = msg.split("\r\n\r\n", 1)
    (result, header_info) = parse_http_header(header)
    if not result:
        return (False, PARSE_ERROR)

    req_info = header_info["req_info"]
    header_len = header_info["len"]
    headers = header_info["headers"]
    (result, info) = parse_request_body(headers, body)

    if not result:
        return (False, info)

    body_len = info["len"]
    req = request.Request(
        req_info["method"],
        req_info["path"],
        req_info["version"],
        headers,
        info["body"]
    )
    return (True, {"len": header_len + body_len + 4, "request": req})


def parse(conn):
    r = (result, info) = parse_http_message(conn.buffer)
    if not result:
        return r

    msg_len = info["len"]
    conn.buffer = conn.buffer[msg_len:]
    return (True, info["request"])
