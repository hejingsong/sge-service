import entry
import model.file as FileModel
import connection
import http_parser

g_connection_map = {}

def py_close_conn(sid):
    pass

def py_send_msg(sid, msg):
    pass

def remove_connect(sid):
    py_close_conn(sid)
    g_connection_map.pop(sid)


def handle_closed(sid):
    if not sid in g_connection_map:
        return False

    c = g_connection_map[sid]
    if c.status == connection.Connection.AVAILABLE:
        c.status = connection.Connection.HALF_CLOSED
    remove_connect(sid)
    return True


def handle_new_connection(sid):
    c = connection.Connection()
    c.status = connection.Connection.AVAILABLE
    c.sid = sid
    g_connection_map[sid] = c
    return True

def handle_write_done(sid):
    if not sid in g_connection_map:
        return False
    
    c = g_connection_map[sid]
    if c.status == connection.Connection.HALF_CLOSED:
        remove_connect(sid)

    return True

def handle_message(sid, msg):
    c = g_connection_map.get(sid, None)
    if not c:
        return False
    c.append_msg(msg)

    (result, req) = http_parser.parse(c)
    if not result:
        print("parse http message error {} {}".format(result, req))
        return False

    resp = entry.route(req)
    py_send_msg(sid, resp)

    return True
