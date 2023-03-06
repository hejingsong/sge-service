#! coding:utf-8

import json
import status


class Response(object):

    def __init__(self, status=200):
        self.status = status
        self.headers = {}
        self.cookie = {}
        self.body = ''

    def set_header(self, headers):
        self.headers.update(headers)

    def set_cookie(self, key, value='', expire=0 , path='/', domain='', secure=False, httponly=False, samesite=''):
        pass

    def set_status(self, code):
        self.status = code

    def get_response(self):
        self.body = self.parse_body()
        return "{status}\r\n{header}\r\n\r\n{body}".format(
            status=self.format_status(),
            header=self.format_header(),
            body=self.body
        )
    
    def format_status(self):
        return "HTTP/1.1 {status} {message}".format(status=self.status, message=status.HTTP_STATUS_MAP.get(self.status, "<unknown>"))

    def format_header(self):
        s_headers = []
        for k, v in self.headers.items():
            s_headers.append("{0}: {1}".format(k, v))
        if self.body:
            s_headers.append("Content-Length: {0}".format(len(self.body)))
        return "\r\n".join(s_headers)

    def parse_body(self):
        return self.body


class Response404(Response):
    def __init__(self):
        super().__init__(404)
        self.body = "<H1>404 Not Found</H1>"


class Response500(Response):
    def __init__(self):
        super().__init__(500)
        self.body = "<H1>500 System Error.</H1>"


class JsonResponse(Response):

    def __init__(self, data):
        super(JsonResponse, self).__init__(200)
        self.headers = {
            "Content-Type": "application/json"
        }
        self.data = data

    def parse_body(self):
        return json.dumps(self.data)
