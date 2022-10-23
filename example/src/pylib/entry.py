import pymongo
import response


def index(req):
    resp = response.Response(200)
    resp.body = "<h1>Hello World.</h1>"
    return resp

def get_config(req):
    client = pymongo.MongoClient("127.0.0.1", 27017)
    db = client["mydb"]
    col = db["mycol"]
    doc = col.find_one()
    _id = str(doc["_id"])
    doc["_id"] = _id
    resp = response.JsonResponse(doc)
    return resp

RESPONSE_404 = response.Response(404)

ROUTER = {
    "/": index,
    "/get_config": get_config
}

def route(req):
    path = req.get_path()
    if not path in ROUTER:
        resp = RESPONSE_404
    else:
        func = ROUTER[path]
        resp = func(req)

    return resp.get_response()
