import response
from model.file import File as FileModel


def ls(req):
    ls = []
    parent_id = req.get("id", 0)
    page = req.get("page", 1)
    rows = req.get("rows", 20)
    results = FileModel.select().where(FileModel.parent_id == parent_id).order_by(FileModel.id).paginate(page, rows).dicts()
    for r in results:
        ls.append(r)

    data = {
        "code": 0,
        "data": ls
    }
    return response.JsonResponse(data)

def info(req):
    ls = []
    file_id = req.get("id")
    if not file_id:
        data = {
            "code": 404
        }
        return response.JsonResponse(data)

    results = FileModel.select().where(FileModel.id == file_id).limit(1).dicts()
    if not results:
        data = {
            "code": 404
        }
        return response.JsonResponse(data)

    for r in results:
        ls.append(r)

    data = {
        "code": 0,
        "data": ls[0]
    }
    return response.JsonResponse(data)

ROUTER = {
    "/ls": ls,
    "/info": info
}

def route(req):
    path = req.get_path()
    if not path in ROUTER:
        resp = response.Response404()
    else:
        func = ROUTER[path]
        try:
            resp = func(req)
        except Exception as err:
            print(str(err))
            resp = response.Response500()

    return resp.get_response()
