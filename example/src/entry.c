#include <Python.h>

#include "core/sge.h"
#include "core/log.h"
#include "utils/config.h"
#include "module/module.h"
#include "server/server.h"

#define LIBRARY_NAME "pyhttp"

struct PyHttpServer {
    int envInitialized;
    PyObject* mainEntry;
    PyObject* handleMessageFn;
    PyObject* handleNewConnection;
    PyObject* handleClosed;
    PyObject* handleWriteDone;
    PyThreadState* threadState;
    struct sge_server* server;
};


#define PYTHON_CALLER(result, func, fmt, ...)                               \
result = PyObject_CallFunction(func, fmt, ##__VA_ARGS__);                   \
if (!result || result == Py_None || result == Py_False) {                   \
    if (PyErr_Occurred()) {                                                 \
        PyErr_Print();                                                      \
        result = NULL;                                                      \
    }                                                                       \
}

#define PY_PRINT_ERROR()                                                    \
{                                                                           \
    if (PyErr_Occurred()) {                                                 \
        PyErr_Print();                                                      \
    }                                                                       \
}

static struct PyHttpServer* g_PyHttpServer;

static struct PyHttpServer* createPyHttpServer() {
    struct PyHttpServer* s;

    s = sge_malloc(sizeof(struct PyHttpServer));
    s->handleMessageFn = NULL;
    s->mainEntry = NULL;
    s->server = NULL;
    s->threadState = NULL;
    s->envInitialized = 0;

    return s;
}

static int
pyHttpHandleMessage(socket_id sid, char* message, int len) {
    PyObject* pyMsg, *pySid, *pyResult;
    PyGILState_STATE state;

    state = PyGILState_Ensure();
    pySid = PyLong_FromUnsignedLong(sid);
    pyMsg = PyUnicode_FromStringAndSize(message, len);
    PYTHON_CALLER(pyResult, g_PyHttpServer->handleMessageFn, "OO", pySid, pyMsg);

    Py_XDECREF(pySid);
    Py_XDECREF(pyMsg);
    Py_XDECREF(pyResult);
    PyGILState_Release(state);
    return SGE_OK;
}

static int
pyHttpHandleClosed(socket_id sid) {
    PyObject* pySid, *pyResult;
    PyGILState_STATE state;

    state = PyGILState_Ensure();
    pySid = PyLong_FromUnsignedLong(sid);
    PYTHON_CALLER(pyResult, g_PyHttpServer->handleClosed, "O", pySid);

    Py_XDECREF(pySid);
    Py_XDECREF(pyResult);
    PyGILState_Release(state);
    return SGE_OK;
}

static int
pyHttpHandleNewConnect(socket_id sid) {
    PyObject* pySid, *pyResult;
    PyGILState_STATE state;

    state = PyGILState_Ensure();
    pySid = PyLong_FromUnsignedLong(sid);
    PYTHON_CALLER(pyResult, g_PyHttpServer->handleNewConnection, "O", pySid);

    Py_XDECREF(pySid);
    Py_XDECREF(pyResult);
    PyGILState_Release(state);
    return SGE_OK;
}

static int
pyHttpHandleWriteDone(socket_id sid) {
    PyObject* pySid, *pyResult;
    PyGILState_STATE state;

    state = PyGILState_Ensure();
    pySid = PyLong_FromUnsignedLong(sid);
    PYTHON_CALLER(pyResult, g_PyHttpServer->handleWriteDone, "O", pySid);

    Py_XDECREF(pySid);
    Py_XDECREF(pyResult);
    PyGILState_Release(state);
    return SGE_OK;
}


static struct sge_server_op SERVER_OP = {
    .handle_closed = pyHttpHandleClosed,
    .handle_new_connect = pyHttpHandleNewConnect,
    .handle_message = pyHttpHandleMessage,
    .handle_write_done = pyHttpHandleWriteDone
};

static PyObject*
sgeSendMessage(PyObject* self, PyObject* args) {
    if (!PyTuple_Check(args)) {
        PyErr_Format(PyExc_TypeError, "sge_send_msg args must be tuple object");
        Py_RETURN_FALSE;
    }

    if (PyTuple_GET_SIZE(args) != 2) {
        PyErr_Format(PyExc_TypeError, "call error sge_send_msg(sid, msg)");
        Py_RETURN_FALSE;
    }

    PyObject* pySid = PyTuple_GET_ITEM(args, 0);
    PyObject* pyMsg = PyTuple_GET_ITEM(args, 1);

    Py_ssize_t size;
    socket_id sid = PyLong_AsUnsignedLong(pySid);
    const char* sMsg = PyUnicode_AsUTF8AndSize(pyMsg, &size);

    sge_send_message(sid, (char*)sMsg, size);

    Py_RETURN_TRUE;
}

PyObject*
sgeCloseConnection(PyObject* self, PyObject* args) {
    if (!PyLong_Check(args)) {
        PyErr_Format(PyExc_TypeError, "sge_close_connection args 1 must be long object");
        Py_RETURN_FALSE;
    }

    socket_id sid = PyLong_AsUnsignedLong(args);
    if (SGE_ERR == sge_close_connection(sid)) {
        Py_RETURN_FALSE;
    } else {
        Py_RETURN_TRUE;
    }
}

static PyMethodDef g_closeConnDef = {
    .ml_name = "sge_close_connection",
    .ml_meth = sgeCloseConnection,
    .ml_flags = METH_O,
    .ml_doc = "close connection"
};

static PyMethodDef g_sendMsgDef = {
    .ml_doc = "send message to socket",
    .ml_flags = METH_VARARGS,
    .ml_meth = sgeSendMessage,
    .ml_name = "sge_send_message"
};


static int
sgeInitPythonEnv(struct PyHttpServer* srv) {
    if (!Py_IsInitialized()) {
        Py_Initialize();
        if (!Py_IsInitialized()) {
            SGE_LOG_ERROR("initialize python interpreter error.");
            return SGE_ERR;
        }
    }
    PyEval_InitThreads();

    PyObject* sysPath = PySys_GetObject("path");
    PyObject* path = PyUnicode_FromStringAndSize("./src/pylib", 11);
    PyList_Insert(sysPath, 0, path);
    Py_DECREF(path);

    srv->mainEntry = PyImport_ImportModule("main");
    if (NULL == srv->mainEntry) {
        SGE_LOG_ERROR("can't import module main.");
        PY_PRINT_ERROR();
        goto ERR;
    }

    srv->handleMessageFn = PyObject_GetAttrString(srv->mainEntry, "handle_message");
    if (NULL == srv->handleMessageFn) {
        SGE_LOG_ERROR("can't found function:handle_message in module:main.");
        goto ERR;
    }

    srv->handleNewConnection = PyObject_GetAttrString(srv->mainEntry, "handle_new_connection");
    if (NULL == srv->handleNewConnection) {
        SGE_LOG_ERROR("can't found function:handle_new_connection in module:main.");
        goto ERR;
    }

    srv->handleClosed = PyObject_GetAttrString(srv->mainEntry, "handle_closed");
    if (NULL == srv->handleClosed) {
        SGE_LOG_ERROR("can't found function:handle_closed in module:main.");
        goto ERR;
    }

    srv->handleWriteDone = PyObject_GetAttrString(srv->mainEntry, "handle_write_done");
    if (NULL == srv->handleWriteDone) {
        SGE_LOG_ERROR("can't found function:handle_write_done in module:main.");
        goto ERR;
    }

    PyObject* fnSendMsg = PyCFunction_New(&g_sendMsgDef, NULL);
    PyObject_SetAttrString(srv->mainEntry, "sge_send_message", fnSendMsg);
    PY_PRINT_ERROR();

    PyObject* fnCloseConn = PyCFunction_New(&g_closeConnDef, NULL);
    PyObject_SetAttrString(srv->mainEntry, "sge_close_connection", fnCloseConn);
    PY_PRINT_ERROR();

    srv->envInitialized = 1;
    return SGE_OK;

ERR:
    return SGE_ERR;
}

static void
sgeDestroyPythonEnv(struct PyHttpServer* srv) {
    if (srv->envInitialized == 0) {
        return;
    }

    if (srv->handleMessageFn) {
        Py_DECREF(srv->handleMessageFn);
    }
    if (srv->handleNewConnection) {
        Py_DECREF(srv->handleNewConnection);
    }
    if (srv->handleClosed) {
        Py_DECREF(srv->handleClosed);
    }
    if (srv->handleWriteDone) {
        Py_DECREF(srv->handleWriteDone);
    }
    if (srv->mainEntry) {
        Py_DECREF(srv->mainEntry);
    }
    if (srv->threadState) {
        PyEval_RestoreThread(srv->threadState);
    }
    srv->handleNewConnection = NULL;
    srv->handleMessageFn = NULL;
    srv->handleClosed = NULL;
    srv->mainEntry = NULL;
    srv->threadState = NULL;
    srv->envInitialized = 0;
    Py_Finalize();
}

static int
init(struct sge_module* module) {
    int port;
    const char* sHost;
    const char* sPort;
    struct PyHttpServer* pyHttpSrv;

    sHost = sge_get_config(LIBRARY_NAME, "host");
    sPort = sge_get_config(LIBRARY_NAME, "port");
    if (NULL == sHost || NULL == sPort) {
        SGE_LOG_ERROR("config error. invalid host or port");
        return SGE_ERR;
    }

    pyHttpSrv = createPyHttpServer();
    if (SGE_ERR == sgeInitPythonEnv(pyHttpSrv)) {
        SGE_LOG_ERROR("init python env failed.");
        goto ERR;
    }

    port = atoi(sPort);
    pyHttpSrv->server = sge_create_server(sHost, port, &SERVER_OP);
    pyHttpSrv->threadState = PyThreadState_Get();
    PyEval_SaveThread();

    g_PyHttpServer = pyHttpSrv;
    return SGE_OK;

ERR:
    sgeDestroyPythonEnv(pyHttpSrv);
    sge_free(pyHttpSrv);
    return SGE_ERR;
}

static int
destroy(struct sge_module* module) {
    SGE_LOG_DEBUG("module pyhttp destroy start.");
    sgeDestroyPythonEnv(g_PyHttpServer);
    if (g_PyHttpServer) {
        sge_free(g_PyHttpServer);
    }
    SGE_LOG_DEBUG("module pyhttp destroy done.");
    return SGE_OK;
}

static int
reload(struct sge_module* module) {
    PyGILState_STATE state;

    state = PyGILState_Ensure();

    //TODO: 添加python 热更新

    PyGILState_Release(state);

    return SGE_OK;
}

struct
sge_module_op MODULE_API = {
    .init = init,
    .destroy = destroy,
    .reload = reload
};
