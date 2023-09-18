#include <Python.h>

#include "core/sge.h"
#include "core/log.h"
#include "core/list.h"
#include "core/event.h"
#include "core/string.h"
#include "core/module.h"
#include "core/server.h"
#include "core/config.h"
#include "core/context.h"

#define PY_PRINT_ERROR()                                                    \
{                                                                           \
    if (PyErr_Occurred()) {                                                 \
        PyErr_Print();                                                      \
    }                                                                       \
}

#define CALL_PYTHON_FUNC(result, func, fmt, ...)                            \
result = PyObject_CallFunction(func, fmt, ##__VA_ARGS__);                   \
if (!result || result == Py_None || result == Py_False) {                   \
    if (PyErr_Occurred()) {                                                 \
        PyErr_Print();                                                      \
        result = NULL;                                                      \
    }                                                                       \
}

struct pyhttp {
    int initialized;
    PyObject* py_main_entry;
    PyObject* py_handle_msg_fn;
    PyObject* py_handle_new_conn_fn;
    PyObject* py_handle_close_fn;
    PyThreadState* py_thread_state;

    struct sge_module* module;
    struct sge_server* server;
};


static PyObject* py_close_conn__(PyObject* obj, PyObject* args) {
    sge_socket_id sid;

    if (!PyLong_Check(args)) {
        PyErr_Format(PyExc_TypeError, "sge_close_connection args 1 must be long object");
        Py_RETURN_FALSE;
    }

    sid = PyLong_AsUnsignedLong(args);
    if (SGE_ERR == sge_destroy_socket_by_sid(sid)) {
        Py_RETURN_FALSE;
    } else {
        Py_RETURN_TRUE;
    }
}

static PyObject* py_send_msg__(PyObject* obj, PyObject* args) {
    PyObject* py_sid, *py_msg;
    Py_ssize_t size;
    sge_socket_id sid;
    const char* msg;

    if (!PyTuple_Check(args)) {
        PyErr_Format(PyExc_TypeError, "sge_send_msg args must be tuple object");
        Py_RETURN_FALSE;
    }

    if (PyTuple_GET_SIZE(args) != 2) {
        PyErr_Format(PyExc_TypeError, "call error sge_send_msg(sid, msg)");
        Py_RETURN_FALSE;
    }

    py_sid = PyTuple_GET_ITEM(args, 0);
    py_msg = PyTuple_GET_ITEM(args, 1);

    sid = PyLong_AsUnsignedLong(py_sid);
    msg = PyUnicode_AsUTF8AndSize(py_msg, &size);

    sge_send_msg(sid, msg, size);

    Py_RETURN_TRUE;
}


static PyMethodDef g_closeConnDef = {
    .ml_name = "py_close_conn",
    .ml_meth = py_close_conn__,
    .ml_flags = METH_O,
    .ml_doc = "close connection"
};

static PyMethodDef g_sendMsgDef = {
    .ml_doc = "send message to socket",
    .ml_flags = METH_VARARGS,
    .ml_meth = py_send_msg__,
    .ml_name = "py_send_msg"
};

static int init_python_env__(struct pyhttp* pyhttp) {
    PyObject* sys_path, *local_path;
    struct sge_config* cfg;
    struct sge_module* module;
    const char* module_name, *workspace;
    char py_lib_path[1024];
    size_t py_lib_path_len;

    if (!Py_IsInitialized()) {
        Py_Initialize();
        if (!Py_IsInitialized()) {
            SGE_LOG(SGE_LOG_LEVEL_ERROR, "initialize python interpreter error.");
            return SGE_ERR;
        }
    }

    module = pyhttp->module;
    cfg = module->ctx->cfg;

    sge_string_data(module->name, &module_name);
    sge_get_config(cfg, module_name, "workspace", &workspace);
    if (NULL == workspace) {
        workspace = ".";
    }
    py_lib_path_len = sprintf(py_lib_path, "%s/src/pylib", workspace);
    py_lib_path[py_lib_path_len + 1] = '\0';

    PyEval_InitThreads();
    sys_path = PySys_GetObject("path");
    local_path = PyUnicode_FromStringAndSize(py_lib_path, py_lib_path_len);
    PyList_Insert(sys_path, 0, local_path);
    Py_DECREF(local_path);

    pyhttp->py_main_entry = PyImport_ImportModule("main");
    if (NULL == pyhttp->py_main_entry) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't import module main.");
        PY_PRINT_ERROR();
        goto error;
    }

    pyhttp->py_handle_msg_fn = PyObject_GetAttrString(pyhttp->py_main_entry, "handle_message");
    if (NULL == pyhttp->py_handle_msg_fn) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't found function:handle_message in module:main.");
        goto error;
    }

    pyhttp->py_handle_new_conn_fn = PyObject_GetAttrString(pyhttp->py_main_entry, "handle_new_connection");
    if (NULL == pyhttp->py_handle_new_conn_fn) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't found function:handle_new_connection in module:main.");
        goto error;
    }

    pyhttp->py_handle_close_fn = PyObject_GetAttrString(pyhttp->py_main_entry, "handle_closed");
    if (NULL == pyhttp->py_handle_close_fn) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't found function:handle_closed in module:main.");
        goto error;
    }

    PyObject* fnSendMsg = PyCFunction_New(&g_sendMsgDef, NULL);
    PyObject_SetAttrString(pyhttp->py_main_entry, "py_send_msg", fnSendMsg);
    PY_PRINT_ERROR();

    PyObject* fnCloseConn = PyCFunction_New(&g_closeConnDef, NULL);
    PyObject_SetAttrString(pyhttp->py_main_entry, "py_close_conn", fnCloseConn);
    PY_PRINT_ERROR();

    pyhttp->py_thread_state = PyThreadState_Get();
    PyEval_SaveThread();
    pyhttp->initialized = 1;

    return SGE_OK;
error:
    Py_Finalize();
    return SGE_ERR;
}

static int py_handle_new_conn__(struct pyhttp* pyhttp, struct sge_message* msg) {
    PyObject* py_sid, *py_result;

    py_sid = PyLong_FromUnsignedLong(msg->custom_id);
    CALL_PYTHON_FUNC(py_result, pyhttp->py_handle_new_conn_fn, "O", py_sid);

    Py_XDECREF(py_sid);
    Py_XDECREF(py_result);

    return SGE_OK;
}

static int py_handle_closed__(struct pyhttp* pyhttp, struct sge_message* msg) {
    PyObject* py_sid, *py_result;

    py_sid = PyLong_FromUnsignedLong(msg->custom_id);
    CALL_PYTHON_FUNC(py_result, pyhttp->py_handle_close_fn, "O", py_sid);

    Py_XDECREF(py_sid);
    Py_XDECREF(py_result);

    return SGE_OK;
}

static int py_handle_msg__(struct pyhttp* pyhttp, struct sge_message* msg) {
    const char* buf;
    size_t buf_len;
    PyObject* py_sid, *py_msg, *py_result;

    buf_len = sge_string_data(msg->msg, &buf);
    py_sid = PyLong_FromUnsignedLong(msg->custom_id);
    py_msg = PyUnicode_FromStringAndSize(buf, buf_len);
    CALL_PYTHON_FUNC(py_result, pyhttp->py_handle_msg_fn, "OO", py_sid, py_msg);

    Py_XDECREF(py_sid);
    Py_XDECREF(py_msg);
    Py_XDECREF(py_result);

    return SGE_OK;
}

static int pyhttp_handle__(struct sge_module* module, struct sge_list* msg_list) {
    int closed;
    struct sge_list* iter, *next;
    struct sge_message* msg;
    struct pyhttp* pyhttp;
    PyGILState_STATE py_state;

    closed = 0;
    pyhttp = (struct pyhttp*)module->private_data;

    py_state = PyGILState_Ensure();
    SGE_LIST_FOREACH_SAFE(iter, next, msg_list) {
        msg = sge_container_of(iter, struct sge_message, entry);
        if (msg->msg_type == SGE_MSG_TYPE_NEW_CONN) {
            py_handle_new_conn__(pyhttp, msg);
        }

        if (msg->msg_type == SGE_MSG_TYPE_CLOSED) {
            py_handle_closed__(pyhttp, msg);
            closed = 1;
        }

        if (msg->msg_type == SGE_MSG_TYPE_NEW_MSG) {
            py_handle_msg__(pyhttp, msg);
        }

        SGE_LIST_REMOVE(iter);
        sge_destroy_string(msg->msg);
        sge_destroy_message(msg);
    }
    PyGILState_Release(py_state);

    if (closed) {
        sge_destroy_socket_by_sid(msg->custom_id);
    }

    return SGE_OK;
}

static int pyhttp_init__(struct sge_module* module) {
    int ret;
    const char* server_addr, *event_type, *module_name;
    struct sge_config* cfg;
    struct sge_server* server;
    struct pyhttp* pyhttp;

    cfg = module->ctx->cfg;
    sge_string_data(module->name, &module_name);
    sge_get_config(cfg, module_name, "server", &server_addr);
    if (!server_addr) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "not found server in module(%s)", module_name);
        return SGE_ERR;
    }
    sge_get_config(cfg, module_name, "event", &event_type);
    if (!event_type) {
        event_type = "EPOLL";
    }

    sge_alloc_server(module, &server);
    ret = sge_get_event_mgr(event_type, &server->event_mgr);
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "can't found event mgr(%s)", event_type);
        goto error;
    }

    ret = sge_create_listener(server_addr, server);
    if (SGE_ERR == ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "create listen socket error.");
        goto error;
    }
    SGE_LOG(SGE_LOG_LEVEL_INFO, "module(%s) create server(%s) success", module_name, server_addr);

    pyhttp = sge_malloc(sizeof(struct pyhttp));
    pyhttp->module = module;
    pyhttp->server = server;
    ret = init_python_env__(pyhttp);
    if (SGE_OK != ret) {
        SGE_LOG(SGE_LOG_LEVEL_ERROR, "init python env error.");
        PyErr_Print();
        goto init_py_env_err;
    }

    module->private_data = pyhttp;
    return SGE_OK;

init_py_env_err:
    sge_free(pyhttp);
error:
    sge_destroy_server(server);
    return SGE_ERR;
}

static int pyhttp_destroy__(struct sge_module* module) {
    struct pyhttp* pyhttp;

    pyhttp = (struct pyhttp*)module->private_data;
    sge_destroy_server(pyhttp->server);
    if (pyhttp->initialized) {
        Py_DECREF(pyhttp->py_handle_msg_fn);
        Py_DECREF(pyhttp->py_handle_new_conn_fn);
        Py_DECREF(pyhttp->py_handle_close_fn);
        Py_DECREF(pyhttp->py_main_entry);
        PyEval_RestoreThread(pyhttp->py_thread_state);
        Py_Finalize();
    }
    sge_free(pyhttp);
    return SGE_OK;
}


struct sge_module_ops module_ops = {
    .init = pyhttp_init__,
    .destroy = pyhttp_destroy__,
    .handle = pyhttp_handle__
};
