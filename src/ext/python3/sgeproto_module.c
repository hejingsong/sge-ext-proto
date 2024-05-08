#include <Python.h>

#include "protocol.h"

typedef struct {
    PyObject_HEAD;
    struct sge_proto *proto;
} PySgeProto;

static PyTypeObject PyProto_Type;

static int _get(const void *ud, const struct sge_key *k, struct sge_value *v) {
    PyObject *obj = (PyObject *)ud;
    PyObject *val = NULL;
    long long n = 0;
    const char *s = NULL;
    Py_ssize_t len = 0;

    val = PyDict_GetItemString(obj, (const char *)k->name.s);
    if (k->t & (~FIELD_TYPE_LIST) && k->t & FIELD_TYPE_LIST) {
        val = PyList_GET_ITEM(val, k->idx);
    }

    if (NULL == val) {
        sge_value_nil(v);
        return SGE_OK;
    }

    if (PyLong_Check(val)) {
        sge_value_integer(v, PyLong_AS_LONG(val));
    } else if (PyUnicode_Check(val)) {
        s = PyUnicode_AsUTF8AndSize(val, &len);
        sge_value_string_with_len(v, (const unsigned char *)s, len);
    } else if (PyBytes_Check(val)) {
        PyBytes_AsStringAndSize(val, (char **)&s, &len);
        sge_value_string_with_len(v, (const unsigned char *)s, len);
    } else if (PyList_Check(val)) {
        n = PyList_GET_SIZE(val);
        sge_value_integer(v, n);
    } else if (PyDict_Check(val)) {
        sge_value_any(v, val);
    } else {
        sge_value_nil(v);
        return SGE_ERROR;
    }

    return SGE_OK;
}

static void *_set(void *ud, const struct sge_key *k, const struct sge_value *v) {
    int t = v->t & (~FIELD_TYPE_LIST);
    void *ret = ud;
    PyObject *val = NULL;
    PyObject *obj = (PyObject *)ud;

    if (!t) {
        t = FIELD_TYPE_LIST;
    }

    switch (t) {
    case FIELD_TYPE_INTEGER:
        val = PyLong_FromLongLong(v->v.i);
        break;

    case FIELD_TYPE_STRING:
        val = PyUnicode_FromStringAndSize((const char *)v->v.s.s, v->v.s.l);
        break;

    case FIELD_TYPE_UNKNOWN:
        val = Py_None;
        Py_INCREF(Py_None);
        break;

    case FIELD_TYPE_CUSTOM:
        val = PyDict_New();
        ret = val;
        break;

    case FIELD_TYPE_LIST:
        val = PyList_New(v->v.i);
        ret = val;
        break;
    }

    if (NULL == val) {
        return NULL;
    }

    if (k->t & (~FIELD_TYPE_LIST) && k->t & FIELD_TYPE_LIST) {
        Py_INCREF(val);
        PyList_SET_ITEM(obj, k->idx, val);
    } else {
        PyDict_SetItemString(obj, (const char *)k->name.s, val);
    }

    Py_DECREF(val);
    return ret;
}

static PyObject *_encode(PyObject *self, PyObject *args) {
    int err_code = 0;
    PyObject *ud = NULL;
    PyObject *proto_name = NULL;
    PyObject *ret = NULL;
    PySgeProto *proto = NULL;
    const char *s_proto_name = NULL;
    const char *err = NULL;
    uint8_t buffer[1024];
    size_t buffer_len = 0;

    if (!PyArg_ParseTuple(args, "UO", &proto_name, &ud)) {
        PyErr_Format(PyExc_TypeError, "args 1 must be str. args 2 must be dict");
        Py_RETURN_NONE;
    }

    if (!PyUnicode_Check(proto_name)) {
        PyErr_Format(PyExc_TypeError, "args 1 must be str");
        Py_RETURN_NONE;
    }
    if (!PyDict_Check(ud)) {
        PyErr_Format(PyExc_TypeError, "args 2 must be dict");
        Py_RETURN_NONE;
    }

    Py_INCREF(self);
    Py_INCREF(ud);
    Py_INCREF(proto_name);

    proto = (PySgeProto *)self;
    s_proto_name = PyUnicode_AsUTF8(proto_name);
    err_code = sge_encode_protocol(proto->proto, s_proto_name, ud, _get, buffer, &buffer_len);
    if (SGE_OK != err_code) {
        err_code = sge_protocol_error(proto->proto, &err);
        PyErr_Format(PyExc_RuntimeError, "encode error(%d), msg(%s).", err_code, err);
        goto out;
    }

    ret = PyBytes_FromStringAndSize((const char *)buffer, buffer_len);
out:
    Py_DECREF(self);
    Py_DECREF(ud);
    Py_DECREF(proto_name);

    return ret;
}

static PyObject *_decode(PyObject *self, PyObject *buffer) {
    int err_code = 0;
    char *s = NULL;
    const char *err = NULL;
    Py_ssize_t len = 0;
    PyObject *obj = NULL;
    PySgeProto *proto = NULL;

    if (!PyBytes_Check(buffer)) {
        PyErr_Format(PyExc_TypeError, "args 1 must be bytes.");
        Py_RETURN_NONE;
    }

    Py_INCREF(self);
    Py_INCREF(buffer);

    PyBytes_AsStringAndSize(buffer, &s, &len);
    obj = PyDict_New();
    if (obj == NULL) {
        PyErr_NoMemory();
        goto out;
    }

    proto = (PySgeProto *)self;
    if (SGE_OK != sge_decode_protocol(proto->proto, (uint8_t *)s, len, obj, _set)) {
        err_code = sge_protocol_error(proto->proto, &err);
        PyErr_Format(PyExc_RuntimeError, "decode error(%d). msg(%s).", err_code, err);
        Py_DECREF(obj);
        obj = NULL;
    }

out:
    Py_DECREF(self);
    Py_DECREF(buffer);

    return obj;
}

static PyObject *_debug(PyObject *self, PyObject *args) {
    PySgeProto *proto = NULL;

    if (self->ob_type != &PyProto_Type) {
        PyErr_Format(PyExc_TypeError, "args 1 must be SgeProto.Proto.");
        Py_RETURN_NONE;
    }

    Py_INCREF(self);
    Py_XINCREF(args);

    proto = (PySgeProto *)self;
    sge_print_protocol(proto->proto);

    Py_DECREF(self);
    Py_XDECREF(args);

    Py_RETURN_NONE;
}

static void _dealloc(PySgeProto *o) {
    sge_destroy_protocol(o->proto);
    PyObject_Del(o);
}

static PyObject *_encode_service(PyObject *self, PyObject *args, int encode_type) {
    int err_code = 0;
    PyObject *ud = NULL;
    PyObject *service = NULL, *method = NULL;
    PyObject *ret = NULL;
    PySgeProto *proto = NULL;
    const char *service_name = NULL, *method_name = NULL;
    const char *err = NULL;
    uint8_t buffer[1024];
    size_t buffer_len = 0;

    if (!PyArg_ParseTuple(args, "UUO", &service, &method, &ud)) {
        PyErr_Format(PyExc_TypeError, "args 1/2 must be str. args 3 must be dict");
        Py_RETURN_NONE;
    }

    if (!PyUnicode_Check(service)) {
        PyErr_Format(PyExc_TypeError, "args 1 must be str");
        Py_RETURN_NONE;
    }
    if (!PyUnicode_Check(method)) {
        PyErr_Format(PyExc_TypeError, "args 2 must be str");
        Py_RETURN_NONE;
    }
    if (!PyDict_Check(ud)) {
        PyErr_Format(PyExc_TypeError, "args 3 must be dict");
        Py_RETURN_NONE;
    }

    Py_INCREF(self);
    Py_INCREF(ud);
    Py_INCREF(service);
    Py_INCREF(method);

    proto = (PySgeProto *)self;
    service_name = PyUnicode_AsUTF8(service);
    method_name = PyUnicode_AsUTF8(method);
    err_code = sge_rpc_encode(proto->proto, (const unsigned char *)service_name,
                              (const unsigned char *)method_name, ud, _get, encode_type, buffer,
                              &buffer_len);
    if (SGE_OK != err_code) {
        err_code = sge_protocol_error(proto->proto, &err);
        PyErr_Format(PyExc_RuntimeError, "encode error(%d), msg(%s).", err_code, err);
        goto out;
    }

    ret = PyBytes_FromStringAndSize((const char *)buffer, buffer_len);
out:
    Py_DECREF(self);
    Py_DECREF(ud);
    Py_DECREF(service);
    Py_DECREF(method);

    return ret;
}

static PyObject *_encodeRequest(PyObject *self, PyObject *args) {
    return _encode_service(self, args, ENCODE_TYPE_REQUEST);
}

static PyObject *_encodeResponse(PyObject *self, PyObject *args) {
    return _encode_service(self, args, ENCODE_TYPE_RESPONSE);
}

static PyObject *_decodeService(PyObject *self, PyObject *buffer) {
    int err_code = 0;
    char *s = NULL;
    const char *err = NULL;
    Py_ssize_t len = 0;
    PyObject *obj = NULL;
    PySgeProto *proto = NULL;
    unsigned char service[64];
    unsigned char method[64];

    if (!PyBytes_Check(buffer)) {
        PyErr_Format(PyExc_TypeError, "args 1 must be bytes.");
        Py_RETURN_NONE;
    }

    Py_INCREF(self);
    Py_INCREF(buffer);

    PyBytes_AsStringAndSize(buffer, &s, &len);
    obj = PyDict_New();
    if (obj == NULL) {
        PyErr_NoMemory();
        goto out;
    }

    proto = (PySgeProto *)self;
    if (SGE_OK != sge_rpc_decode(proto->proto, (uint8_t *)s, len, obj, _set, service, method)) {
        err_code = sge_protocol_error(proto->proto, &err);
        PyErr_Format(PyExc_RuntimeError, "decode error(%d). msg(%s).", err_code, err);
        Py_DECREF(obj);
        obj = NULL;
    }

out:
    Py_DECREF(self);
    Py_DECREF(buffer);

    if (NULL == obj) {
        Py_RETURN_NONE;
    }

    PyObject *result = PyDict_New();
    PyDict_SetItemString(result, "service", PyUnicode_FromString((const char *)service));
    PyDict_SetItemString(result, "method", PyUnicode_FromString((const char *)method));
    PyDict_SetItemString(result, "result", obj);
    return result;
}

PyDoc_STRVAR(sge_proto_doc,
             "dict() -> new empty dictionary\n"
             "dict(mapping) -> new dictionary initialized from a mapping object's\n"
             "    (key, value) pairs\n"
             "dict(iterable) -> new dictionary initialized as if via:\n"
             "    d = {}\n"
             "    for k, v in iterable:\n"
             "        d[k] = v\n"
             "dict(**kwargs) -> new dictionary initialized with the name=value pairs\n"
             "    in the keyword argument list.  For example:  dict(one=1, two=2)");

static PyMethodDef methods[] = {
    {"encode", _encode, METH_VARARGS, "sge protocol encode"},
    {"decode", _decode, METH_O, "sge protocol decode"},
    {"encodeRequest", _encodeRequest, METH_VARARGS, "sge protocol encode request"},
    {"encodeResponse", _encodeResponse, METH_VARARGS, "sge protocol encode response"},
    {"decodeService", _decodeService, METH_O, "sge protocol decode service"},
    {"debug", _debug, METH_NOARGS, "print proto structure"},
    {NULL, NULL}};

static PyTypeObject PyProto_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "SgeProto.Proto",
    sizeof(PySgeProto),
    0,
    (destructor)_dealloc,                     /* tp_dealloc */
    0,                                        /* tp_vectorcall_offset */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_as_async */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    sge_proto_doc,                            /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    methods,                                  /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
    PyObject_Del,                             /* tp_free */
};

static PyObject *_parse(PyObject *self, PyObject *buffer) {
    int ret = 0;
    Py_ssize_t len = 0;
    const char *bufp = NULL, *err = NULL;
    struct sge_proto *proto = NULL;
    PyObject *obj = NULL;
    PySgeProto *proto_obj = NULL;

    if (!PyUnicode_Check(buffer)) {
        PyErr_Format(PyExc_TypeError, "only accept str object");
        Py_RETURN_NONE;
    }

    Py_INCREF(self);
    Py_INCREF(buffer);

    bufp = PyUnicode_AsUTF8AndSize(buffer, &len);
    proto = sge_parse_protocol(bufp, len);
    if (NULL == proto) {
        PyErr_NoMemory();
        goto out;
    }
    ret = sge_protocol_error(proto, &err);
    if (SGE_OK != ret) {
        PyErr_Format(PyExc_RuntimeError, err);
        sge_destroy_protocol(proto);
        goto out;
    }

    obj = PyObject_MALLOC(sizeof(PySgeProto));
    if (!obj) {
        PyErr_NoMemory();
        sge_destroy_protocol(proto);
        goto out;
    }

    proto_obj = (PySgeProto *)PyObject_INIT(obj, &PyProto_Type);
    proto_obj->proto = proto;

out:
    Py_DECREF(self);
    Py_DECREF(buffer);

    return obj;
}

static PyObject *_parseFile(PyObject *self, PyObject *file) {
    int ret = 0;
    const char *filename = NULL, *err = NULL;
    struct sge_proto *proto = NULL;
    PyObject *obj = NULL;
    PySgeProto *proto_obj = NULL;

    if (!PyUnicode_Check(file)) {
        PyErr_Format(PyExc_TypeError, "only accept str object");
        Py_RETURN_FALSE;
    }

    Py_INCREF(self);
    Py_INCREF(file);

    filename = PyUnicode_AsUTF8(file);
    proto = sge_parse_protocol_file(filename);
    if (NULL == proto) {
        PyErr_NoMemory();
        goto out;
    }

    ret = sge_protocol_error(proto, &err);
    if (0 != ret) {
        PyErr_Format(PyExc_RuntimeError, err);
        sge_destroy_protocol(proto);
        goto out;
    }

    obj = PyObject_MALLOC(sizeof(PySgeProto));
    if (!obj) {
        PyErr_NoMemory();
        sge_destroy_protocol(proto);
        goto out;
    }

    proto_obj = (PySgeProto *)PyObject_INIT(obj, &PyProto_Type);
    proto_obj->proto = proto;

out:
    Py_DECREF(self);
    Py_DECREF(file);

    return obj;
}

static PyMethodDef sgeProtoMethods[] = {
    {"parse", _parse, METH_O, "sg protocol parse from string buffer"},
    {"parseFile", _parseFile, METH_O, "sg protocol parse from file"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef sgeProtoModule = {PyModuleDef_HEAD_INIT, "SgeProto",
                                            "Python interface for SgeProto", -1, sgeProtoMethods};

PyMODINIT_FUNC PyInit_SgeProto(void) {
    PyObject *module = NULL;

    module = PyModule_Create(&sgeProtoModule);
    if (NULL == module) {
        return NULL;
    }

    if (PyModule_AddType(module, &PyProto_Type)) {
        return NULL;
    }

    return module;
}
