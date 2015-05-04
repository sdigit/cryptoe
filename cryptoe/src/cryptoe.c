/*
 * Copyright (c) 2015 Sean Davis <dive@endersgame.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS `AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define PY_SSIZE_T_CLEAN /* proper types are nice */

#include <Python.h>
#include <structmember.h>
#include <inttypes.h>
#include <limits.h>
#include <immintrin.h> /* AVX please */

#include "include/hmac_sha2.h"
#include "include/rdrand.h"

/*
 * RDRAND code
 */
static PyObject *
rdrand32(PyObject *self, PyObject *args)
{
    PyObject *item;
    unsigned int rdrand_arg;
    int rdrand_ret;
    uint32_t *data;

    if (!PyArg_ParseTuple(args, "I", &rdrand_arg))
        return NULL;

    data = (uint32_t *)malloc(sizeof(uint32_t) * rdrand_arg);
    if (data == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    rdrand_ret = rdrand_get_n_32(rdrand_arg, data);
    if (rdrand_ret == RDRAND_NOT_READY)
    {
        free(data);
        PyErr_NoMemory();
        return NULL;
    }
    else if (rdrand_ret == RDRAND_SUCCESS)
    {
        PyObject *retval;
        retval = PyTuple_New(rdrand_arg);
        unsigned int i;
        for (i=0;i<rdrand_arg;i++)
        {
            item = PyLong_FromUnsignedLong(data[i]);
            PyTuple_SetItem(retval,i,item);
        }
        free(data);
        return retval;
    } else {
        free(data);
        return NULL;
    }
}

static PyObject *
rdrand64(PyObject *self, PyObject *args)
{
    PyObject *item;
    unsigned int rdrand_arg;
    int rdrand_ret;
    uint64_t *data;

    if (!PyArg_ParseTuple(args, "I", &rdrand_arg))
        return NULL;

    data = (uint64_t *)malloc(sizeof(uint64_t) * rdrand_arg);
    if (data == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    rdrand_ret = rdrand_get_n_64(rdrand_arg, data);
    if (rdrand_ret == RDRAND_NOT_READY)
    {
        free(data);
        PyErr_NoMemory();
        return NULL;
    }
    else if (rdrand_ret == RDRAND_SUCCESS)
    {
        PyObject *retval;
        unsigned int i;
        retval = PyTuple_New(rdrand_arg);
        for (i=0;i<rdrand_arg;i++)
        {
            item = PyLong_FromUnsignedLongLong(data[i]);
            PyTuple_SetItem(retval,i,item);
        }
        free(data);
        return retval;
    } else {
        free(data);
        return NULL;
    }
}

static PyObject *
rdrand_bytes(PyObject *self, PyObject *args)
{
    unsigned int rdrand_arg;
    int rdrand_ret;
    unsigned char *buf;

    if (!PyArg_ParseTuple(args, "I", &rdrand_arg))
        return NULL;

    buf = (unsigned char *)malloc(rdrand_arg);
    if (buf == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    rdrand_ret = rdrand_get_bytes(rdrand_arg, buf);
    if (rdrand_ret == RDRAND_NOT_READY)
    {
        free(buf);
        PyErr_NoMemory();
        return NULL;
    }
    else if (rdrand_ret == RDRAND_SUCCESS)
    {
        PyObject *retval;
        retval = PyString_FromStringAndSize((const char *)buf, rdrand_arg);
        free(buf);
        return retval;
    } else {
        free(buf);
        return NULL;
    }
}

/*
 * SHA2 code
 */
static PyObject *
sha2_256(PyObject *self, PyObject *args)
{
    unsigned char *msg, *digest;
    Py_ssize_t len;
    PyObject *retval;

    Py_BEGIN_ALLOW_THREADS
    if (!PyArg_ParseTuple(args, "s#", &msg, &len))
        return NULL;
    if (len > UINT_MAX)
    {
        PyErr_NoMemory();
        return NULL;
    }
    digest = (unsigned char *)malloc(SHA256_DIGEST_SIZE);
    if (digest == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }
    sha256(msg,len,digest);
    retval = PyString_FromStringAndSize((const char *)digest, SHA256_DIGEST_SIZE);
    memset(digest,0,SHA256_DIGEST_SIZE);
    free(digest);
    Py_END_ALLOW_THREADS
    return retval;
}

static PyObject *
sha2_384(PyObject *self, PyObject *args)
{
    unsigned char *msg, *digest;
    Py_ssize_t len;
    PyObject *retval;

    Py_BEGIN_ALLOW_THREADS
    if (!PyArg_ParseTuple(args, "s#", &msg, &len))
        return NULL;
    if (len > UINT_MAX)
    {
        PyErr_NoMemory();
        return NULL;
    }
    digest = (unsigned char *)malloc(SHA384_DIGEST_SIZE);
    if (digest == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }
    sha384(msg,len,digest);
    retval = PyString_FromStringAndSize((const char *)digest, SHA384_DIGEST_SIZE);
    memset(digest,0,SHA384_DIGEST_SIZE);
    free(digest);
    Py_END_ALLOW_THREADS
    return retval;
}

static PyObject *
sha2_512(PyObject *self, PyObject *args)
{
    unsigned char *msg, *digest;
    Py_ssize_t len;
    PyObject *retval;

    Py_BEGIN_ALLOW_THREADS
    if (!PyArg_ParseTuple(args, "s#", &msg, &len))
        return NULL;
    if (len > UINT_MAX)
    {
        PyErr_NoMemory();
        return NULL;
    }
    digest = (unsigned char *)malloc(SHA512_DIGEST_SIZE);
    if (digest == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }
    sha512(msg,len,digest);
    retval = PyString_FromStringAndSize((const char *)digest, SHA512_DIGEST_SIZE);
    memset(digest,0,SHA512_DIGEST_SIZE);
    free(digest);
    Py_END_ALLOW_THREADS
    return retval;
}

#if 0
typedef struct {
    PyObject_HEAD
    hmac_sha256_ctx ctx;
} HMAC_SHA2_256_CTX;

typedef struct {
    PyObject_HEAD
    hmac_sha384_ctx ctx;
} HMAC_SHA2_384_CTX;

typedef struct {
    PyObject_HEAD
    hmac_sha512_ctx ctx;
} HMAC_SHA2_512_CTX;

/*
 * destructors
 */
static void
HMAC_SHA2_256_CTX_dealloc(HMAC_SHA2_256_CTX *self)
{
    memset(&self->ctx,0,sizeof(hmac_sha256_ctx));
    self->ob_type->tp_free((PyObject*)self);
}

static void
HMAC_SHA2_384_CTX_dealloc(HMAC_SHA2_384_CTX *self)
{
    memset(&self->ctx,0,sizeof(hmac_sha384_ctx));
    self->ob_type->tp_free((PyObject*)self);
}

static void
HMAC_SHA2_512_CTX_dealloc(HMAC_SHA2_512_CTX *self)
{
    memset(&self->ctx,0,sizeof(hmac_sha512_ctx));
    self->ob_type->tp_free((PyObject*)self);
}

/*
 * constructors
 */
static PyObject *
HMAC_SHA2_256_CTX_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HMAC_SHA2_256_CTX *self;

    self = (HMAC_SHA2_256_CTX *)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        memset(&self->ctx,0,sizeof(hmac_sha256_ctx));
    }

    return (PyObject *)self;
}

static PyObject *
HMAC_SHA2_384_CTX_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HMAC_SHA2_384_CTX *self;

    self = (HMAC_SHA2_384_CTX *)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        memset(&self->ctx,0,sizeof(hmac_sha384_ctx));
    }

    return (PyObject *)self;
}

static PyObject *
HMAC_SHA2_512_CTX_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HMAC_SHA2_512_CTX *self;

    self = (HMAC_SHA2_512_CTX *)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        memset(&self->ctx,0,sizeof(hmac_sha512_ctx));
    }

    return (PyObject *)self;
}

/*
 * Initialization routines
 */
PyMODINIT_FUNC
HMAC_SHA2_256_CTX_init(void)
{
    PyObject* m;

    HMAC_SHA2_256_CTX_Type.tp_new = PyType_GenericNew;
    if (PyType_Ready(&HMAC_SHA2_256_CTX_Type) < 0)
        return;

    m = Py_InitModule3("HMAC_SHA2_256", HMAC_CTX_METHODS,
                       "HMAC_SHA2_256 Context");

    Py_INCREF(&HMAC_SHA2_256_CTX_Type);
    PyModule_AddObject(m, "HMAC_SHA2_256", (PyObject *)&HMAC_SHA2_256_CTX_Type);
}

static PyTypeObject HMAC_SHA2_256_CTX_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "crypto_ext.HMAC_SHA2_256_CTX",           /* tp_name */
    sizeof(HMAC_SHA2_256_CTX),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)HMAC_SHA2_256_CTX_dealloc,    /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
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
    "HMAC_SHA2_256_CTX for internal context", /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)HMAC_SHA2_256_CTX_init,         /* tp_init */
    0,                                        /* tp_alloc */
    HMAC_SHA2_256_CTX_new,                    /* tp_new */
};

PyMODINIT_FUNC
HMAC_SHA2_384_CTX_init(void)
{
    PyObject* m;

    HMAC_SHA2_384_CTX_Type.tp_new = PyType_GenericNew;
    if (PyType_Ready(&HMAC_SHA2_384_CTX_Type) < 0)
        return;

    m = Py_InitModule3("HMAC_SHA2_384", HMAC_CTX_METHODS,
                       "HMAC_SHA2_384 Context");

    Py_INCREF(&HMAC_SHA2_384_CTX_Type);
    PyModule_AddObject(m, "HMAC_SHA2_384", (PyObject *)&HMAC_SHA2_384_CTX_Type);
}

static PyTypeObject HMAC_SHA2_384_CTX_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "crypto_ext.HMAC_SHA2_384_CTX",           /* tp_name */
    sizeof(HMAC_SHA2_384_CTX),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)HMAC_SHA2_384_CTX_dealloc,    /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
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
    "HMAC_SHA2_384_CTX for internal context", /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)HMAC_SHA2_384_CTX_init,         /* tp_init */
    0,                                        /* tp_alloc */
    HMAC_SHA2_384_CTX_new,                    /* tp_new */
};

PyMODINIT_FUNC
HMAC_SHA2_512_CTX_init(void)
{
    PyObject* m;

    HMAC_SHA2_512_CTX_Type.tp_new = PyType_GenericNew;
    if (PyType_Ready(&HMAC_SHA2_512_CTX_Type) < 0)
        return;

    m = Py_InitModule3("HMAC_SHA2_512", HMAC_CTX_METHODS,
                       "HMAC_SHA2_512 Context");

    Py_INCREF(&HMAC_SHA2_512_CTX_Type);
    PyModule_AddObject(m, "HMAC_SHA2_512", (PyObject *)&HMAC_SHA2_512_CTX_Type);
}

static PyTypeObject HMAC_SHA2_512_CTX_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "crypto_ext.HMAC_SHA2_512_CTX",           /* tp_name */
    sizeof(HMAC_SHA2_512_CTX),                /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor)HMAC_SHA2_512_CTX_dealloc,    /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
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
    "HMAC_SHA2_512_CTX for internal context", /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)HMAC_SHA2_512_CTX_init,         /* tp_init */
    0,                                        /* tp_alloc */
    HMAC_SHA2_512_CTX_new,                    /* tp_new */
};
#endif /* (#if 0): HMAC code is not yet ready */

/*
 * Methods implemented by cryptoe for export to Python
 */
static PyMethodDef cryptoe_ext_methods[] = {
    {"rdrand_32",
     rdrand32,METH_VARARGS,
     "Return 32-bit integers from RDRAND"},
    {"rdrand_64",
     rdrand64,METH_VARARGS,
     "Return 64-bit integers from RDRAND"},
    {"rdrand_bytes",
     rdrand_bytes,
     METH_VARARGS,
     "Return random bytes"},
    {"sha2_256",
     sha2_256,METH_VARARGS,
     "Return SHA2-256 digest"},
    {"sha2_384",
     sha2_384,METH_VARARGS,
     "Return SHA2-384 digest"},
    {"sha2_512",
     sha2_512,
     METH_VARARGS,
     "Return SHA2-512 digest"},
    {NULL,NULL,0,NULL}
};

PyMODINIT_FUNC
initcryptoe_ext(void)
{
    Py_InitModule("cryptoe_ext", cryptoe_ext_methods);
}

