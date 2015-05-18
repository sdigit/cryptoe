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
    uint64_t rdrand_arg;
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
        uint64_t i;
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
    uint64_t rdrand_arg;
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
        uint64_t i;
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
    uint64_t rdrand_arg;
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
SHA256(PyObject *self, PyObject *args)
{
    unsigned char digest[SHA256_DIGEST_SIZE];
    unsigned char *msg;
    Py_ssize_t len;
    PyObject *retval;

    if (!PyArg_ParseTuple(args, "z#", &msg, &len))
        return NULL;
    if (len > ULONG_MAX)
    {
        PyErr_NoMemory();
        return NULL;
    }
    memset(digest,0,SHA256_DIGEST_SIZE);
    sha256((const unsigned char *)msg,len,(unsigned char *)&digest);
    retval = PyString_FromStringAndSize((const char *)digest, SHA256_DIGEST_SIZE);
    memset(&digest,0,SHA256_DIGEST_SIZE);
    return retval;
}

static PyObject *
SHA384(PyObject *self, PyObject *args)
{
    unsigned char digest[SHA384_DIGEST_SIZE];
    unsigned char *msg;
    Py_ssize_t len;
    PyObject *retval;

    if (!PyArg_ParseTuple(args, "z#", &msg, &len))
        return NULL;
    if (len > ULONG_MAX)
    {
        PyErr_NoMemory();
        return NULL;
    }
    sha384((const unsigned char *)msg,len,(unsigned char *)&digest);
    retval = PyString_FromStringAndSize((const char *)digest, SHA384_DIGEST_SIZE);
    memset(&digest,0,SHA384_DIGEST_SIZE);
    return retval;
}

static PyObject *
SHA512(PyObject *self, PyObject *args)
{
    unsigned char digest[SHA512_DIGEST_SIZE];
    unsigned char *msg;
    Py_ssize_t len;
    PyObject *retval;

    if (!PyArg_ParseTuple(args, "z#", &msg, &len))
        return NULL;
    if (len > ULONG_MAX)
    {
        PyErr_NoMemory();
        return NULL;
    }
    sha512((const unsigned char *)msg,len,(unsigned char *)&digest);
    retval = PyString_FromStringAndSize((const char *)digest, SHA512_DIGEST_SIZE);
    memset(&digest,0,SHA512_DIGEST_SIZE);
    return retval;
}

/*
 * one-shot SHA2 HMAC routines
 */

static PyObject *
HMAC_SHA256(PyObject *self, PyObject *args)
{
    unsigned char mac[SHA256_DIGEST_SIZE];
    unsigned char *key, *msg;
    Py_ssize_t key_len, msg_len, mac_len;
    PyObject *retval;

    mac_len = -1;
    if (!PyArg_ParseTuple(args, "z#z#n", &key, &key_len, &msg, &msg_len, &mac_len))
        return NULL;

    if (key_len > SHA256_DIGEST_SIZE ||
        mac_len > SHA256_DIGEST_SIZE ||
        msg_len > ULONG_MAX ||
        mac_len <= 0)
    {
        PyErr_NoMemory();
        return NULL;
    }

    if (mac_len == -1)
        mac_len = SHA256_DIGEST_SIZE;

    hmac_sha256((const unsigned char *)key, key_len,
                (const unsigned char *)msg, msg_len,
                (unsigned char *)&mac, mac_len);
    retval = PyString_FromStringAndSize((const char *)mac, mac_len);
    memset(&mac,0,SHA256_DIGEST_SIZE);
    return retval;
}

static PyObject *
HMAC_SHA384(PyObject *self, PyObject *args)
{
    unsigned char mac[SHA384_DIGEST_SIZE];
    unsigned char *key, *msg;
    Py_ssize_t key_len, msg_len, mac_len;
    PyObject *retval;

    mac_len = -1;
    if (!PyArg_ParseTuple(args, "z#z#n", &key, &key_len, &msg, &msg_len, &mac_len))
        return NULL;

    if (key_len > SHA384_DIGEST_SIZE ||
        mac_len > SHA384_DIGEST_SIZE ||
        msg_len > ULONG_MAX ||
        mac_len <= 0)
    {
        PyErr_NoMemory();
        return NULL;
    }
    if (mac_len == -1)
        mac_len = SHA384_DIGEST_SIZE;

    hmac_sha384((const unsigned char *)key, key_len,
                (const unsigned char *)msg, msg_len,
                (unsigned char *)&mac, mac_len);
    retval = PyString_FromStringAndSize((const char *)mac, mac_len);
    memset(&mac,0,SHA384_DIGEST_SIZE);
    return retval;
}

static PyObject *
HMAC_SHA512(PyObject *self, PyObject *args)
{
    unsigned char mac[SHA512_DIGEST_SIZE];
    unsigned char *key, *msg;
    Py_ssize_t key_len, msg_len, mac_len;
    PyObject *retval;

    mac_len = -1;

    if (!PyArg_ParseTuple(args, "z#z#n", &key, &key_len, &msg, &msg_len, &mac_len))
        return NULL;

    if (key_len > SHA512_DIGEST_SIZE ||
        mac_len > SHA512_DIGEST_SIZE ||
        msg_len > ULONG_MAX ||
        mac_len <= 0)
    {
        PyErr_NoMemory();
        return NULL;
    }
    if (mac_len == -1)
        mac_len = SHA512_DIGEST_SIZE;

    hmac_sha512((const unsigned char *)key, key_len,
                (const unsigned char *)msg, msg_len,
                (unsigned char *)&mac, mac_len);
    retval = PyString_FromStringAndSize((const char *)mac, mac_len);
    memset(&mac,0,SHA512_DIGEST_SIZE);
    return retval;
}


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
    {"SHA256",
     SHA256,
     METH_VARARGS,
     "Return SHA-256 digest"},
    {"SHA384",
     SHA384,
     METH_VARARGS,
     "Return SHA-384 digest"},
    {"SHA512",
     SHA512,
     METH_VARARGS,
     "Return SHA-512 digest"},
    {"HMAC_SHA256",
     HMAC_SHA256,
     METH_VARARGS,
     "HMAC-SHA-256(k,m)"},
    {"HMAC_SHA384",
     HMAC_SHA384,
     METH_VARARGS,
     "HMAC-SHA-384(k,m)"},
    {"HMAC_SHA512",
     HMAC_SHA512,
     METH_VARARGS,
     "HMAC-SHA-512(k,m)"},
    {NULL,NULL,0,NULL}
};

PyMODINIT_FUNC
initcryptoe_ext(void)
{
    Py_InitModule("cryptoe_ext", cryptoe_ext_methods);
}

