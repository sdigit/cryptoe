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
#include <inttypes.h>
#include "cryptoe.h"
#include "rdrand.h"

/*
 * RDRAND
 */
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
 * Methods implemented by cryptoe for export to Python
 */
static PyMethodDef cryptoe_ext_methods[] = {
    {"rdrand_64",
     rdrand64,METH_VARARGS,
     "Return 64-bit integers from RDRAND"},
    {"rdrand_bytes",
     rdrand_bytes,
     METH_VARARGS,
     "Return random bytes"},
    {NULL,NULL,0,NULL}
};

PyMODINIT_FUNC
initcryptoe_ext(void)
{
    Py_InitModule("cryptoe_ext", cryptoe_ext_methods);
}

