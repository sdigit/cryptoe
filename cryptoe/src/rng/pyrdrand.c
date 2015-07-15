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
#include "rng/rdrand.h"

static PyObject *rdrand64(PyObject *, PyObject *);
static PyObject *rdrand_bytes(PyObject *, PyObject *);

/*
 * RDRAND
 */
PyDoc_STRVAR(rdrand64_doc,"rdrand_64(num): return num random 64-bit numbers\n");
static PyObject *
rdrand64(self,args)
    PyObject *self;
    PyObject *args;
{
    unsigned int rdrand_arg;
    if (!PyArg_ParseTuple(args, "I", &rdrand_arg))
        return NULL;

    uint64_t *data;
    data = malloc(sizeof(uint64_t) * rdrand_arg);
    if (data == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    int rdrand_ret;
    rdrand_ret = rdrand_get_n_64(rdrand_arg, data);
    if (rdrand_ret == RDRAND_NOT_READY)
    {
        free(data);
        PyErr_SetString(PyExc_RuntimeError, "RDRAND failure");
        return NULL;
    }
    else if (rdrand_ret == RDRAND_SUCCESS)
    {
        PyObject *retval;
        uint64_t i;
        retval = PyTuple_New(rdrand_arg);
        for (i=0;i<rdrand_arg;i++)
        {
            PyObject *item;
            item = PyInt_FromLong(data[i]);
            PyTuple_SetItem(retval,i,item);
        }
        free(data);
        return retval;
    } else {
        free(data);
        PyErr_SetString(PyExc_RuntimeError, "RDRAND failure");
        return NULL;
    }
}

PyDoc_STRVAR(rdrandbytes_doc,"rdrand_bytes(num): return num random bytes\n");
static PyObject *
rdrand_bytes(self,args)
    PyObject *self;
    PyObject *args;
{
    unsigned int rdrand_arg;
    if (!PyArg_ParseTuple(args, "I", &rdrand_arg))
        return NULL;

    unsigned char *buf;
    buf = malloc(rdrand_arg);
    if (buf == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    int rdrand_ret;
    rdrand_ret = rdrand_get_bytes(rdrand_arg, buf);
    if (rdrand_ret == RDRAND_NOT_READY)
    {
        memset(buf,0,rdrand_arg);
        free(buf);
        PyErr_SetString(PyExc_RuntimeError, "RDRAND failure");
        return NULL;
    }
    else if (rdrand_ret == RDRAND_SUCCESS)
    {
        PyObject *retval;
        retval = PyBytes_FromStringAndSize((const char *)buf, rdrand_arg);
        memset(buf,0,rdrand_arg);
        free(buf);
        return retval;
    }
    else
    {
        memset(buf,0,rdrand_arg);
        free(buf);
        PyErr_SetString(PyExc_RuntimeError, "RDRAND failure");
        return NULL;
    }
}

PyDoc_STRVAR(
    RDRAND_doc,
    "Intel RDRAND Random Number Generator\n"
    "\n"
    "The following description comes from:\n"
    "Intel(r) 64 and IA-32 Architectures Software Developer's Manual\n"
    "Combined Volumes: 1, 2A, 2B, 2C, 3A, 3B and 3C\n"
    "\n"
    "RDRAND returns random numbers that are supplied by a cryptographically secure,\n"
    "deterministic random bit generator DRBG. The DRBG is designed to meet the NIST\n"
    "SP 800-90A standard. The DRBG is re-seeded frequently from an on-chip\n"
    "non-deterministic entropy source to guarantee data returned by RDRAND is\n"
    "statistically uniform, non-periodic and non-deterministic.\n"
    "\n"
    "In order for the hardware design to meet its security goals, the random number\n"
    "generator continuously tests itself and the random data it is generating.\n"
    "Runtime failures in the random number generator circuitry or statistically\n"
    "anomalous data occurring by chance will be detected by the self test hardware\n"
    "and flag the resulting data as being bad. In such extremely rare cases, the\n"
    "RDRAND instruction will return no data instead of bad data.\n"
    "\n"
    "    >>> from Cryptoe.Hardware import RDRAND\n"
    "    >>>\n"
    "    >>> rand_int = RDRAND.rdrand_64(num)\n"
    "    >>> rand_bytes = RDRAND.rdrand_bytes(num)\n"
    "\n"
    "rdrand_64 will return the specified number of random 64-bit values.\n"
    "\n"
    "rdrand_bytes will return the specified number of random bytes.\n"
    "\n");

/*
 * Methods implemented by cryptoe for export to Python
 */
static PyMethodDef RDRAND_methods[] = {
    {"rdrand_64",
     rdrand64,METH_VARARGS,
     rdrand64_doc},
    {"rdrand_bytes",
     rdrand_bytes,
     METH_VARARGS,
     rdrandbytes_doc},
    {NULL,NULL,0,NULL}
};

PyMODINIT_FUNC
initRDRAND(void)
{
    if (! RdRand_isSupported())
        PyErr_SetString(PyExc_NotImplementedError,"RDRAND is not supported on this machine");
    Py_InitModule3("cryptoe.Hardware.RDRAND", RDRAND_methods, RDRAND_doc);
}
