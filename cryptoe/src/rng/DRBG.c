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
# define PyString_CompareWithASCIIString(o,s) \
    (PyString_Check(o) ? strcmp(PyString_AsString(o),(s)) : -1)

#include <Python.h>
#include "rng/drbg_api.h"

typedef struct {
	PyObject_HEAD
	RBG rbg;
} DRBG;

staticforward PyTypeObject DRBGtype;

static DRBG *newDRBG(void);
static DRBG *DRBG_new(PyObject *,PyObject *);
static PyObject *DRBG_reseed(PyObject *,PyObject *);
static PyObject *DRBG_read(PyObject *,PyObject *);


static DRBG *
newDRBG(void)
{
	DRBG *r;
	r = PyObject_New(DRBG, &DRBGtype);
    RBG *rbg_tmp;
    rbg_tmp = drbg_new();
    memcpy(&r->rbg,rbg_tmp,sizeof(RBG));
    memset(rbg_tmp,0,sizeof(RBG));
    free(rbg_tmp);
	return r;
}

PyDoc_STRVAR(DRBG_reseed_doc,"reseeds the CTR_DRBG instance from additional data and OS-provided random");
PyDoc_STRVAR(DRBG_read_doc,"returns bytes from CTR_DRBG (AES)");
static struct PyMethodDef DRBG_OBJ_methods[] = {
    {"reseed", (PyCFunction)DRBG_reseed, METH_NOARGS, DRBG_reseed_doc},
    {"read", (PyCFunction)DRBG_read, METH_O, DRBG_read_doc},
	{NULL,			NULL}
};


static void
DRBG_dealloc(PyObject *ptr)
{
	DRBG *self = (DRBG *)ptr;
    drbg_destroy(&self->rbg);
	PyObject_Del(ptr);
}

static DRBG *
DRBG_new(PyObject *self, PyObject *args)
{
    DRBG *r;
    r = newDRBG();
	return r;
}

static PyObject *
DRBG_reseed(self,args)
    PyObject *self;
    PyObject *args;
{
    DRBG *dr;
    int ret;
    dr = (DRBG *)self;

    ret = drbg_reseed_ad(&dr->rbg);
    if (ret == -1)
    {
        PyErr_SetString(PyExc_OSError,"DRBG indicated a failure");
        return NULL;
    }
    RBG *r;
    r = (RBG *)&dr->rbg;
    PyObject *rval = PyLong_FromUnsignedLongLong(r->rbg_last_reseeded);
    return rval;
}

static PyObject *
DRBG_read(self,args)
    PyObject *self;
    PyObject *args;
{
    unsigned int len;

    if (!PyArg_Parse(args,"I",&len))
    {
        return NULL;
    }

    if (len < 1 || len > 524288)
    {
        PyErr_SetString(PyExc_ValueError,"Invalid length requested");
        return NULL;
    }

    int ret;
    DRBG *dr;
    char *buf;
    buf = malloc(len);
    if (buf == NULL)
    {
        PyErr_NoMemory();
        return NULL;
    }

    dr = (DRBG *)self;

    ret = drbg_generate(&dr->rbg, (uint8_t *)buf, len);
    if (ret == -1)
    {
        free(buf);
        PyErr_SetString(PyExc_OSError,"DRBG indicated a failure");
        return NULL;
    }
    PyObject *pbuf = PyBytes_FromStringAndSize(buf, len);
/*    memset(buf,0,len); */
    return pbuf;
}


static char DRBG_doc[] = "NIST SP800-90A based CTR_DRBG implementation using AES-128";
PyDoc_STRVAR(DRBG_new_doc,"Create a new DRBG state object");

static struct PyMethodDef DRBG_methods[] = {
	{"new", (PyCFunction)DRBG_new, METH_NOARGS, DRBG_new_doc},
	{NULL,			NULL}
};

PyMODINIT_FUNC
initDRBG(void)
{
	PyObject *m = NULL;
	PyObject *__all__ = NULL;

	if (PyType_Ready(&DRBGtype) < 0)
		goto errout;

    m = Py_InitModule3("cryptoe.Random.DRBG", DRBG_methods, DRBG_doc);
    if (m == NULL)
        goto errout;

    PyObject_SetAttrString(m, "DRBG", (PyObject *)&DRBGtype);
    __all__ = PyList_New(1);
    PyList_SetItem(__all__, 0, PyString_FromString("DRBG"));
    PyObject_SetAttrString(m, "__all__", __all__);

out:
	if (m == NULL && !PyErr_Occurred()) {
		PyErr_SetString(PyExc_ImportError, "can't initialize module");
		goto errout;
	}

	Py_CLEAR(__all__);

	return;

errout:
	Py_CLEAR(m);
	goto out;
}

static PyObject *
DRBG_getattro(PyObject *self, PyObject *attr)
{
	if (!PyString_Check(attr))
		goto generic;

	if (PyString_CompareWithASCIIString(attr, "name")==0)
		return PyString_FromString("DRBG");

  generic:
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	return PyObject_GenericGetAttr(self, attr);
#else
	if (PyString_Check(attr) < 0) {
		PyErr_SetObject(PyExc_AttributeError, attr);
		return NULL;
	}
	return Py_FindMethod(DRBG_OBJ_methods, (PyObject *)self, PyString_AsString(attr));
#endif
}

static PyTypeObject DRBGtype = {
	PyVarObject_HEAD_INIT(NULL, 0)  /* deferred type init for compilation on Windows, type will be filled in at runtime */
 	"DRBG",			/*tp_name*/
 	sizeof(DRBG),	/*tp_size*/
 	0,			/*tp_itemsize*/
 	/* methods */
	(destructor) DRBG_dealloc, /*tp_dealloc*/
 	0,			    /*tp_print*/
	0,			    /*tp_getattr*/
 	0,		    	/*tp_setattr*/
 	0,	    		/*tp_compare*/
 	0,  			/*tp_repr*/
    0,			    /*tp_as_number*/
	0,				/*tp_as_sequence */
	0,				/*tp_as_mapping */
	0,				/*tp_hash*/
	0,				/*tp_call*/
	0,				/*tp_str*/
	DRBG_getattro, 	/*tp_getattro*/
	0,				/*tp_setattro*/
	0,				/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,		/*tp_flags*/
	DRBG_doc,   	/*tp_doc*/
	0,				/*tp_traverse*/
	0,				/*tp_clear*/
	0,				/*tp_richcompare*/
	0,				/*tp_weaklistoffset*/
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	0,				/*tp_iter*/
	0,				/*tp_iternext*/
	DRBG_OBJ_methods,	/*tp_methods*/
#endif
};


