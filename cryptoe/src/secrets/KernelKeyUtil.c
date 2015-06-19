#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <keyutils.h>
#include <errno.h>

#define KDB_TYPE_KEYRING    "keyring"
#define KDB_TYPE_USER       "user"

static PyObject *new_keyring(PyObject *,PyObject *);
static PyObject *destroy_keyring(PyObject *,PyObject *);
static PyObject *find_keyring(PyObject *,PyObject *);

static PyObject *
new_keyring(self,args)
    PyObject *self;
    PyObject *args;
{
    const char *desc;
    long rv;
    key_serial_t ks;
    key_perm_t kp;
    kp = KEY_USR_VIEW;
    kp |= KEY_USR_READ;
    kp |= KEY_USR_WRITE;
    kp |= KEY_USR_LINK;
    kp |= KEY_USR_SEARCH;

    if (!PyArg_ParseTuple(args, "s", &desc))
        return NULL;

    ks = keyctl(KEYCTL_SEARCH,KEY_SPEC_USER_KEYRING,"keyring",desc,0);
    if (ks != -1)
    {
        ks = add_key(KDB_TYPE_KEYRING,desc,NULL,0,KEY_SPEC_USER_KEYRING);
        if (ks != -1)
        {
            rv = keyctl(KEYCTL_SETPERM,ks,kp);
            if (rv == -1)
            {
                keyctl_revoke(ks);
                ks = -1;
            }
        }
    }
    if (ks == -1)
    {
        PyErr_SetString(PyExc_IOError,"key creation failed");
        return NULL;
    }
    PyObject *key_serial;
    key_serial = PyLong_FromLong(ks);
    return key_serial;
}

static PyObject *
find_keyring(self,args)
    PyObject *self;
    PyObject *args;
{
    const char *desc;
    if (!PyArg_ParseTuple(args, "s", &desc))
        return NULL;

    key_serial_t kr_serial;
    PyObject *keyring;

    kr_serial = keyctl(KEYCTL_SEARCH,KEY_SPEC_USER_KEYRING,"keyring",desc,0);
    keyring = PyLong_FromLong(kr_serial);
    return keyring;
}

static PyObject *
destroy_keyring(self,args)
    PyObject *self;
    PyObject *args;
{
    key_serial_t ks;
    long rv = 0;
    if (!PyArg_ParseTuple(args, "l", &ks))
        return NULL;
    rv = keyctl(KEYCTL_CLEAR,ks);
    if (rv == 0)
    {
        rv = keyctl(KEYCTL_INVALIDATE,ks);
    }
    PyObject *ret;
    ret = PyLong_FromLong(rv);
    return ret;
}


static PyMethodDef KernelKeyUtil_methods[] = {
    {"new_keyring",
     new_keyring,
     METH_VARARGS,
     "Create a keyring, returning the serial number"},
    {"destroy_keyring",
     destroy_keyring,
     METH_VARARGS,
     "Destroy the specified keyring (first clear and then invalidate it)"},
    {"find_keyring",
     find_keyring,
     METH_VARARGS,
     "Find the named keyring, returning its serial number"},
    {NULL,NULL,0,NULL}
};

PyMODINIT_FUNC
initKernelKeyUtil(void)
{
    Py_InitModule("KernelKeyUtil", KernelKeyUtil_methods);
}
