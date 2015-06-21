#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <unistd.h>
#include <keyutils.h>
#include <errno.h>

#define KDB_TYPE_KEYRING    "keyring"
#define KDB_TYPE_USER       "user"
#define KDB_MAX_DESC        64
#define KDB_MAX_KEY         512
#define KDB_DESC_PREFIX     "cryptoe|"
#define KDB_PREFIX_LEN      9
#define KDB_DESC_BUFSIZE     1024

static PyObject *new_keyring(PyObject *,PyObject *);
static PyObject *destroy_keyring(PyObject *,PyObject *);
static PyObject *find_keyring(PyObject *,PyObject *);
static PyObject *store_key(PyObject *,PyObject *);

static int prefix_desc(ssize_t,const char *);

static char desc_buffer[KDB_DESC_BUFSIZE];

int
prefix_desc(len,str)
    ssize_t len;
    const char *str;
{
    size_t i, end;

    end = 0;

    for (i=0;i<len;i++)
    {
        if (str[i] == '\0')
        {
            end = i;
            break;
        }
    }
    if ((KDB_PREFIX_LEN+end+1) >= KDB_DESC_BUFSIZE)
    {
        return -1;
    }

    memset(desc_buffer,0,KDB_DESC_BUFSIZE);
    strlcpy(desc_buffer,KDB_DESC_PREFIX,KDB_DESC_BUFSIZE);
    strlcat(desc_buffer,str,KDB_DESC_BUFSIZE);
    return 0;
}

static PyObject *
new_keyring(self,args)
    PyObject *self;
    PyObject *args;
{
    const char *desc;
    Py_ssize_t dlen;
    long rv;
    key_serial_t ks;
    key_perm_t kp;
    kp = KEY_USR_VIEW;
    kp |= KEY_USR_READ;
    kp |= KEY_USR_WRITE;
    kp |= KEY_USR_LINK;
    kp |= KEY_USR_SEARCH;

    if (!PyArg_ParseTuple(args, "s#", &desc, &dlen))
        return NULL;
    if (prefix_desc(dlen,desc) != 0)
    {
        PyErr_SetString(PyExc_MemoryError,"unable to prefix description");
        return NULL;
    }
    ks = keyctl(KEYCTL_SEARCH,KEY_SPEC_USER_KEYRING,KDB_TYPE_KEYRING,desc_buffer,0);
    if (ks != -1)
    {
        PyErr_SetString(PyExc_ValueError,"keyring exists");
        return NULL;
    }

    ks = add_key(KDB_TYPE_KEYRING,desc_buffer,NULL,0,KEY_SPEC_USER_KEYRING);
    if (ks == -1)
    {
        PyErr_SetString(PyExc_OSError,"key creation failed");
        return NULL;
    }

    rv = keyctl(KEYCTL_SETPERM,ks,kp);
    if (rv == -1)
    {
        rv = keyctl_invalidate(ks);
        if (rv == 0)
        {
            PyErr_SetString(PyExc_OSError,"failed to set key permissions");
            return NULL;
        }
        else
        {
            PyErr_SetString(PyExc_OSError,"failed to invalidate key after failing to set permissions");
            return NULL;
        }
    }

    PyObject *key_serial;
    key_serial = PyInt_FromLong(ks);
    return key_serial;
}

static PyObject *
find_keyring(self,args)
    PyObject *self;
    PyObject *args;
{
    const char *desc;
    Py_ssize_t dlen;
    if (!PyArg_ParseTuple(args, "s#", &desc, &dlen))
        return NULL;
    if (prefix_desc(dlen,desc) != 0)
    {
        PyErr_SetString(PyExc_MemoryError,"unable to prefix description");
        return NULL;
    }

    key_serial_t kr_serial;
    PyObject *keyring;

    kr_serial = keyctl(KEYCTL_SEARCH,
                       KEY_SPEC_USER_KEYRING,
                       KDB_TYPE_KEYRING,
                       desc_buffer,
                       0);
    keyring = PyInt_FromLong(kr_serial);
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
        rv = keyctl_invalidate(ks);
    }

    PyObject *ret;
    ret = PyInt_FromLong(rv);
    return ret;
}

static PyObject *
store_key(self,args)
    PyObject *self;
    PyObject *args;
{
    char *desc, *key;
    long rv;
    Py_ssize_t dlen, klen;
    key_serial_t kr, ks;
    key_perm_t kp;

    kp = KEY_USR_VIEW;
    kp |= KEY_USR_READ;
    kp |= KEY_USR_SEARCH;
    kp |= KEY_USR_WRITE;

    if (!PyArg_ParseTuple(args, "ls#s#", &kr,&desc,&dlen,&key,&klen))
        return NULL;

    if (prefix_desc(dlen,desc) != 0)
    {
        PyErr_SetString(PyExc_MemoryError,"unable to prefix description");
        return NULL;
    }

    if (dlen > KDB_MAX_DESC)
    {
        PyErr_SetString(PyExc_ValueError,"description exceeds maximum length");
        return NULL;
    }
    else if (klen > KDB_MAX_KEY)
    {
        PyErr_SetString(PyExc_ValueError,"key exceeds maximum length");
        return NULL;
    }

    rv = keyctl(KEYCTL_READ,kr,NULL,0);
    if (rv == -1)
    {
        PyErr_SetString(PyExc_LookupError,"KEYCTL_READ failed");
        return NULL;
    }

    ks = add_key(KDB_TYPE_USER,desc_buffer,key,klen,kr);
    if (ks == -1)
    {
        PyErr_SetString(PyExc_IOError,"key creation failed");
        return NULL;
    }

    rv = keyctl(KEYCTL_SETPERM,ks,kp);
    if (rv == -1)
    {
        rv = keyctl_invalidate(ks);
        kp = KEY_USR_VIEW;
        kp |= KEY_USR_READ;
        kp |= KEY_USR_SEARCH;
        if (rv == 0)
        {
            PyErr_SetString(PyExc_OSError,"failed to set key permissions");
            return NULL;
        }
        else
        {
            PyErr_SetString(PyExc_OSError,"failed to invalidate key after failing to set permissions");
            return NULL;
        }
    }

    PyObject *ret;
    ret = PyInt_FromLong(ks);
    return ret;
}
    
static PyMethodDef KernelKeyUtil_methods[] = {
    {"new_keyring",
     new_keyring,
     METH_VARARGS,
     "new_keyring(name)\n"
     "Create a keyring, returning the serial number"},
    {"destroy_keyring",
     destroy_keyring,
     METH_VARARGS,
     "destroy_keyring(keyring_serial)\n"
     "Destroy the specified keyring (first clear and then invalidate it)\n"},
    {"find_keyring",
     find_keyring,
     METH_VARARGS,
     "find_keyring(name)\n"
     "Find the named keyring, returning its serial number"},
    {"store_key",
     store_key,
     METH_VARARGS,
    "store_key(keyring serial,description,key)\n"
    "Store a key in the specified keyring\n"},
    {"read_key(key serial)",
     store_key,
     METH_VARARGS,
    "store_key(keyring serial,description,key)\n"
    "Store a key in the specified keyring\n"},
    {NULL,NULL,0,NULL}
};

PyMODINIT_FUNC
initKernelKeyUtil(void)
{
    Py_InitModule("KernelKeyUtil", KernelKeyUtil_methods);
}
