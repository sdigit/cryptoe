#include <python2.7/Python.h>
#include "hmac_sha2.h"

static PyObject *rdrand32(PyObject *,PyObject *);
static PyObject *rdrand64(PyObject *,PyObject *);
static PyObject *rdrand_bytes(PyObject *,PyObject *);

static PyObject *rdrand32(PyObject *,PyObject *);
static PyObject *rdrand64(PyObject *,PyObject *);
static PyObject *rdrand_bytes(PyObject *,PyObject *);
static PyObject *hmac_sha2_224(PyObject *,PyObject *);
static PyObject *hmac_sha2_256(PyObject *,PyObject *);
static PyObject *hmac_sha2_384(PyObject *,PyObject *);
static PyObject *hmac_sha2_512(PyObject *,PyObject *);
static PyObject *sha2_sha224(PyObject *,PyObject *);
static PyObject *sha2_sha256(PyObject *,PyObject *);
static PyObject *sha2_sha384(PyObject *,PyObject *);
static PyObject *sha2_sha512(PyObject *,PyObject *);

