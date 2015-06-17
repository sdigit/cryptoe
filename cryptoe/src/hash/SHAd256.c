/*
 * An implementation of the SHAd256 hash function.
 *
 * Implemented per Schneier & Ferguson, Cryptography Engineering, section 5.4.2.
 *
 * Adapted by Sean Davis, dive@endersgame.net
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 *
 */

#include "SHAd256.h"
#include <string.h>

static uint8_t zero_block[64] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static char SHAd256_doc__[] =
    "SHA-256 cryptographic hash algorithm.\n"
    "\n"
    "SHA-256 belongs to the SHA-2_ family of cryptographic hashes.\n"
    "It produces the 256 bit digest of a message.\n"
    "\n"
    "    >>> from Crypto.Hash import SHA256\n"
    "    >>>\n"
    "    >>> h = SHA256.new()\n"
    "    >>> h.update(b'Hello')\n"
    "    >>> print h.hexdigest()\n"
    "\n"
    "*SHA* stands for Secure Hash Algorithm.\n"
    "\n"
    ".. _SHA-2: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf\n"
    "\n"
    ":Variables:\n"
    " block_size\n"
    "    The internal block size of the hash algorithm in bytes.\n"
    " digest_size\n"
    "    The size of the resulting hash in bytes.\n";

static char ALG_copy__doc__[] =
"copy()\n"
"Return a copy (\"clone\") of the hash object.\n"
"\n"
"The copy will have the same internal state as the original hash\n"
"object.\n"
"This can be used to efficiently compute the digests of strings that\n"
"share a common initial substring.\n"
"\n"
":Return: A hash object of the same type\n";

static char ALG_digest__doc__[] =
"digest()\n"
"Return the **binary** (non-printable) digest of the message that has been hashed so far.\n"
"\n"
"This method does not change the state of the hash object.\n"
"You can continue updating the object after calling this function.\n"
"\n"
":Return: A byte string of `digest_size` bytes. It may contain non-ASCII\n"
"characters, including null bytes.\n";

static char ALG_hexdigest__doc__[] =
"hexdigest()\n"
"Return the **printable** digest of the message that has been hashed so far.\n"
"\n"
"This method does not change the state of the hash object.\n"
"\n"
":Return: A string of 2* `digest_size` characters. It contains only\n"
"hexadecimal ASCII digits.\n";

static char ALG_update__doc__[] =
"update(data)\n"
"Continue hashing of a message by consuming the next chunk of data.\n"
"\n"
"Repeated calls are equivalent to a single call with the concatenation\n"
"of all the arguments. In other words:\n"
"\n"
"   >>> m.update(a); m.update(b)\n"
"\n"
"is equivalent to:\n"
"\n"
"   >>> m.update(a+b)\n"
"\n"
":Parameters:\n"
"  data : byte string\n"
"    The next chunk of the message being hashed.\n";

static char ALG_new__doc__[] =
"new(data=None)\n"
"Return a fresh instance of the hash object.\n"
"\n"
":Parameters:\n"
"   data : byte string\n"
"    The very first chunk of the message to hash.\n"
"    It is equivalent to an early call to `SHAd256.update()`.\n"
"    Optional.\n"
"\n"
":Return: A `SHAd256` object\n";


/* Initial Values H */
static const uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

/* the Constants K */
static const uint32_t K[SCHEDULE_SIZE] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA-256 specific functions */
#define Sigma0(x)    (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x)    (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define Gamma0(x)    (ROTR(x,  7) ^ ROTR(x, 18) ^ SHR(x,  3))
#define Gamma1(x)    (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* compress one block  */
static void sha_compress(hash_state * hs)
{
    uint32_t S[8], W[SCHEDULE_SIZE], T1, T2;
    int i;

    /* copy state into S */
    for (i = 0; i < 8; i++)
        S[i] = hs->state[i];

    /* copy the state into W[0..15] */
    for (i = 0; i < 16; i++){
        W[i] = (
            (((uint32_t) hs->buf[(WORD_SIZE*i)+0]) << (WORD_SIZE_BITS- 8)) |
            (((uint32_t) hs->buf[(WORD_SIZE*i)+1]) << (WORD_SIZE_BITS-16)) |
            (((uint32_t) hs->buf[(WORD_SIZE*i)+2]) << (WORD_SIZE_BITS-24)) |
            (((uint32_t) hs->buf[(WORD_SIZE*i)+3]) << (WORD_SIZE_BITS-32))
            );
    }

    /* fill W[16..SCHEDULE_SIZE] */
    for (i = 16; i < SCHEDULE_SIZE; i++)
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

    /* Compress */
    for (i = 0; i < SCHEDULE_SIZE; i++) {
        T1 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        T2 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + T1;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = T1 + T2;
    }

    /* feedback */
    for (i = 0; i < 8; i++)
        hs->state[i] += S[i];
}

/* adds *inc* to the length of the hash_state *hs*
 * return 1 on success
 * return 0 if the length overflows
 */
static int add_length(hash_state *hs, uint32_t inc) {
    uint32_t overflow_detector;
    overflow_detector = hs->length_lower;
    hs->length_lower += inc;
    if (overflow_detector > hs->length_lower) {
        overflow_detector = hs->length_upper;
        hs->length_upper++;
        if (hs->length_upper > hs->length_upper)
            return 0;
    }
    return 1;
}

/* init the SHA state */
static void sha_init(hash_state * hs)
{
    int i;
    hs->curlen = hs->length_upper = hs->length_lower = 0;
    for (i = 0; i < 8; ++i)
        hs->state[i] = H[i];
}

static void sha_process(hash_state * hs, unsigned char *buf, int len)
{
    while (len--) {
        /* copy byte */
        hs->buf[hs->curlen++] = *buf++;

        /* is a block full? */
        if (hs->curlen == BLOCK_SIZE) {
            sha_compress(hs);
            add_length(hs, BLOCK_SIZE_BITS);
            hs->curlen = 0;
        }
    }
}

static void sha_done(hash_state * hs, unsigned char *hash)
{
    int i;

    /* increase the length of the message */
    add_length(hs, hs->curlen * 8);

    /* append the '1' bit */
    hs->buf[hs->curlen++] = 0x80;

    /* if the length is currently above LAST_BLOCK_SIZE bytes we append
     * zeros then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (hs->curlen > LAST_BLOCK_SIZE) {
        for (; hs->curlen < BLOCK_SIZE;)
            hs->buf[hs->curlen++] = 0;
        sha_compress(hs);
        hs->curlen = 0;
    }

    /* pad upto LAST_BLOCK_SIZE bytes of zeroes */
    for (; hs->curlen < LAST_BLOCK_SIZE;)
        hs->buf[hs->curlen++] = 0;

    /* append length */
    for (i = 0; i < WORD_SIZE; i++)
        hs->buf[i + LAST_BLOCK_SIZE] =
            (hs->length_upper >> ((WORD_SIZE - 1 - i) * 8)) & 0xFF;
    for (i = 0; i < WORD_SIZE; i++)
        hs->buf[i + LAST_BLOCK_SIZE + WORD_SIZE] =
            (hs->length_lower >> ((WORD_SIZE - 1 - i) * 8)) & 0xFF;
    sha_compress(hs);

    /* copy output */
    for (i = 0; i < DIGEST_SIZE; i++)
        hash[i] = (hs->state[i / WORD_SIZE] >>
                   ((WORD_SIZE - 1 - (i % WORD_SIZE)) * 8)) & 0xFF;
}

// Done
static void hash_init (hash_state *ptr)
{
	sha_init(ptr);
    /*
     * FS&K - SHAd256(m) = SHA256(SHA256(0^512|m))
     * step 1: add in the block of zeroes
     */
    sha_process(ptr,(unsigned char *)zero_block, BLOCK_SIZE);
}

// Done
static void
hash_update (hash_state *self, const uint8_t *buf, int len)
{
	sha_process(self,(unsigned char *)buf, len);
}

// Done
static void
hash_copy(hash_state *src, hash_state *dest)
{
	memcpy(dest,src,sizeof(hash_state));
}

// Done
static PyObject *
hash_digest (const hash_state *self)
{
	unsigned char digest[DIGEST_SIZE];
	hash_state inner; /* ordinary SHA2-256 */
    hash_state outer; /* SHA-256(SHA-256(0^512 | m)) */

	hash_copy((hash_state*)self,&inner);
	sha_done(&inner,digest);

    sha_init(&outer);
    sha_process(&outer,(unsigned char *)digest, DIGEST_SIZE);
    memset(digest,0,DIGEST_SIZE);
    sha_done(&outer, digest);
    memset(&outer,0,sizeof(hash_state));

	return PyBytes_FromStringAndSize((char *)digest, DIGEST_SIZE);
}

typedef struct {
	PyObject_HEAD
	hash_state st;
} ALGobject;

/*
 * Please see PEP3123 for a discussion of PyObject_HEAD and changes made in 3.x
 * to make it conform to Standard C.
 * These changes also dictate using Py_TYPE to check type, and
 * PyVarObject_HEAD_INIT(NULL, 0) to initialize
 */
staticforward PyTypeObject ALGtype;

static char ALG__doc__[] =
"Class that implements a SHAd256 hash.";

static ALGobject *
newALGobject(void)
{
	ALGobject *new;

	new = PyObject_New(ALGobject, &ALGtype);
	return new;
}

/* Internal methods for a hashing object */

static void
ALG_dealloc(PyObject *ptr)
{
	ALGobject *self = (ALGobject *)ptr;

	/* Overwrite the contents of the object */
	memset((char*)&(self->st), 0, sizeof(hash_state));
	PyObject_Del(ptr);
}


/* External methods for a hashing object */

static PyObject *
ALG_copy(ALGobject *self, PyObject *args)
{
	ALGobject *newobj;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

	if ( (newobj = newALGobject())==NULL)
		return NULL;

	hash_copy(&(self->st), &(newobj->st));
	return((PyObject *)newobj);
}

static PyObject *
ALG_digest(ALGobject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	return (PyObject *)hash_digest(&(self->st));
}

static PyObject *
ALG_hexdigest(ALGobject *self, PyObject *args)
{
	PyObject *value, *retval;
	unsigned char *raw_digest, *hex_digest;
	int i, j, size;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	/* Get the raw (binary) digest value */
	value = (PyObject *)hash_digest(&(self->st));
	size = PyBytes_Size(value);
	raw_digest = (unsigned char *) PyBytes_AsString(value);

	/* Create a new string */
	retval = PyBytes_FromStringAndSize(NULL, size * 2 );
	hex_digest = (unsigned char *) PyBytes_AsString(retval);

	/* Make hex version of the digest */
	for(i=j=0; i<size; i++)
	{
		char c;
		c = raw_digest[i] / 16; c = (c>9) ? c+'a'-10 : c + '0';
		hex_digest[j++] = c;
		c = raw_digest[i] % 16; c = (c>9) ? c+'a'-10 : c + '0';
		hex_digest[j++] = c;
	}

	Py_DECREF(value);
	return retval;
}

static PyObject *
ALG_update(ALGobject *self, PyObject *args)
{
	unsigned char *cp;
	int len;

	if (!PyArg_ParseTuple(args, "s#", &cp, &len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS;

	hash_update(&(self->st), cp, len);
	Py_END_ALLOW_THREADS;

	Py_INCREF(Py_None);

	return Py_None;
}

/** Forward declaration for this module's new() method **/
static PyObject *ALG_new(PyObject*, PyObject*);

static PyMethodDef ALG_methods[] = {
	{"copy", (PyCFunction)ALG_copy, METH_VARARGS, ALG_copy__doc__},
	{"digest", (PyCFunction)ALG_digest, METH_VARARGS, ALG_digest__doc__},
	{"hexdigest", (PyCFunction)ALG_hexdigest, METH_VARARGS, ALG_hexdigest__doc__},
	{"update", (PyCFunction)ALG_update, METH_VARARGS, ALG_update__doc__},
	{"new", (PyCFunction)ALG_new, METH_VARARGS, ALG_new__doc__},
	{NULL,			NULL}		/* sentinel */
};

static PyObject *
ALG_getattro(PyObject *self, PyObject *attr)
{
	if (!PyString_Check(attr))
		goto generic;

	if (PyString_CompareWithASCIIString(attr, "digest_size")==0)
		return PyInt_FromLong(DIGEST_SIZE);
	if (PyString_CompareWithASCIIString(attr, "name")==0)
		return PyString_FromString("SHAd256");

  generic:
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	return PyObject_GenericGetAttr(self, attr);
#else
	if (PyString_Check(attr) < 0) {
		PyErr_SetObject(PyExc_AttributeError, attr);
		return NULL;
	}
	return Py_FindMethod(ALG_methods, (PyObject *)self, PyString_AsString(attr));
#endif
}

static PyTypeObject ALGtype = {
	PyVarObject_HEAD_INIT(NULL, 0)  /* deferred type init for compilation on Windows, type will be filled in at runtime */
 	"SHAd256",			/*tp_name*/
 	sizeof(ALGobject),	/*tp_size*/
 	0,			/*tp_itemsize*/
 	/* methods */
	(destructor) ALG_dealloc, /*tp_dealloc*/
 	0,			/*tp_print*/
	0,			/*tp_getattr*/
 	0,			/*tp_setattr*/
 	0,			/*tp_compare*/
 	0,			/*tp_repr*/
    0,			/*tp_as_number*/
	0,				/*tp_as_sequence */
	0,				/*tp_as_mapping */
	0,				/*tp_hash*/
	0,				/*tp_call*/
	0,				/*tp_str*/
	ALG_getattro,	/*tp_getattro*/
	0,				/*tp_setattro*/
	0,				/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,		/*tp_flags*/
	ALG__doc__,	/*tp_doc*/
	0,				/*tp_traverse*/
	0,				/*tp_clear*/
	0,				/*tp_richcompare*/
	0,				/*tp_weaklistoffset*/
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	0,				/*tp_iter*/
	0,				/*tp_iternext*/
	ALG_methods,		/*tp_methods*/
#endif
 };

/* The single module-level function: new() */

/** This method belong to both the module and the hash object **/
static PyObject *
ALG_new(PyObject *self, PyObject *args)
{
        ALGobject *new;
	unsigned char *cp = NULL;
	int len;

	if ((new = newALGobject()) == NULL)
		return NULL;

	if (!PyArg_ParseTuple(args, "|s#",
			      &cp, &len)) {
	        Py_DECREF(new);
		return NULL;
	}

        hash_init(&(new->st));

	if (PyErr_Occurred()) {
		Py_DECREF(new);
		return NULL;
	}
	if (cp) {
		Py_BEGIN_ALLOW_THREADS;
		hash_update(&(new->st), cp, len);
		Py_END_ALLOW_THREADS;
	}

	return (PyObject *)new;
}

/* List of functions exported by this module */

static struct PyMethodDef ALG_functions[] = {
	{"new", (PyCFunction)ALG_new, METH_VARARGS, ALG_new__doc__},
	{NULL,			NULL}		 /* Sentinel */
};


/* Initialize this module. */

PyMODINIT_FUNC
initSHAd256 (void)
{
	PyObject *m = NULL;
	PyObject *__all__ = NULL;

	if (PyType_Ready(&ALGtype) < 0)
		goto errout;

	/* Create the module and add the functions */
	m = Py_InitModule3("cryptoe.Hash.SHAd256", ALG_functions, SHAd256_doc__);
	if (m == NULL)
		goto errout;

	/* Add the type object to the module (using the name of the module itself),
	 * so that its methods docstrings are discoverable by introspection tools. */
	PyObject_SetAttrString(m, "SHAd256", (PyObject *)&ALGtype);

	/* Add some symbolic constants to the module */
	PyModule_AddIntConstant(m, "digest_size", DIGEST_SIZE);
	PyModule_AddIntConstant(m, "block_size", BLOCK_SIZE);

	/* Create __all__ (to help generate documentation) */
	__all__ = PyList_New(4);
	if (__all__ == NULL)
		goto errout;
	PyList_SetItem(__all__, 0, PyString_FromString("SHAd256"));	/* This is the ALGType object */
	PyList_SetItem(__all__, 1, PyString_FromString("new"));
	PyList_SetItem(__all__, 2, PyString_FromString("digest_size"));
	PyList_SetItem(__all__, 3, PyString_FromString("block_size"));
	PyObject_SetAttrString(m, "__all__", __all__);

out:
	/* Final error check, then return */
	if (m == NULL && !PyErr_Occurred()) {
		PyErr_SetString(PyExc_ImportError, "can't initialize module");
		goto errout;
	}

	/* Free local objects here */
	Py_CLEAR(__all__);

	/* Return */
	return;

errout:
	/* Free the module and other global objects here */
	Py_CLEAR(m);
	goto out;
}

