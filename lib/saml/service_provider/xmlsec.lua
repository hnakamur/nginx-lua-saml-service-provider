-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local ffi = require("ffi")
local C = ffi.C
local xml2 = ffi.load("xml2")
local xmlsec1 = ffi.load("xmlsec1")
local xmlsec1openssl = ffi.load("xmlsec1-openssl")
local bit = require "bit"
local bor = bit.bor

local _M = {}

ffi.cdef[[

typedef struct {
    const char *data;
    int len;
    int pos;
} xsdReadContext, *xsdReadContextPtr;

typedef struct {
    int len;
    const char *buf;
} handleErrUserData, *handleErrUserDataxPtr;

typedef signed long time_t;

//-------------------------------------------------------
// ctype.h
//-------------------------------------------------------

int isspace(int c);

//-------------------------------------------------------
// string.h
//-------------------------------------------------------

size_t strlen(const char *s);
char *basename(const char *filename);

//-------------------------------------------------------
// typedef and constants from libxml2 2.9.4
//-------------------------------------------------------

typedef unsigned char xmlChar;

typedef enum {
    XML_ELEMENT_NODE=           1,
    XML_ATTRIBUTE_NODE=         2,
    XML_TEXT_NODE=              3,
    XML_CDATA_SECTION_NODE=     4,
    XML_ENTITY_REF_NODE=        5,
    XML_ENTITY_NODE=            6,
    XML_PI_NODE=                7,
    XML_COMMENT_NODE=           8,
    XML_DOCUMENT_NODE=          9,
    XML_DOCUMENT_TYPE_NODE=     10,
    XML_DOCUMENT_FRAG_NODE=     11,
    XML_NOTATION_NODE=          12,
    XML_HTML_DOCUMENT_NODE=     13,
    XML_DTD_NODE=               14,
    XML_ELEMENT_DECL=           15,
    XML_ATTRIBUTE_DECL=         16,
    XML_ENTITY_DECL=            17,
    XML_NAMESPACE_DECL=         18,
    XML_XINCLUDE_START=         19,
    XML_XINCLUDE_END=           20
/* #ifdef LIBXML_DOCB_ENABLED */
   ,XML_DOCB_DOCUMENT_NODE=     21
/* #endif */
} xmlElementType;

typedef enum {
    XML_ELEMENT_TYPE_UNDEFINED = 0,
    XML_ELEMENT_TYPE_EMPTY = 1,
    XML_ELEMENT_TYPE_ANY,
    XML_ELEMENT_TYPE_MIXED,
    XML_ELEMENT_TYPE_ELEMENT
} xmlElementTypeVal;

typedef xmlElementType xmlNsType;

typedef struct _xmlNs xmlNs;
typedef xmlNs *xmlNsPtr;
struct _xmlNs {
    struct _xmlNs  *next;       /* next Ns link for this node  */
    xmlNsType      type;        /* global or local */
    const xmlChar *href;        /* URL for the namespace */
    const xmlChar *prefix;      /* prefix for the namespace */
    void           *_private;   /* application data */
    struct _xmlDoc *context;    /* normally an xmlDoc */
};

typedef enum {
    XML_ATTRIBUTE_CDATA = 1,
    XML_ATTRIBUTE_ID,
    XML_ATTRIBUTE_IDREF ,
    XML_ATTRIBUTE_IDREFS,
    XML_ATTRIBUTE_ENTITY,
    XML_ATTRIBUTE_ENTITIES,
    XML_ATTRIBUTE_NMTOKEN,
    XML_ATTRIBUTE_NMTOKENS,
    XML_ATTRIBUTE_ENUMERATION,
    XML_ATTRIBUTE_NOTATION
} xmlAttributeType;

typedef enum {
    XML_ATTRIBUTE_NONE = 1,
    XML_ATTRIBUTE_REQUIRED,
    XML_ATTRIBUTE_IMPLIED,
    XML_ATTRIBUTE_FIXED
} xmlAttributeDefault;

typedef struct _xmlEnumeration xmlEnumeration;
typedef xmlEnumeration *xmlEnumerationPtr;
struct _xmlEnumeration {
    struct _xmlEnumeration    *next;    /* next one */
    const xmlChar            *name;     /* Enumeration name */
};

typedef struct _xmlAttribute xmlAttribute;
typedef xmlAttribute *xmlAttributePtr;
struct _xmlAttribute {
    void           *_private;           /* application data */
    xmlElementType          type;       /* XML_ATTRIBUTE_DECL, must be second ! */
    const xmlChar          *name;       /* Attribute name */
    struct _xmlNode    *children;       /* NULL */
    struct _xmlNode        *last;       /* NULL */
    struct _xmlDtd       *parent;       /* -> DTD */
    struct _xmlNode        *next;       /* next sibling link  */
    struct _xmlNode        *prev;       /* previous sibling link  */
    struct _xmlDoc          *doc;       /* the containing document */

    struct _xmlAttribute  *nexth;       /* next in hash table */
    xmlAttributeType       atype;       /* The attribute type */
    xmlAttributeDefault      def;       /* the default */
    const xmlChar  *defaultValue;       /* or the default value */
    xmlEnumerationPtr       tree;       /* or the enumeration tree if any */
    const xmlChar        *prefix;       /* the namespace prefix if any */
    const xmlChar          *elem;       /* Element holding the attribute */
};

typedef enum {
    XML_ELEMENT_CONTENT_PCDATA = 1,
    XML_ELEMENT_CONTENT_ELEMENT,
    XML_ELEMENT_CONTENT_SEQ,
    XML_ELEMENT_CONTENT_OR
} xmlElementContentType;

typedef enum {
    XML_ELEMENT_CONTENT_ONCE = 1,
    XML_ELEMENT_CONTENT_OPT,
    XML_ELEMENT_CONTENT_MULT,
    XML_ELEMENT_CONTENT_PLUS
} xmlElementContentOccur;

typedef struct _xmlElementContent xmlElementContent;
typedef xmlElementContent *xmlElementContentPtr;
struct _xmlElementContent {
    xmlElementContentType     type;     /* PCDATA, ELEMENT, SEQ or OR */
    xmlElementContentOccur    ocur;     /* ONCE, OPT, MULT or PLUS */
    const xmlChar             *name;    /* Element name */
    struct _xmlElementContent *c1;      /* first child */
    struct _xmlElementContent *c2;      /* second child */
    struct _xmlElementContent *parent;  /* parent */
    const xmlChar             *prefix;  /* Namespace prefix */
};

typedef struct _xmlElement xmlElement;
typedef xmlElement *xmlElementPtr;
struct _xmlElement {
    void           *_private;           /* application data */
    xmlElementType          type;       /* XML_ELEMENT_DECL, must be second ! */
    const xmlChar          *name;       /* Element name */
    struct _xmlNode    *children;       /* NULL */
    struct _xmlNode        *last;       /* NULL */
    struct _xmlDtd       *parent;       /* -> DTD */
    struct _xmlNode        *next;       /* next sibling link  */
    struct _xmlNode        *prev;       /* previous sibling link  */
    struct _xmlDoc          *doc;       /* the containing document */

    xmlElementTypeVal      etype;       /* The type */
    xmlElementContentPtr content;       /* the allowed element content */
    xmlAttributePtr   attributes;       /* List of the declared attributes */
    const xmlChar        *prefix;       /* the namespace prefix if any */
// NOTE: I'm lazy here to add typedef for xmlRegexpPtr.
//       It's OK because the xmlRegexpPtr and void*
//       has the same size and I don't access these fields in this module.
// #ifdef LIBXML_REGEXP_ENABLED
//    xmlRegexpPtr       contModel;        /* the validating regexp */
// #else
    void              *contModel;
// #endif
};

typedef struct _xmlAttr xmlAttr;
typedef xmlAttr *xmlAttrPtr;
struct _xmlAttr {
    void           *_private;   /* application data */
    xmlElementType   type;      /* XML_ATTRIBUTE_NODE, must be second ! */
    const xmlChar   *name;      /* the name of the property */
    struct _xmlNode *children;  /* the value of the property */
    struct _xmlNode *last;      /* NULL */
    struct _xmlNode *parent;    /* child->parent link */
    struct _xmlAttr *next;      /* next sibling link  */
    struct _xmlAttr *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* the containing document */
    xmlNs           *ns;        /* pointer to the associated namespace */
    xmlAttributeType atype;     /* the attribute type if validating */
    void            *psvi;      /* for type/PSVI informations */
};

typedef struct _xmlID xmlID;
typedef xmlID *xmlIDPtr;
struct _xmlID {
    struct _xmlID    *next;     /* next ID */
    const xmlChar    *value;    /* The ID name */
    xmlAttrPtr        attr;     /* The attribute holding it */
    const xmlChar    *name;     /* The attribute if attr is not available */
    int               lineno;   /* The line number if attr is not available */
    struct _xmlDoc   *doc;      /* The document holding the ID */
};

typedef struct _xmlNode xmlNode;
typedef xmlNode *xmlNodePtr;
struct _xmlNode {
    void           *_private;   /* application data */
    xmlElementType   type;      /* type number, must be second ! */
    const xmlChar   *name;      /* the name of the node, or the entity */
    struct _xmlNode *children;  /* parent->childs link */
    struct _xmlNode *last;      /* last child link */
    struct _xmlNode *parent;    /* child->parent link */
    struct _xmlNode *next;      /* next sibling link  */
    struct _xmlNode *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* the containing document */

    /* End of common part */
    xmlNs           *ns;        /* pointer to the associated namespace */
    xmlChar         *content;   /* the content */
    struct _xmlAttr *properties;/* properties list */
    xmlNs           *nsDef;     /* namespace definitions on this node */
    void            *psvi;      /* for type/PSVI informations */
    unsigned short   line;      /* line number */
    unsigned short   extra;     /* extra data for XPath/XSLT */
};

typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;
struct _xmlDoc {
    void           *_private;   /* application data */
    xmlElementType  type;       /* XML_DOCUMENT_NODE, must be second ! */
    char           *name;       /* name/filename/URI of the document */
    struct _xmlNode *children;  /* the document tree */
    struct _xmlNode *last;      /* last child link */
    struct _xmlNode *parent;    /* child->parent link */
    struct _xmlNode *next;      /* next sibling link  */
    struct _xmlNode *prev;      /* previous sibling link  */
    struct _xmlDoc  *doc;       /* autoreference to itself */

    /* End of common part */
    int             compression;/* level of zlib compression */
    int             standalone; /* standalone document (no external refs)
                                     1 if standalone="yes"
                                     0 if standalone="no"
                                    -1 if there is no XML declaration
                                    -2 if there is an XML declaration, but no
                                        standalone attribute was specified */
    struct _xmlDtd  *intSubset; /* the document internal subset */
    struct _xmlDtd  *extSubset; /* the document external subset */
    struct _xmlNs   *oldNs;     /* Global namespace, the old way */
    const xmlChar  *version;    /* the XML version string */
    const xmlChar  *encoding;   /* external initial encoding, if any */
    void           *ids;        /* Hash table for ID attributes if any */
    void           *refs;       /* Hash table for IDREFs attributes if any */
    const xmlChar  *URL;        /* The URI for that document */
    int             charset;    /* encoding of the in-memory content
                                   actually an xmlCharEncoding */
    struct _xmlDict *dict;      /* dict used to allocate names or NULL */
    void           *psvi;       /* for type/PSVI informations */
    int             parseFlags; /* set of xmlParserOption used to parse the
                                   document */
    int             properties; /* set of xmlDocProperties for this document
                                   set at the end of parsing */
};


// #ifndef LIBXML_ATTR_FORMAT
// # if ((__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 3)))
// #  define LIBXML_ATTR_FORMAT(fmt,args) __attribute__((__format__(__printf__,fmt,args)))
// # else
// #  define LIBXML_ATTR_FORMAT(fmt,args)
// # endif
// #else
// # define LIBXML_ATTR_FORMAT(fmt,args)
// #endif

typedef void (/* XMLCDECL */ *xmlValidityErrorFunc) (void *ctx,
                             const char *msg,
                             ...) /* LIBXML_ATTR_FORMAT(2,3) */;

typedef void (/* XMLCDECL */ *xmlValidityWarningFunc) (void *ctx,
                               const char *msg,
                               ...) /* LIBXML_ATTR_FORMAT(2,3) */;

typedef struct _xmlValidState xmlValidState;

typedef struct _xmlValidCtxt xmlValidCtxt;
typedef xmlValidCtxt *xmlValidCtxtPtr;
struct _xmlValidCtxt {
    void *userData;                     /* user specific data block */
    xmlValidityErrorFunc error;         /* the callback in case of errors */
    xmlValidityWarningFunc warning;     /* the callback in case of warning */

    /* Node analysis stack used when validating within entities */
    xmlNodePtr         node;          /* Current parsed Node */
    int                nodeNr;        /* Depth of the parsing stack */
    int                nodeMax;       /* Max depth of the parsing stack */
    xmlNodePtr        *nodeTab;       /* array of nodes */

    unsigned int     finishDtd;       /* finished validating the Dtd ? */
    xmlDocPtr              doc;       /* the document */
    int                  valid;       /* temporary validity check result */

    /* state state used for non-determinist content validation */
    xmlValidState     *vstate;        /* current state */
    int                vstateNr;      /* Depth of the validation stack */
    int                vstateMax;     /* Max depth of the validation stack */
    xmlValidState     *vstateTab;     /* array of validation states */

// NOTE: I'm lazy here to add typedef for xmlAutomataPtr and xmlAutomataStatePtr.
//       It's OK because the xmlAutomataPtr, xmlAutomataStatePtr, and void*
//       has the same size and I don't access these fields in this module.
// #ifdef LIBXML_REGEXP_ENABLED
//  xmlAutomataPtr            am;   /* the automata */
//  xmlAutomataStatePtr    state;   /* used to build the automata */
// #else
    void                     *am;
    void                  *state;
// #endif
};

void xmlInitParser(void);
void xmlCleanupParser(void);

xmlNodePtr xmlDocGetRootElement(const xmlDoc *doc);
xmlDocPtr xmlParseDoc(const xmlChar *cur);

int xmlStrEqual              (const xmlChar *str1,
                              const xmlChar *str2);

xmlChar * xmlNodeListGetString    (xmlDocPtr doc,
                                   const xmlNode *list,
                                   int inLine);
xmlAttrPtr xmlGetID               (xmlDocPtr doc,
                                   const xmlChar *ID);

xmlIDPtr   xmlAddID               (xmlValidCtxtPtr ctxt,
                                   xmlDocPtr doc,
                                   const xmlChar *value,
                                   xmlAttrPtr attr);

typedef void (/* XMLCALL */ *xmlFreeFunc)(void *mem);

/* xmlFreeFunc *__xmlFree(void); */
/* #define xmlFree \
(*(__xmlFree()))
*/
xmlFreeFunc xmlFree;

/* XMLPUBFUN */ void /* XMLCALL */
		xmlDocDumpMemory	(xmlDocPtr cur,
					         xmlChar **mem,
					         int *size);

//------------
// xmlerror.h
//------------

/**
 * xmlErrorLevel:
 *
 * Indicates the level of an error
 */
typedef enum {
    XML_ERR_NONE = 0,
    XML_ERR_WARNING = 1,	/* A simple warning */
    XML_ERR_ERROR = 2,		/* A recoverable error */
    XML_ERR_FATAL = 3		/* A fatal error */
} xmlErrorLevel;

/**
 * xmlError:
 *
 * An XML Error instance.
 */

typedef struct _xmlError xmlError;
typedef xmlError *xmlErrorPtr;
struct _xmlError {
    int		domain;	/* What part of the library raised this error */
    int		code;	/* The error code, e.g. an xmlParserError */
    char       *message;/* human-readable informative error message */
    xmlErrorLevel level;/* how consequent is the error */
    char       *file;	/* the filename */
    int		line;	/* the line number if available */
    char       *str1;	/* extra string information */
    char       *str2;	/* extra string information */
    char       *str3;	/* extra string information */
    int		int1;	/* extra number information */
    int		int2;	/* error column # or 0 if N/A (todo: rename field when we would brk ABI) */
    void       *ctxt;   /* the parser context if available */
    void       *node;   /* the node in the tree */
};

/**
 * xmlStructuredErrorFunc:
 * @userData:  user provided data for the error callback
 * @error:  the error being raised.
 *
 * Signature of the function to use when there is an error and
 * the module handles the new error reporting mechanism.
 */
typedef void (/* XMLCALL */ *xmlStructuredErrorFunc) (void *userData, xmlErrorPtr error);

/* XMLPUBFUN */ void /* XMLCALL */
    xmlSetStructuredErrorFunc	(void *ctx,
				 xmlStructuredErrorFunc handler);

//---------
// xmlIO.h
//---------

/**
 * xmlInputMatchCallback:
 * @filename: the filename or URI
 *
 * Callback used in the I/O Input API to detect if the current handler
 * can provide input fonctionnalities for this resource.
 *
 * Returns 1 if yes and 0 if another Input module should be used
 */
typedef int (/* XMLCALL */ *xmlInputMatchCallback) (char const *filename);
/**
 * xmlInputOpenCallback:
 * @filename: the filename or URI
 *
 * Callback used in the I/O Input API to open the resource
 *
 * Returns an Input context or NULL in case or error
 */
typedef void * (/* XMLCALL */ *xmlInputOpenCallback) (char const *filename);
/**
 * xmlInputReadCallback:
 * @context:  an Input context
 * @buffer:  the buffer to store data read
 * @len:  the length of the buffer in bytes
 *
 * Callback used in the I/O Input API to read the resource
 *
 * Returns the number of bytes read or -1 in case of error
 */
typedef int (/* XMLCALL */ *xmlInputReadCallback) (void * context, char * buffer, int len);
/**
 * xmlInputCloseCallback:
 * @context:  an Input context
 *
 * Callback used in the I/O Input API to close the resource
 *
 * Returns 0 or -1 in case of error
 */
typedef int (/* XMLCALL */ *xmlInputCloseCallback) (void * context);

/* XMLPUBFUN */ int /* XMLCALL */
	xmlRegisterInputCallbacks		(xmlInputMatchCallback matchFunc,
						 xmlInputOpenCallback openFunc,
						 xmlInputReadCallback readFunc,
						 xmlInputCloseCallback closeFunc);
/* XMLPUBFUN */ int /* XMLCALL */
  xmlPopInputCallbacks      (void);

//--------------
// xmlschemas.h
//--------------

typedef struct _xmlSchemaParserCtxt xmlSchemaParserCtxt;
typedef xmlSchemaParserCtxt *xmlSchemaParserCtxtPtr;

typedef struct _xmlSchemaValidCtxt xmlSchemaValidCtxt;
typedef xmlSchemaValidCtxt *xmlSchemaValidCtxtPtr;

/* XMLPUBFUN */ xmlSchemaParserCtxtPtr /* XMLCALL */
	    xmlSchemaNewParserCtxt	(const char *URL);

typedef struct _xmlSchema xmlSchema;
typedef xmlSchema *xmlSchemaPtr;

/* XMLPUBFUN */ xmlSchemaPtr /* XMLCALL */
	    xmlSchemaParse		(xmlSchemaParserCtxtPtr ctxt);

/* XMLPUBFUN */ xmlSchemaValidCtxtPtr /* XMLCALL */
	    xmlSchemaNewValidCtxt	(xmlSchemaPtr schema);
/* XMLPUBFUN */ void /* XMLCALL */
	    xmlSchemaFreeValidCtxt	(xmlSchemaValidCtxtPtr ctxt);

/* XMLPUBFUN */ void /* XMLCALL */
            xmlSchemaValidateSetFilename(xmlSchemaValidCtxtPtr vctxt,
	                                 const char *filename);

/* XMLPUBFUN */ int /* XMLCALL */
	    xmlSchemaValidateDoc	(xmlSchemaValidCtxtPtr ctxt,
					 xmlDocPtr instance);

/* XMLPUBFUN */ void /* XMLCALL */
	    xmlSchemaSetParserStructuredErrors(xmlSchemaParserCtxtPtr ctxt,
					 xmlStructuredErrorFunc serror,
					 void *ctx);

/* XMLPUBFUN */ void /* XMLCALL */
	    xmlSchemaSetValidStructuredErrors(xmlSchemaValidCtxtPtr ctxt,
					 xmlStructuredErrorFunc serror,
					 void *ctx);

//-------------------------------------------------------
// typedef and constants from libxmlsec1 1.2.25
//-------------------------------------------------------

int xmlSecInit(void);
int xmlSecShutdown(void);

// #define xmlSecByte                              unsigned char
typedef unsigned char xmlSecByte;

enum {
    XMLSEC_VERSION_MAJOR          = 1,
    XMLSEC_VERSION_MINOR          = 2,
    XMLSEC_VERSION_SUBMINOR       = 25
};

typedef enum {
    xmlSecCheckVersionExactMatch = 0,
    xmlSecCheckVersionABICompatible
} xmlSecCheckVersionMode;

int xmlSecCheckVersionExt(int major,
                          int minor,
                          int subminor,
                          xmlSecCheckVersionMode mode);

// #ifdef XMLSEC_NO_SIZE_T
// #define xmlSecSize                              unsigned int
// #else /* XMLSEC_NO_SIZE_T */
// #define xmlSecSize                              size_t
// #endif /* XMLSEC_NO_SIZE_T */
typedef unsigned int                            xmlSecSize;

typedef void*                                   xmlSecPtr;

typedef const struct _xmlSecPtrListKlass                        xmlSecPtrListKlass,
                                                                *xmlSecPtrListId;
typedef struct _xmlSecPtrList                                   xmlSecPtrList,
                                                                *xmlSecPtrListPtr;

typedef struct _xmlSecKeyInfoCtx                xmlSecKeyInfoCtx, *xmlSecKeyInfoCtxPtr;
typedef struct _xmlSecKey                       xmlSecKey, *xmlSecKeyPtr;
typedef struct _xmlSecKeyStore                  xmlSecKeyStore, *xmlSecKeyStorePtr;
typedef struct _xmlSecKeysMngr                  xmlSecKeysMngr, *xmlSecKeysMngrPtr;
typedef struct _xmlSecTransformCtx              xmlSecTransformCtx, *xmlSecTransformCtxPtr;

typedef struct _xmlSecKeyReq                    xmlSecKeyReq, *xmlSecKeyReqPtr;

typedef struct _xmlSecDSigCtx                   xmlSecDSigCtx, *xmlSecDSigCtxPtr;

typedef struct _xmlSecEncCtx                    xmlSecEncCtx, *xmlSecEncCtxPtr;

typedef const struct _xmlSecKeyStoreKlass               xmlSecKeyStoreKlass,
                                                        *xmlSecKeyStoreId;

typedef const struct _xmlSecTransformKlass              xmlSecTransformKlass,
                                                        *xmlSecTransformId;


typedef enum {
    xmlSecKeyInfoModeRead = 0,
    xmlSecKeyInfoModeWrite
} xmlSecKeyInfoMode;

typedef struct _IO_FILE FILE;

typedef int (*xmlSecKeyStoreInitializeMethod)(xmlSecKeyStorePtr store);
typedef void (*xmlSecKeyStoreFinalizeMethod)(xmlSecKeyStorePtr store);
typedef xmlSecKeyPtr(*xmlSecKeyStoreFindKeyMethod)(xmlSecKeyStorePtr store,
                                                   const xmlChar* name,
                                                   xmlSecKeyInfoCtxPtr keyInfoCtx);
typedef xmlSecPtr               (*xmlSecPtrDuplicateItemMethod) (xmlSecPtr ptr);
typedef void                    (*xmlSecPtrDestroyItemMethod)   (xmlSecPtr ptr);
typedef void                    (*xmlSecPtrDebugDumpItemMethod) (xmlSecPtr ptr,
                                                                 FILE* output);

typedef unsigned int                            xmlSecKeyDataType;

typedef unsigned int                    xmlSecKeyUsage;

typedef const struct _xmlSecKeyDataKlass                xmlSecKeyDataKlass,
                                                        *xmlSecKeyDataId;


typedef enum {
    xmlSecAllocModeExact = 0,
    xmlSecAllocModeDouble
} xmlSecAllocMode;

struct _xmlSecPtrList {
    xmlSecPtrListId             id;

    xmlSecPtr*                  data;
    xmlSecSize                  use;
    xmlSecSize                  max;
    xmlSecAllocMode             allocMode;
};

struct _xmlSecPtrListKlass {
    const xmlChar*                      name;
    xmlSecPtrDuplicateItemMethod        duplicateItem;
    xmlSecPtrDestroyItemMethod          destroyItem;
    xmlSecPtrDebugDumpItemMethod        debugDumpItem;
    xmlSecPtrDebugDumpItemMethod        debugXmlDumpItem;
};

struct _xmlSecKeyReq {
    xmlSecKeyDataId             keyId;
    xmlSecKeyDataType           keyType;
    xmlSecKeyUsage              keyUsage;
    xmlSecSize                  keyBitsSize;
    xmlSecPtrList               keyUseWithList;

    void*                       reserved1;
    void*                       reserved2;
};

typedef enum {
    xmlEncCtxModeEncryptedData = 0,
    xmlEncCtxModeEncryptedKey
} xmlEncCtxMode;

typedef enum  {
    xmlSecTransformOperationNone = 0,
    xmlSecTransformOperationEncode,
    xmlSecTransformOperationDecode,
    xmlSecTransformOperationSign,
    xmlSecTransformOperationVerify,
    xmlSecTransformOperationEncrypt,
    xmlSecTransformOperationDecrypt
} xmlSecTransformOperation;

const xmlChar xmlSecNodeSignature[];
const xmlChar xmlSecDSigNs[];

typedef struct _xmlSecBuffer                                    xmlSecBuffer,
                                                                *xmlSecBufferPtr;
typedef struct _xmlSecTransform                 xmlSecTransform, *xmlSecTransformPtr;

typedef xmlSecKeyPtr    (*xmlSecGetKeyCallback)         (xmlNodePtr keyInfoNode,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);

struct _xmlSecKeysMngr {
    xmlSecKeyStorePtr           keysStore;
    xmlSecPtrList               storesList;
    xmlSecGetKeyCallback        getKey;
};

typedef unsigned int xmlSecTransformUriType;
typedef int          (*xmlSecTransformCtxPreExecuteCallback)(xmlSecTransformCtxPtr transformCtx);

typedef enum  {
    xmlSecTransformStatusNone = 0,
    xmlSecTransformStatusWorking,
    xmlSecTransformStatusFinished,
    xmlSecTransformStatusOk,
    xmlSecTransformStatusFail
} xmlSecTransformStatus;

struct _xmlSecTransformCtx {
    /* user settings */
    void*                                       userData;
    unsigned int                                flags;
    unsigned int                                flags2;
    xmlSecTransformUriType                      enabledUris;
    xmlSecPtrList                               enabledTransforms;
    xmlSecTransformCtxPreExecuteCallback        preExecCallback;

    /* results */
    xmlSecBufferPtr                             result;
    xmlSecTransformStatus                       status;
    xmlChar*                                    uri;
    xmlChar*                                    xptrExpr;
    xmlSecTransformPtr                          first;
    xmlSecTransformPtr                          last;

    /* for the future */
    void*                                       reserved0;
    void*                                       reserved1;
};

struct _xmlSecKeyInfoCtx {
    void*                               userData;
    unsigned int                        flags;
    unsigned int                        flags2;
    xmlSecKeysMngrPtr                   keysMngr;
    xmlSecKeyInfoMode                   mode;
    xmlSecPtrList                       enabledKeyData;
    int                                 base64LineSize;

    /* RetrievalMethod */
    xmlSecTransformCtx                  retrievalMethodCtx;
    int                                 maxRetrievalMethodLevel;

// #ifndef XMLSEC_NO_XMLENC
    /* EncryptedKey */
    xmlSecEncCtxPtr                     encCtx;
    int                                 maxEncryptedKeyLevel;
// #endif /* XMLSEC_NO_XMLENC */

// #ifndef XMLSEC_NO_X509
    /* x509 certificates */
    time_t                              certsVerificationTime;
    int                                 certsVerificationDepth;
// #endif /* XMLSEC_NO_X509 */

    /* PGP */
    void*                               pgpReserved;    /* TODO */

    /* internal data */
    int                                 curRetrievalMethodLevel;
    int                                 curEncryptedKeyLevel;
    xmlSecKeyReq                        keyReq;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
};

struct _xmlSecEncCtx {
    /* these data user can set before performing the operation */
    void*                       userData;
    unsigned int                flags;
    unsigned int                flags2;
    xmlEncCtxMode               mode;
    xmlSecKeyInfoCtx            keyInfoReadCtx;
    xmlSecKeyInfoCtx            keyInfoWriteCtx;
    xmlSecTransformCtx          transformCtx;
    xmlSecTransformId           defEncMethodId;

    /* these data are returned */
    xmlSecKeyPtr                encKey;
    xmlSecTransformOperation    operation;
    xmlSecBufferPtr             result;
    int                         resultBase64Encoded;
    int                         resultReplaced;
    xmlSecTransformPtr          encMethod;

    /* attributes from EncryptedData or EncryptedKey */
    xmlChar*                    id;
    xmlChar*                    type;
    xmlChar*                    mimeType;
    xmlChar*                    encoding;
    xmlChar*                    recipient;
    xmlChar*                    carriedKeyName;

    /* these are internal data, nobody should change that except us */
    xmlNodePtr                  encDataNode;
    xmlNodePtr                  encMethodNode;
    xmlNodePtr                  keyInfoNode;
    xmlNodePtr                  cipherValueNode;

    xmlNodePtr                  replacedNodeList; /* the pointer to the replaced node */
    void*                       reserved1;        /* reserved for future */
};

struct _xmlSecKeyStoreKlass {
    xmlSecSize                          klassSize;
    xmlSecSize                          objSize;

    /* data */
    const xmlChar*                      name;

    /* constructors/destructor */
    xmlSecKeyStoreInitializeMethod      initialize;
    xmlSecKeyStoreFinalizeMethod        finalize;
    xmlSecKeyStoreFindKeyMethod         findKey;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
};

typedef struct _xmlSecKeyData                   xmlSecKeyData, *xmlSecKeyDataPtr;

struct _xmlSecKey {
    xmlChar*                            name;
    xmlSecKeyDataPtr                    value;
    xmlSecPtrListPtr                    dataList;
    xmlSecKeyUsage                      usage;
    time_t                              notValidBefore;
    time_t                              notValidAfter;
};



struct _xmlSecKeyStore {
    xmlSecKeyStoreId                    id;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
};

typedef enum {
    xmlSecDSigStatusUnknown = 0,
    xmlSecDSigStatusSucceeded,
    xmlSecDSigStatusInvalid
} xmlSecDSigStatus;

struct _xmlSecDSigCtx {
    /* these data user can set before performing the operation */
    void*                       userData;
    unsigned int                flags;
    unsigned int                flags2;
    xmlSecKeyInfoCtx            keyInfoReadCtx;
    xmlSecKeyInfoCtx            keyInfoWriteCtx;
    xmlSecTransformCtx          transformCtx;
    xmlSecTransformUriType      enabledReferenceUris;
    xmlSecPtrListPtr            enabledReferenceTransforms;
    xmlSecTransformCtxPreExecuteCallback referencePreExecuteCallback;
    xmlSecTransformId           defSignMethodId;
    xmlSecTransformId           defC14NMethodId;
    xmlSecTransformId           defDigestMethodId;

    /* these data are returned */
    xmlSecKeyPtr                signKey;
    xmlSecTransformOperation    operation;
    xmlSecBufferPtr             result;
    xmlSecDSigStatus            status;
    xmlSecTransformPtr          signMethod;
    xmlSecTransformPtr          c14nMethod;
    xmlSecTransformPtr          preSignMemBufMethod;
    xmlNodePtr                  signValueNode;
    xmlChar*                    id;
    xmlSecPtrList               signedInfoReferences;
    xmlSecPtrList               manifestReferences;

    /* reserved for future */
    void*                       reserved0;
    void*                       reserved1;
};

xmlSecKeysMngrPtr         xmlSecKeysMngrCreate            (void);
void xmlSecKeysMngrDestroy(xmlSecKeysMngrPtr mngr);
int                xmlSecOpenSSLAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr);


typedef enum {
    xmlSecKeyDataFormatUnknown = 0,
    xmlSecKeyDataFormatBinary,
    xmlSecKeyDataFormatPem,
    xmlSecKeyDataFormatDer,
    xmlSecKeyDataFormatPkcs8Pem,
    xmlSecKeyDataFormatPkcs8Der,
    xmlSecKeyDataFormatPkcs12,
    xmlSecKeyDataFormatCertPem,
    xmlSecKeyDataFormatCertDer
} xmlSecKeyDataFormat;

enum {
  xmlSecKeyDataTypeTrusted                      = 0x0100
};

xmlNodePtr        xmlSecGetNextElementNode(xmlNodePtr cur);

xmlNodePtr        xmlSecFindNode(const xmlNodePtr parent,
                                 const xmlChar *name,
                                 const xmlChar *ns);

/* XMLSEC_EXPORT */ xmlSecDSigCtxPtr  xmlSecDSigCtxCreate       (xmlSecKeysMngrPtr keysMngr);

/* XMLSEC_EXPORT */ void              xmlSecDSigCtxDestroy      (xmlSecDSigCtxPtr dsigCtx);
/* XMLSEC_EXPORT */ int               xmlSecDSigCtxInitialize   (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlSecKeysMngrPtr keysMngr);

int               xmlSecDSigCtxVerify             (xmlSecDSigCtxPtr dsigCtx,                                                                xmlNodePtr node);

xmlSecSize        xmlSecPtrListGetSize            (xmlSecPtrListPtr list);

/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplSignatureCreate        (xmlDocPtr doc,
                                                                 xmlSecTransformId c14nMethodId,
                                                                 xmlSecTransformId signMethodId,
                                                                 const xmlChar *id);

// #define xmlSecTransformExclC14NId \
//         xmlSecTransformExclC14NGetKlass()
/* XMLSEC_EXPORT */ xmlSecTransformId xmlSecTransformExclC14NGetKlass         (void);

/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplSignatureAddReference  (xmlNodePtr signNode,
                                                                 xmlSecTransformId digestMethodId,
                                                                 const xmlChar *id,
                                                                 const xmlChar *uri,
                                                                 const xmlChar *type);

/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplReferenceAddTransform  (xmlNodePtr referenceNode,
                                                                 xmlSecTransformId transformId);

// #define xmlSecTransformEnvelopedId \
//         xmlSecTransformEnvelopedGetKlass()
/* XMLSEC_EXPORT */ xmlSecTransformId xmlSecTransformEnvelopedGetKlass        (void);

/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplSignatureEnsureKeyInfo (xmlNodePtr signNode,
                                                                 const xmlChar *id);

/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplKeyInfoAddX509Data     (xmlNodePtr keyInfoNode);

/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplX509DataAddSubjectName (xmlNodePtr x509DataNode);
/* XMLSEC_EXPORT */ xmlNodePtr xmlSecTmplX509DataAddCertificate (xmlNodePtr x509DataNode);

/* XMLSEC_EXPORT */ int               xmlSecDSigCtxSign         (xmlSecDSigCtxPtr dsigCtx,
                                                                 xmlNodePtr tmpl);

/* XMLSEC_EXPORT */ xmlDocPtr         xmlSecParseMemory (const xmlSecByte *buffer,
                                                         xmlSecSize size,
                                                         int recovery);

/* XMLSEC_EXPORT */ void              xmlSecKeyDestroy        (xmlSecKeyPtr key);

//-------------------------------------------------------
// typedef and constants from libxmlsec1-openssl 1.2.25
//-------------------------------------------------------

int xmlSecOpenSSLAppInit(const char *config);
int xmlSecOpenSSLAppShutdown(void);

int xmlSecOpenSSLInit(void);
int xmlSecOpenSSLShutdown(void);

/* XMLSEC_CRYPTO_EXPORT */ int    xmlSecOpenSSLAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format,
                                                                         xmlSecKeyDataType type);

/* XMLSEC_CRYPTO_EXPORT */ xmlSecKeyPtr xmlSecOpenSSLAppKeyLoadMemory   (const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format,
                                                                         const char *pwd,
                                                                         void* pwdCallback,
                                                                         void* pwdCallbackCtx);

/* XMLSEC_CRYPTO_EXPORT */ int         xmlSecOpenSSLAppKeyCertLoadMemory(xmlSecKeyPtr key,
                                                                         const xmlSecByte* data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format);

/* XMLSEC_CRYPTO_EXPORT */ int   xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr,
                                                                         xmlSecKeyPtr key);

]]

function _M.readfile(filename)
    local lines = {}
    for line in io.lines(filename) do
        table.insert(lines, line)
    end
    return table.concat(lines, "\n")
end

local function ffiStr(cdata, def_val)
    if cdata == nil then
        return def_val or ''
    end
    return ffi.string(cdata)
end

local function ffiStrTrimRight(cdata, def_val)
    if cdata == nil then
        return def_val or ''
    end
    local len = C.strlen(cdata) - 1
    while len > 0 and C.isspace(cdata[len]) ~= 0 do
        len = len - 1
    end
    return ffi.string(cdata, len + 1)
end

local function errFileLine(err)
    if err.file == nil then
        return ''
    end
    if err.line == 0 then
        return ffi.string(err.file)
    end
    return ffi.string(err.file) .. ':' .. tostring(err.line)
end

local function globalParseError(userData, err)
    local msg = ffiStrTrimRight(err.message)
    local fileLine = errFileLine(err)
    if fileLine ~= "" then
        msg = fileLine .. ': ' .. msg
    end
    ngx.log(ngx.WARN, string.format('saml.service_provider.xmlsec xmlParseError: %s', msg))
end
-- NOTE: We explicitly cast the above lua function to a C function pointer
--       and keep it to avoid "too many callbacks" error.
--       See "Callback resource handling" in https://luajit.org/ext_ffi_semantics.html
--       for detail.
local globalParseError_Cfunc = ffi.cast('xmlStructuredErrorFunc', globalParseError)

local function has_suffix(s, suffix)
    return #s >= #suffix and string.sub(s, -#suffix) == suffix
end

function _M.load_xsd_files(dir)
    local filenames = {
        'saml-schema-assertion-2.0.xsd',
        'saml-schema-protocol-2.0.xsd',
        'xenc-schema.xsd',
        'xmldsig-core-schema.xsd',
    }
    _M.xsdFiles = {}
    for _, filename in ipairs(filenames) do
        _M.xsdFiles[filename] = _M.readfile(dir .. '/' .. filename)
    end
end

local function xsdMatch(filename)
    local filename_s = ffi.string(filename)
    if has_suffix(filename_s, '.xsd') then
        -- print('xsdMatch, filename=', filename_s, ', returns 1')
        return 1
    end
    return 0
end

local function xsdOpen(filename)
    local filename_s = ffi.string(C.basename(filename))
    local data = _M.xsdFiles[filename_s]
    if data == nil then
        return nil
    end
    local context = ffi.new('xsdReadContext[1]')
    context[0].data = data
    context[0].len = #data
    context[0].pos = 0
    return context
end

local function xsdRead(context, buffer, len)
    if context == nil then
        return -1
    end
    local ctx = ffi.cast('xsdReadContextPtr', context)
    local to_copy = ctx.len - ctx.pos
    if to_copy >= len then
        to_copy = len
    end
    -- print('xsdRead, pos=', ctx.pos, ', to_copy=', to_copy, ', len=', len, ', ctx.len=', ctx.len)
    ffi.copy(buffer, ctx.data + ctx.pos, to_copy)
    ctx.pos = ctx.pos + to_copy
    return to_copy
end

local function xsdClose(context)
    return 0
end

local xsdMatchC = ffi.cast('xmlInputMatchCallback', xsdMatch)
local xsdOpenC = ffi.cast('xmlInputOpenCallback', xsdOpen)
local xsdReadC = ffi.cast('xmlInputReadCallback', xsdRead)
local xsdCloseC = ffi.cast('xmlInputCloseCallback', xsdClose)

local function handleParseError(userDataC, err)
    local userData = ffi.cast('handleErrUserDataxPtr', userDataC)
    local msg = ffiStrTrimRight(err.message)
    local fileLine = errFileLine(err)
    if fileLine ~= "" then
        msg = fileLine .. ': ' .. msg
    end
    userData.len = #msg
    userData.buf = msg
end
local handleParseError_Cfunc = ffi.cast('xmlStructuredErrorFunc', handleParseError)

local function initParseXMLSchema(schema)
    if xml2.xmlRegisterInputCallbacks(xsdMatchC, xsdOpenC, xsdReadC, xsdCloseC) == -1 then
        ngx.log(ngx.EMERG, 'error in xmlRegisterInputCallbacks')
    end
    local ctxt = xml2.xmlSchemaNewParserCtxt(schema)

    local userData = ffi.new('handleErrUserData')
    xml2.xmlSchemaSetParserStructuredErrors(ctxt, handleParseError_Cfunc, userData)
    local wxschemas = xml2.xmlSchemaParse(ctxt)
    xml2.xmlPopInputCallbacks();
    if wxschemas == nil then
        ngx.log(ngx.EMERG, string.format("saml.service_provider.xmlsec initParseXMLSchema error: %s", ffi.string(userData.buf, userData.len)))
        return
    end
    return wxschemas
end

local function handleValidError(userDataC, err)
    local userData = ffi.cast('handleErrUserDataxPtr', userDataC)
    local msg = ffiStrTrimRight(err.message)
    local fileLine = errFileLine(err)
    if fileLine ~= "" then
        msg = fileLine .. ': ' .. msg
    end
    userData.len = #msg
    userData.buf = msg
end
local handleValidError_Cfunc = ffi.cast('xmlStructuredErrorFunc', handleValidError)

function _M.validateXMLWithSchemaDoc(doc)
    local wxschemas = initParseXMLSchema('saml-schema-protocol-2.0.xsd')
    local vctxt = xml2.xmlSchemaNewValidCtxt(wxschemas)
    local userData = ffi.new('handleErrUserData')
    xml2.xmlSchemaSetValidStructuredErrors(vctxt, handleValidError_Cfunc, userData)
    local ret = xml2.xmlSchemaValidateDoc(vctxt, doc)
    if ret ~= 0 then
        ngx.log(ngx.WARN, string.format("saml.service_provider.xmlsec xmlSchemaValidateDoc error: %s", ffi.string(userData.buf, userData.len)))
    end
    xml2.xmlSchemaFreeValidCtxt(vctxt)
    return ret == 0
end

local function appCryptoInit()
    local ret = xmlsec1openssl.xmlSecOpenSSLAppInit(nil)
    if ret < 0 then
        return "openssl initialization failed."
    end

    if xmlsec1openssl.xmlSecOpenSSLInit() < 0 then
        return "xmlsec-openssl initialization failed."
    end

    return nil
end

local function appCryptoShutdown()
    xmlsec1openssl.xmlSecOpenSSLShutdown()
    xmlsec1openssl.xmlSecOpenSSLAppShutdown()
end

local function appInit()
    xml2.xmlInitParser()

    local ret = xmlsec1.xmlSecInit()
    if ret < 0 then
        return "xmlsec initialization failed."
    end

    ret = xmlsec1.xmlSecCheckVersionExt(
            xmlsec1.XMLSEC_VERSION_MAJOR,
            xmlsec1.XMLSEC_VERSION_MINOR,
            xmlsec1.XMLSEC_VERSION_SUBMINOR,
            xmlsec1.xmlSecCheckVersionABICompatible)
    if ret ~= 1 then
        return "loaded xmlsec library version is not compatible."
    end

    local err = appCryptoInit()
    if err ~= nil then
        return err
    end

    xml2.xmlSetStructuredErrorFunc(nil, globalParseError_Cfunc)

    return nil
end

local function appShutdown()
    appCryptoShutdown()
    xmlsec1.xmlSecShutdown()
    xml2.xmlCleanupParser()
end

--- Adds attributes <attrName> from all nodes with <nsHref>:<nodeName>.
-- It provides the same effect as `xmlsec1 --id-attr:<attrName> <nsHref>:<nodeName>`
-- See man xmlsec1(1).
--
-- addIDAttr is a lua port of xmlSecAppAddIDAttr.
-- https://github.com/lsh123/xmlsec/blob/xmlsec-1_2_25/apps/xmlsec.c#L2773-L2829
local function addIDAttr(node, attrName, nodeName, nsHref)
    if node == nil or attrName == nil or nodeName == nil then
        return -1
    end

    -- process children first because it does not matter much but does simplify code
    local cur = xmlsec1.xmlSecGetNextElementNode(node.children)
    while cur ~= nil do
        if addIDAttr(cur, attrName, nodeName, nsHref) < 0 then
            return -1
        end
        cur = xmlsec1.xmlSecGetNextElementNode(cur.next)
    end

    -- node name must match
    if xml2.xmlStrEqual(node.name, nodeName) ~= 1 then
        return 0
    end

    -- if nsHref is set then it also should match
    if nsHref ~= nil and node.ns ~= nil and
            xml2.xmlStrEqual(nsHref, ffi.string(node.ns.href)) ~= 1 then
        return 0
    end

    -- the attribute with name equal to attrName should exist
    local found = false
    local attr = node.properties
    while attr ~= nil do
        if xml2.xmlStrEqual(attr.name, attrName) == 1 then
            found = true
            break
        end
        attr = attr.next
    end
    if not found then
        return 0
    end

    -- and this attr should have a value
    local id = xml2.xmlNodeListGetString(node.doc, attr.children, 1)
    if id == nil then
        return 0
    end

    -- check that we don't have same ID already
    local tmpAttr = xml2.xmlGetID(node.doc, id)
    if tmpAttr == nil then
        xml2.xmlAddID(nil, node.doc, id, attr)
    elseif tmpAttr ~= attr then
        xml2.xmlFree(id)
        return -1
    end
    xml2.xmlFree(id)
    return 0
end

--- Parse xml on memory and return doc and startNode.
-- You need to call xmlFree
-- @param xml                xml (string).
-- @param defStartNodeName   start node name (string).
-- @param defStartNodeNs     start node namespace (string).
-- @param idAttr             ID attribute (table with "attrName", "nodeName",
--                           and "nsHref" keys).
--                           Example:
--                           { attrName = "ID", nodeName = "Response",
--                             nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- @return doc               parsed xml document (xml2.xmlDocPtr).
-- @return startNode         start node (xml2.xmlNodePtr).
-- @return err               err (string).
local function appXmlDocCreate(xml, defStartNodeName, defStartNodeNs, idAttr)
    local doc = xmlsec1.xmlSecParseMemory(xml, #xml, 0)
    if doc == nil then
        return nil, nil, "unable to parse response xml"
    end

    local root = xml2.xmlDocGetRootElement(doc)
    if root == nil then
        return nil, nil, "unable to get root element of response xml"
    end

    local cur
    if idAttr ~= nil then
        local attrName = idAttr.attrName
        local nodeName = idAttr.nodeName
        local nsHref = idAttr.nsHref
        cur = xmlsec1.xmlSecGetNextElementNode(doc.children)
        while cur ~= nil do
            if addIDAttr(cur, attrName, nodeName, nsHref) < 0 then
                return nil, nil, string.format("failed to add ID attribute \"%s\" for node \"%s\"\n", attrName, nodeName)
            end
            cur = xmlsec1.xmlSecGetNextElementNode(cur.next)
        end
    end

    cur = root
    local startNode
    if defStartNodeName ~= nil then
        startNode = xmlsec1.xmlSecFindNode(cur, defStartNodeName, defStartNodeNs)
        if startNode == nil then
            return nil, nil, string.format("failed to find default node with name=\"%s\"", defStartNodeName)
        end
    else
        startNode = cur
    end

    return doc, startNode, nil
end

local function appCryptoSimpleKeysMngrCertLoad(mngr, pem, format, dataType)
    return xmlsec1openssl.xmlSecOpenSSLAppKeysMngrCertLoadMemory(
            mngr, pem, #pem, format, dataType)
end

--- Load private key and certificates
-- @param mngr                key manager (xmlsec1.xmlSecKeysMngrPtr).
-- @param key                 IdP key (string).
-- @param certificates        IdP and CA certificate (table of string).
-- @param format              pem format (string).
-- @return err                error message (string).
local function appCryptoSimpleKeysMngrKeyAndCertsLoad(mngr, key, certificates, format)
    local loadedKey
    local err = (function()
        loadedKey = xmlsec1openssl.xmlSecOpenSSLAppKeyLoadMemory(
                key, #key, format, nil, nil, nil)
        if loadedKey == nil then
            return "xmlSecCryptoAppKeyLoad failed"
        end
    
        for _, cert in ipairs(certificates) do
            local ret = xmlsec1openssl.xmlSecOpenSSLAppKeyCertLoadMemory(
                    loadedKey, cert, #cert, format)
            if ret < 0 then
                return "xmlSecCryptoAppKeyCertLoad failed"
            end
        end
    
        local ret = xmlsec1openssl.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(
                mngr, loadedKey)
        if ret < 0 then
            return "xmlSecCryptoAppDefaultKeysMngrAdoptKey failed"
        end
    end)()
    if err ~= nil then
        if loadedKey ~= nil then
            xmlsec1.xmlSecKeyDestroy(loadedKey)
        end
    end
    return err
end

--- Dump xml on memory
-- @param doc                 a xml document (xml2.xmlDocPtr)
-- @return ret                a dumped xml (string)
local function dumpXML(doc)
    local dumped_xml = ffi.new("xmlChar*[1]")
    local dumped_size = ffi.new("int[1]")
    xml2.xmlDocDumpMemory(doc, dumped_xml, dumped_size)
    local ret = ffi.string(dumped_xml[0], dumped_size[0])
    xml2.xmlFree(dumped_xml[0])
    return ret
end

--- Verifies a simple SAML response on memory.
--
-- @param response_xml        response XML (string).
-- @param idp_cert            IdP certificate (string).
-- @param id_attr             ID attribute (table with "attrName", "nodeName",
--                            and "nsHref" keys).
--                            Example:
--                            { attrName = "ID", nodeName = "Response",
--                              nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- @return ok                 verified successfully or not (bool).
-- @return err                the error message (string or nil).
function _M.verify_response(response_xml, idp_cert, id_attr)
    local mngr, dsigCtx, doc
    local ok, err = (function()
        local err = appInit()
        if err ~= nil then
            return false, err
        end

        mngr = xmlsec1.xmlSecKeysMngrCreate()
        if mngr == nil then
            return false, "failed to initialize keys manager."
        end

        if xmlsec1openssl.xmlSecOpenSSLAppDefaultKeysMngrInit(mngr) < 0 then
            return false, "failed to initialize OpenSSL keys manager."
        end

        if appCryptoSimpleKeysMngrCertLoad(
                mngr, idp_cert,
                xmlsec1.xmlSecKeyDataFormatPem,
                xmlsec1.xmlSecKeyDataTypeTrusted) < 0 then
            return false, "failed to load trusted cert"
        end

        local startNode
        doc, startNode, err = appXmlDocCreate(
                response_xml,
                xmlsec1.xmlSecNodeSignature,
                xmlsec1.xmlSecDSigNs,
                id_attr)
        if err ~= nil then
            return false, err
        end

        local valid = _M.validateXMLWithSchemaDoc(doc)
        if not valid then
            return false, "verify_response validate with xml schema failed"
        end

        dsigCtx = xmlsec1.xmlSecDSigCtxCreate(mngr)
        if dsigCtx == nil then
            return false, "failed to create signature context"
        end

        local ret = xmlsec1.xmlSecDSigCtxVerify(dsigCtx, startNode)
        if ret < 0 then
            return false, nil
        end

        if dsigCtx.status ~= xmlsec1.xmlSecDSigStatusSucceeded then
            return false, nil
        end

        return true, nil
    end)()

    -- cleanup
    if doc ~= nil then
        xml2.xmlFree(doc)
    end
    if dsigCtx ~= nil then
        xmlsec1.xmlSecDSigCtxDestroy(dsigCtx)
    end
    if mngr ~= nil then
        xmlsec1.xmlSecKeysMngrDestroy(mngr)
    end
    appShutdown()

    return ok, err
end


--- Signs a simple SAML response on memory.
--
-- @param response_xml        response XML (string).
-- @param key                 IdP key (string).
-- @param certificates        IdP and CA certificate (table of string).
-- @param id_attr             ID attribute (table with "attrName", "nodeName",
--                            and "nsHref" keys).
--                            Example:
--                            { attrName = "ID", nodeName = "Response",
--                              nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- @return signed_response    signed response (string).
-- @return err                nil if signed successfully, the error message otherwise (string).
function _M.sign_response(response_xml, key, certificates, id_attr)
    local mngr, dsigCtx, doc, signed_response
    local err = (function()
        local err = appInit()
        if err ~= nil then
            return err
        end

        mngr = xmlsec1.xmlSecKeysMngrCreate()
        if mngr == nil then
            return "failed to initialize keys manager."
        end

        if xmlsec1openssl.xmlSecOpenSSLAppDefaultKeysMngrInit(mngr) < 0 then
            return "failed to initialize OpenSSL keys manager."
        end

        err = appCryptoSimpleKeysMngrKeyAndCertsLoad(
            mngr, key, certificates, xmlsec1.xmlSecKeyDataFormatPem)
        if err ~= nil then
            return err
        end

        local startNode
		doc, startNode, err = appXmlDocCreate(
				response_xml,
                xmlsec1.xmlSecNodeSignature,
                xmlsec1.xmlSecDSigNs,
                id_attr)
        if err ~= nil then
            return err
		end

        dsigCtx = xmlsec1.xmlSecDSigCtxCreate(mngr)
        if dsigCtx == nil then
            return "failed to create signature context"
        end

        local ret = xmlsec1.xmlSecDSigCtxSign(dsigCtx, startNode)
        if ret < 0 then
            return "signature failed"
        end

        -- dump signed document
        signed_response = dumpXML(doc)

        return nil
    end)()

    -- cleanup
    if doc ~= nil then
        xml2.xmlFree(doc)
    end
    if dsigCtx ~= nil then
        xmlsec1.xmlSecDSigCtxDestroy(dsigCtx)
    end
    if mngr ~= nil then
        xmlsec1.xmlSecKeysMngrDestroy(mngr)
    end
    appShutdown()

    return signed_response, err
end

return _M
