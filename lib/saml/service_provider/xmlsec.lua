-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local ffi = require "ffi"
local xml2 = ffi.load("xml2")
local xmlsec1 = ffi.load("xmlsec1")
local xmlsec1openssl = ffi.load("xmlsec1-openssl")
local bit = require "bit"
local bor = bit.bor

local _M = {}

ffi.cdef([[

//-------------------------------------------------------
// typedef and constants from libxml2 2.9.4
//-------------------------------------------------------

enum {
  XML_DETECT_IDS        = 2,
  XML_COMPLETE_ATTRS    = 4
};

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

// XMLPUBFUN int * XMLCALL __xmlLoadExtDtdDefaultValue(void);
// #ifdef LIBXML_THREAD_ENABLED
// #define xmlLoadExtDtdDefaultValue \
// (*(__xmlLoadExtDtdDefaultValue()))
// #else
/* XMLPUBVAR */ int xmlLoadExtDtdDefaultValue;
// #endif

int xmlSubstituteEntitiesDefault(int val);

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

/* XMLPUBFUN */ xmlNodePtr /* XMLCALL */
                xmlAddChild             (xmlNodePtr parent,
                                         xmlNodePtr cur);

//-------------------------------------------------------
// typedef and constants from libxmlsec1 1.2.25
//-------------------------------------------------------

int xmlSecInit(void);
int xmlSecShutdown(void);

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

typedef signed long time_t;

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

xmlSecDSigCtxPtr  xmlSecDSigCtxCreate             (xmlSecKeysMngrPtr keysMngr);
void              xmlSecDSigCtxDestroy            (xmlSecDSigCtxPtr dsigCtx);

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


//-------------------------------------------------------
// typedef and constants from libxmlsec1-openssl 1.2.25
//-------------------------------------------------------

int xmlSecOpenSSLAppInit(const char *config);
int xmlSecOpenSSLAppShutdown(void);

int xmlSecOpenSSLInit(void);
int xmlSecOpenSSLShutdown(void);

// #define xmlSecByte                              unsigned char
typedef unsigned char xmlSecByte;

/* XMLSEC_CRYPTO_EXPORT */ int xmlSecOpenSSLAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr,
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
                                                                         const xmlSecByte * data,
                                                                         xmlSecSize dataSize,
                                                                         xmlSecKeyDataFormat format);

// #define xmlSecOpenSSLTransformRsaSha1Id \
//         xmlSecOpenSSLTransformRsaSha1GetKlass()
/* XMLSEC_CRYPTO_EXPORT */ xmlSecTransformId xmlSecOpenSSLTransformRsaSha1GetKlass(void);

// #define xmlSecOpenSSLTransformSha1Id \
//         xmlSecOpenSSLTransformSha1GetKlass()
/* XMLSEC_CRYPTO_EXPORT */ xmlSecTransformId xmlSecOpenSSLTransformSha1GetKlass(void);

]])

--- Adds attributes <attrName> from all nodes with <nsHref>:<nodeName>.
-- It provides the same effect as `xmlsec1 --id-attr:<attrName> <nsHref>:<nodeName>`
-- See man xmlsec1(1).
--
-- addIDAttr is a lua port of xmlSecAppAddIDAttr.
-- https://github.com/lsh123/xmlsec/blob/xmlsec-1_2_25/apps/xmlsec.c#L2773-L2829
function addIDAttr(node, attrName, nodeName, nsHref)
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

--- Verifies a simple SAML response on memory.
-- In addition to refular verification we ensure that the signature
-- has only one <dsig:Reference/> element.
--
-- @param response_xml        response XML (string).
-- @param idp_certificates    IdP certificates (table of string).
-- @param id_attr             ID attribute (table with "attrName", "nodeName",
--                            and "nsHref" keys).
--                            Example:
--                            { attrName = "ID", nodeName = "Response",
--                              nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- @return err                nil if verified successfully, the error message otherwise (string).
function _M.verify_response(response_xml, idp_certificates, id_attr)
    -- verify_response_memory was started as a lua port of examples/verify4.c.
    -- https://github.com/lsh123/xmlsec/blob/xmlsec-1_2_25/examples/verify4.c
    -- And then it is modified like below:
    -- * call addIDAttr
    -- * read idp_certificates from memory, not from file.

    -- NOTE: Long response_xml will be truncated in nginx log without "..." suffix.
    ngx.log(ngx.DEBUG, "response_xml=", response_xml)

    -- initialize
    xml2.xmlInitParser()
    xml2.xmlLoadExtDtdDefaultValue = bor(xml2.XML_DETECT_IDS, xml2.XML_COMPLETE_ATTRS)
    xml2.xmlSubstituteEntitiesDefault(1)

    local mngr, dsigCtx
    local err = (function()
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

        ret = xmlsec1openssl.xmlSecOpenSSLAppInit(nil)
        if ret < 0 then
            return "openssl initialization failed."
        end

        if xmlsec1openssl.xmlSecOpenSSLInit() < 0 then
            return "xmlsec-openssl initialization failed."
        end

        mngr = xmlsec1.xmlSecKeysMngrCreate()
        if mngr == nil then
            return "failed to initialize keys manager."
        end

        if xmlsec1openssl.xmlSecOpenSSLAppDefaultKeysMngrInit(mngr) < 0 then
            return "failed to initialize OpenSSL keys manager."
        end

        for _, cert in ipairs(idp_certificates) do
            ret = xmlsec1openssl.xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                mngr, cert, #cert,
                xmlsec1.xmlSecKeyDataFormatPem,
                xmlsec1.xmlSecKeyDataTypeTrusted)
            if ret < 0 then
                return "failed to load pem certificate"
            end
        end

        local doc = xml2.xmlParseDoc(response_xml)
        if doc == nil then
            return "unable to parse response xml"
        end

        local root = xml2.xmlDocGetRootElement(doc)
        if root == nil then
            return "unable to get root element of response xml"
        end

        if id_attr ~= nil then
            local attrName = id_attr.attrName
            local nodeName = id_attr.nodeName
            local nsHref = id_attr.nsHref
            local cur = xmlsec1.xmlSecGetNextElementNode(doc.children)
            while cur ~= nil do
                if addIDAttr(cur, attrName, nodeName, nsHref) < 0 then
                    return string.format("failed to add ID attribute \"%s\" for node \"%s\"\n", attrName, nodeName)
                end
                cur = xmlsec1.xmlSecGetNextElementNode(cur.next)
            end
        end

        local node = xmlsec1.xmlSecFindNode(root,
                ffi.string(xmlsec1.xmlSecNodeSignature),
                ffi.string(xmlsec1.xmlSecDSigNs))
        if node == nil then
            return "start node not found in response xml"
        end

        dsigCtx = xmlsec1.xmlSecDSigCtxCreate(mngr)
        if dsigCtx == nil then
            return "failed to create signature context"
        end

        ret = xmlsec1.xmlSecDSigCtxVerify(dsigCtx, node)
        if ret < 0 then
            return "failed to verify signature"
        end

        -- check that we have only one Reference
        if dsigCtx.status == xmlsec1.xmlSecDSigStatusSucceeded and
                xmlsec1.xmlSecPtrListGetSize(dsigCtx.signedInfoReferences) ~= 1 then
            return "only one reference is allowed"
        end

        if dsigCtx.status ~= xmlsec1.xmlSecDSigStatusSucceeded then
            return "verify status is not succeeded"
        end
        return nil
    end)()

    -- cleanup
    if dsigCtx ~= nil then
        xmlsec1.xmlSecDSigCtxDestroy(dsigCtx)
    end
    if mngr ~= nil then
        xmlsec1.xmlSecKeysMngrDestroy(mngr)
    end
    xmlsec1openssl.xmlSecOpenSSLShutdown()
    xmlsec1openssl.xmlSecOpenSSLAppShutdown()
    xmlsec1.xmlSecShutdown()
    xml2.xmlCleanupParser()

    -- NOTE: nil err means verify success.
    ngx.log(ngx.DEBUG, "verify result err=", err)
    return err
end

--- Signs a simple SAML response on memory.
--
-- @param response_xml        response XML (string).
-- @param idp_key             IdP key (string).
-- @param idp_cert            IdP certificate (string).
-- @param id_attr             ID attribute (table with "attrName", "nodeName",
--                            and "nsHref" keys).
--                            Example:
--                            { attrName = "ID", nodeName = "Response",
--                              nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- @return signed_response    signed response (string).
-- @return err                nil if signed successfully, the error message otherwise (string).
function _M.sign_response(response_xml, idp_key, idp_cert, id_attr)
    -- verify_response_memory was started as a lua port of examples/sign3.c.
    -- https://github.com/lsh123/xmlsec/blob/xmlsec-1_2_25/examples/sign3.c
    -- And then it is modified like below:
    -- * call addIDAttr
    -- * read idp_key and idp_cert from memory, not from files.

    -- NOTE: Long response_xml will be truncated in nginx log without "..." suffix.
    -- print("response_xml=", response_xml)

    -- initialize
    xml2.xmlInitParser()
    xml2.xmlLoadExtDtdDefaultValue = bor(xml2.XML_DETECT_IDS, xml2.XML_COMPLETE_ATTRS)
    xml2.xmlSubstituteEntitiesDefault(1)

    local dsigCtx
    local signed_response, err = (function()
        local ret = xmlsec1.xmlSecInit()
        if ret < 0 then
            return nil, "xmlsec initialization failed."
        end

        ret = xmlsec1.xmlSecCheckVersionExt(
                xmlsec1.XMLSEC_VERSION_MAJOR,
                xmlsec1.XMLSEC_VERSION_MINOR,
                xmlsec1.XMLSEC_VERSION_SUBMINOR,
                xmlsec1.xmlSecCheckVersionABICompatible)
        if ret ~= 1 then
            return nil, "loaded xmlsec library version is not compatible."
        end

        ret = xmlsec1openssl.xmlSecOpenSSLAppInit(nil)
        if ret < 0 then
            return nil, "openssl initialization failed."
        end

        if xmlsec1openssl.xmlSecOpenSSLInit() < 0 then
            return nil, "xmlsec-openssl initialization failed."
        end

        local doc = xml2.xmlParseDoc(response_xml)
        if doc == nil then
            return nil, "unable to parse response xml"
        end

        local root = xml2.xmlDocGetRootElement(doc)
        if root == nil then
            return nil, "unable to get root element of response xml"
        end

        if id_attr ~= nil then
            local attrName = id_attr.attrName
            local nodeName = id_attr.nodeName
            local nsHref = id_attr.nsHref
            local cur = xmlsec1.xmlSecGetNextElementNode(doc.children)
            while cur ~= nil do
                if addIDAttr(cur, attrName, nodeName, nsHref) < 0 then
                    return string.format("failed to add ID attribute \"%s\" for node \"%s\"\n", attrName, nodeName)
                end
                cur = xmlsec1.xmlSecGetNextElementNode(cur.next)
            end
        end

        -- create signature template for RSA-SHA1 enveloped signature
        local xmlSecTransformExclC14NId = xmlsec1.xmlSecTransformExclC14NGetKlass()
        local xmlSecTransformRsaSha1Id = xmlsec1openssl.xmlSecOpenSSLTransformRsaSha1GetKlass()
        local signNode = xmlsec1.xmlSecTmplSignatureCreate(
            doc, xmlSecTransformExclC14NId,
            xmlSecTransformRsaSha1Id, nil)
        if signNode == nil then
            return nil, "failed to create signature template"
        end

        -- add <dsig:Signature/> node to the doc
        xml2.xmlAddChild(root, signNode)

        -- add reference
        local xmlSecTransformSha1Id = xmlsec1openssl.xmlSecOpenSSLTransformSha1GetKlass()
        local refNode = xmlsec1.xmlSecTmplSignatureAddReference(
            signNode, xmlSecTransformSha1Id,
            nil, nil, nil)
        if refNode == nil then
            return nil, "failed to add reference to signature template"
        end

        -- add enveloped transform
        local xmlSecTransformEnvelopedId = xmlsec1.xmlSecTransformEnvelopedGetKlass()
        if xmlsec1.xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == nil then
            return nil, "failed to add enveloped transform to reference"
        end
        
        -- add <dsig:KeyInfo/> and <dsig:X509Data/>
        local keyInfoNode = xmlsec1.xmlSecTmplSignatureEnsureKeyInfo(signNode, nil)
        if keyInfoNode == nil then
            return nil, "failed to add key info"
        end
        
        local x509DataNode = xmlsec1.xmlSecTmplKeyInfoAddX509Data(keyInfoNode)
        if x509DataNode == nil then
            return nil, "failed to add X509Data node"
        end
    
        if xmlsec1.xmlSecTmplX509DataAddSubjectName(x509DataNode) == nil then
            return nil, "failed to add X509SubjectName node"
        end
    
        if xmlsec1.xmlSecTmplX509DataAddCertificate(x509DataNode) == nil then
            return nil, "failed to add X509Certificate node"
        end
    
        -- create signature context, we don't need keys manager in this function
        dsigCtx = xmlsec1.xmlSecDSigCtxCreate(nil)
        if dsigCtx == nil then
            return nil, "failed to create signature context"
        end

        -- load private key, assuming that there is not password
        dsigCtx.signKey = xmlsec1openssl.xmlSecOpenSSLAppKeyLoadMemory(idp_key, #idp_key, xmlsec1.xmlSecKeyDataFormatPem, nil, nil, nil)
        if dsigCtx.signKey == nil then
            return nil, "failed to load private pem key on memory"
        end
        
        -- load certificate and add to the key
        if xmlsec1openssl.xmlSecOpenSSLAppKeyCertLoadMemory(dsigCtx.signKey, idp_cert, #idp_cert, xmlsec1.xmlSecKeyDataFormatPem) < 0 then
            return nil, "failed to load pem certificate on memory"
        end
    
--        -- set key name to the file name, this is just an example!
--        if xmlsec1.xmlSecKeySetName(dsigCtx.signKey, key_file) < 0) {
--            fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
--            goto done;
--        }
    
        -- sign the template
        if xmlsec1.xmlSecDSigCtxSign(dsigCtx, signNode) < 0 then
            return nil, "signature failed"
        end
            
        -- dump signed document
        local dumped_xml = ffi.new("xmlChar*[1]")
        local dumped_size = ffi.new("int[1]")
		xml2.xmlDocDumpMemory(doc, dumped_xml, dumped_size)
        local signed_response = ffi.string(dumped_xml[0], dumped_size[0])
        xml2.xmlFree(dumped_xml[0])
        
        -- success
        return signed_response, nil
    end)()

    -- cleanup
    if dsigCtx ~= nil then
        xmlsec1.xmlSecDSigCtxDestroy(dsigCtx)
    end
    xmlsec1openssl.xmlSecOpenSSLShutdown()
    xmlsec1openssl.xmlSecOpenSSLAppShutdown()
    xmlsec1.xmlSecShutdown()
    xml2.xmlCleanupParser()

    return signed_response, err
end

return _M
