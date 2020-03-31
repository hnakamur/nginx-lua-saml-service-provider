-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local ffi = require("ffi")
local xml2 = ffi.load("xml2")
local xmlsec1 = ffi.load("xmlsec1")
local xmlsec1openssl = ffi.load("xmlsec1-openssl")
local bit = require "bit"
local bor = bit.bor

local _M = {}

ffi.cdef[[

typedef signed long time_t;

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
-- @return err                nil if verified successfully, the error message otherwise (string).
function _M.verify_response(response_xml, idp_cert, id_attr)
    local mngr, dsigCtx, doc
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

        if appCryptoSimpleKeysMngrCertLoad(
                mngr, idp_cert,
                xmlsec1.xmlSecKeyDataFormatPem,
                xmlsec1.xmlSecKeyDataTypeTrusted) < 0 then
            return "failed to load trusted cert"
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

        local ret = xmlsec1.xmlSecDSigCtxVerify(dsigCtx, startNode)
        if ret < 0 then
            return "failed to verify signature"
        end

        if dsigCtx.status ~= xmlsec1.xmlSecDSigStatusSucceeded then
            return "verify status is not succeeded"
        end

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

    -- NOTE: nil err means verify success.
    return err
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
