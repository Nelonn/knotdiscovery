/*
 * This file is part of knotdiscovery.
 *
 * For license and copyright information please follow this link:
 * https://github.com/nelonn/knotdiscovery/blob/master/README.md
 */

#include "adapter.h"
#include "dns_sd.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/select.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

#if defined(__APPLE__)
#define BONJOUR_DYNAMIC 0
#else
#define BONJOUR_DYNAMIC 1
#endif

#if BONJOUR_DYNAMIC

#if defined(_WIN32) && !defined(APIENTRY) && !defined(__CYGWIN__) && !defined(__SCITECH_SNAP__)
#define APIENTRY __stdcall
#endif

#ifndef APIENTRY
#define APIENTRY
#endif
#ifndef APIENTRYP
#define APIENTRYP APIENTRY *
#endif

typedef DNSServiceErrorType (APIENTRYP PFN_DNSServiceRegister)(
    DNSServiceRef *sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    const char *name,
    const char *regtype,
    const char *domain,
    const char *host,
    uint16_t port,
    uint16_t txtLen,
    const void *txtRecord,
    DNSServiceRegisterReply callBack,
    void *context
);
PFN_DNSServiceRegister KN_DNSServiceRegister;
#define DNSServiceRegister KN_DNSServiceRegister

typedef DNSServiceErrorType (APIENTRYP PFN_DNSServiceBrowse)(
    DNSServiceRef *sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    const char *regtype,
    const char *domain,
    DNSServiceBrowseReply callBack,
    void *context
);
PFN_DNSServiceBrowse KN_DNSServiceBrowse;
#define DNSServiceBrowse KN_DNSServiceBrowse

typedef DNSServiceErrorType (APIENTRYP PFN_DNSServiceResolve)(
    DNSServiceRef *sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    const char *name,
    const char *regtype,
    const char *domain,
    DNSServiceResolveReply callBack,
    void *context
);
PFN_DNSServiceResolve KN_DNSServiceResolve;
#define DNSServiceResolve KN_DNSServiceResolve

typedef DNSServiceErrorType (APIENTRYP PFN_DNSServiceQueryRecord)(
    DNSServiceRef *sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    const char *fullname,
    uint16_t rrtype,
    uint16_t rrclass,
    DNSServiceQueryRecordReply callBack,
    void *context
);
PFN_DNSServiceQueryRecord KN_DNSServiceQueryRecord;
#define DNSServiceQueryRecord KN_DNSServiceQueryRecord

typedef dnssd_sock_t (APIENTRYP PFN_DNSServiceRefSockFD)(
    DNSServiceRef sdRef
);
PFN_DNSServiceRefSockFD KN_DNSServiceRefSockFD;
#define DNSServiceRefSockFD KN_DNSServiceRefSockFD

typedef DNSServiceErrorType (APIENTRYP PFN_DNSServiceProcessResult)(
    DNSServiceRef sdRef
);
PFN_DNSServiceProcessResult KN_DNSServiceProcessResult;
#define DNSServiceProcessResult KN_DNSServiceProcessResult

typedef void (APIENTRYP PFN_DNSServiceRefDeallocate)(
    DNSServiceRef sdRef
);
PFN_DNSServiceRefDeallocate KN_DNSServiceRefDeallocate;
#define DNSServiceRefDeallocate KN_DNSServiceRefDeallocate

typedef void (APIENTRYP PFN_TXTRecordCreate)(
    TXTRecordRef *txtRecord,
    uint16_t bufferLen,
    void *buffer
);
PFN_TXTRecordCreate KN_TXTRecordCreate;
#define TXTRecordCreate KN_TXTRecordCreate

typedef void (APIENTRYP PFN_TXTRecordDeallocate)(
    TXTRecordRef *txtRecord
);
PFN_TXTRecordDeallocate KN_TXTRecordDeallocate;
#define TXTRecordDeallocate KN_TXTRecordDeallocate

typedef DNSServiceErrorType (APIENTRYP PFN_TXTRecordSetValue)(
    TXTRecordRef *txtRecord,
    const char *key,
    uint8_t valueSize,
    const void *value
);
PFN_TXTRecordSetValue KN_TXTRecordSetValue;
#define TXTRecordSetValue KN_TXTRecordSetValue

typedef uint16_t (APIENTRYP PFN_TXTRecordGetLength)(
    const TXTRecordRef *txtRecord
);
PFN_TXTRecordGetLength KN_TXTRecordGetLength;
#define TXTRecordGetLength KN_TXTRecordGetLength

typedef void* (APIENTRYP PFN_TXTRecordGetBytesPtr)(
    const TXTRecordRef *txtRecord
);
PFN_TXTRecordGetBytesPtr KN_TXTRecordGetBytesPtr;
#define TXTRecordGetBytesPtr KN_TXTRecordGetBytesPtr

#if defined(_WIN32)
#define DL_GET_PROC(handle, name) GetProcAddress((HANDLE)handle, name)
#else
#define DL_GET_PROC dlsym(handle, name)
#endif

bool KN_DNSSD_LOADED = false;

bool KNLoadBonjour() {
#if defined(_WIN32)
    HANDLE handle = LoadLibraryW(L"dnssd.dll");
#else
    void* handle = dlopen("libdns_sd.so", RTLD_LAZY);
#endif
    if (!handle) return false;
    KN_DNSServiceRegister = (PFN_DNSServiceRegister)DL_GET_PROC(handle, "DNSServiceRegister");
    KN_DNSServiceBrowse = (PFN_DNSServiceBrowse)DL_GET_PROC(handle, "DNSServiceBrowse");
    KN_DNSServiceResolve = (PFN_DNSServiceResolve)DL_GET_PROC(handle, "DNSServiceResolve");
    KN_DNSServiceQueryRecord = (PFN_DNSServiceQueryRecord)DL_GET_PROC(handle, "DNSServiceQueryRecord");
    KN_DNSServiceRefSockFD = (PFN_DNSServiceRefSockFD)DL_GET_PROC(handle, "DNSServiceRefSockFD");
    KN_DNSServiceProcessResult = (PFN_DNSServiceProcessResult)DL_GET_PROC(handle, "DNSServiceProcessResult");
    KN_DNSServiceRefDeallocate = (PFN_DNSServiceRefDeallocate)DL_GET_PROC(handle, "DNSServiceRefDeallocate");
    KN_TXTRecordCreate = (PFN_TXTRecordCreate)DL_GET_PROC(handle, "TXTRecordCreate");
    KN_TXTRecordDeallocate = (PFN_TXTRecordDeallocate)DL_GET_PROC(handle, "TXTRecordDeallocate");
    KN_TXTRecordSetValue = (PFN_TXTRecordSetValue)DL_GET_PROC(handle, "TXTRecordSetValue");
    KN_TXTRecordGetLength = (PFN_TXTRecordGetLength)DL_GET_PROC(handle, "TXTRecordGetLength");
    KN_TXTRecordGetBytesPtr = (PFN_TXTRecordGetBytesPtr)DL_GET_PROC(handle, "TXTRecordGetBytesPtr");
    KN_DNSSD_LOADED = true;
#if defined(_WIN32)
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif
    return true;
}
#endif

static const char* KNBonjourErrorToString(DNSServiceErrorType error) {
    switch (error) {
        default: return "Unrecognized error code";
        case kDNSServiceErr_NoError: return "NoError";
        case kDNSServiceErr_Unknown: return "Unknown";
        case kDNSServiceErr_NoSuchName: return "NoSuchName";
        case kDNSServiceErr_NoMemory: return "NoMemory";
        case kDNSServiceErr_BadParam: return "BadParam";
        case kDNSServiceErr_BadReference: return "BadReference";
        case kDNSServiceErr_BadState: return "BadState";
        case kDNSServiceErr_BadFlags: return "BadFlags";
        case kDNSServiceErr_Unsupported: return "Unsupported";
        case kDNSServiceErr_NotInitialized: return "NotInitialized";
        case kDNSServiceErr_AlreadyRegistered: return "AlreadyRegistered";
        case kDNSServiceErr_NameConflict: return "NameConflict";
        case kDNSServiceErr_Invalid: return "Invalid";
        case kDNSServiceErr_Firewall: return "Firewall";
        case kDNSServiceErr_Incompatible: return "Incompatible";
        case kDNSServiceErr_BadInterfaceIndex: return "BadInterfaceIndex";
        case kDNSServiceErr_Refused: return "Refused";
        case kDNSServiceErr_NoSuchRecord: return "NoSuchRecord";
        case kDNSServiceErr_NoAuth: return "NoAuth";
        case kDNSServiceErr_NoSuchKey: return "NoSuchKey";
        case kDNSServiceErr_NATTraversal: return "NATTraversal";
        case kDNSServiceErr_DoubleNAT: return "DoubleNAT";
        case kDNSServiceErr_BadTime: return "BadTime";
#if !defined(KNOTDISCOVERY_AVAHI_BONJOUR_COMPAT)
        case kDNSServiceErr_BadSig: return "BadSig";
        case kDNSServiceErr_BadKey: return "BadKey";
        case kDNSServiceErr_Transient: return "Transient";
        case kDNSServiceErr_ServiceNotRunning: return "ServiceNotRunning";
        case kDNSServiceErr_NATPortMappingUnsupported: return "NATPortMappingUnsupported";
        case kDNSServiceErr_NATPortMappingDisabled: return "NATPortMappingDisabled";
        case kDNSServiceErr_NoRouter: return "NoRouter";
        case kDNSServiceErr_PollingMode: return "PollingMode";
        case kDNSServiceErr_Timeout: return "Timeout";
#endif
    }
}

struct KNServiceHandle {
    DNSServiceRef sd_ref;
};

struct KNBrowseHandle {
    DNSServiceRef sd_ref;
    KNBrowseCallback callback;
    void* user_data;
};

struct KNResolveHandle {
    DNSServiceRef sd_ref;
    KNResolveCallback callback;
    void* user_data;
};

struct KNQueryHandle {
    DNSServiceRef sd_ref;
    KNQueryCallback callback;
    void* user_data;
};

static void serializeTxtRecord(TXTRecordRef* txt_record, const KNTxtEntry* txt_entries, size_t txt_count) {
    for (size_t i = 0; i < txt_count; i++) {
        const char* key = txt_entries[i].key;
        const char* value = txt_entries[i].value;
        uint8_t value_len = value ? (uint8_t)strlen(value) : 0;
        TXTRecordSetValue(txt_record, key, value_len, value);
    }
}

static KNServiceHandle* BONJOUR_RegisterService(
        KNDiscoveryAdapter* this,
        const char* service_name,
        const char* reg_type,
        uint16_t port,
        const KNTxtEntry* txt_entries,
        size_t txt_count) {
    KNServiceHandle* handle = (KNServiceHandle*)calloc(1, sizeof(KNServiceHandle));
    if (!handle) {
        return NULL;
    }

    TXTRecordRef txt_record;
    TXTRecordCreate(&txt_record, 0, NULL);
    serializeTxtRecord(&txt_record, txt_entries, txt_count);
    DNSServiceErrorType err = DNSServiceRegister(&handle->sd_ref, 0, kDNSServiceInterfaceIndexAny,
                                                 service_name, reg_type, "local.",
                                                 NULL,
                                                 htons(port),
                                                 TXTRecordGetLength(&txt_record), TXTRecordGetBytesPtr(&txt_record),
                                                 NULL, NULL);
    TXTRecordDeallocate(&txt_record);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceRegister failed with error: %s\n", KNBonjourErrorToString(err));
        free(handle);
        return NULL;
    }

    return handle;
}

static size_t BONJOUR_ServiceGetSockets(KNServiceHandle* handle, KNSocket* sockets, size_t count) {
    return 0;
}

static void BONJOUR_ServiceNotify(KNServiceHandle* handle, KNSocket socket) {
}

static void BONJOUR_ServiceStop(KNServiceHandle* handle) {
    if (!handle) return;
    DNSServiceRefDeallocate(handle->sd_ref);
    free(handle);
}

static void bonjourBrowseReply(
        DNSServiceRef sd_ref,
        DNSServiceFlags flags,
        uint32_t interface_index,
        DNSServiceErrorType error_code,
        const char* service_name,
        const char* reg_type,
        const char* reply_domain,
        void* context
) {
    if (error_code != kDNSServiceErr_NoError) return;

    KNBrowseHandle* handle = (KNBrowseHandle*)context;
    if (!handle || !handle->callback) return;

    KNBrowseReply reply;
    reply.service_name = (char*)service_name;
    reply.reg_type = (char*)reg_type;
    reply.reply_domain = (char*)reply_domain;

    handle->callback(&reply, handle->user_data);
}

static KNBrowseHandle* BONJOUR_BrowseServices(
        KNDiscoveryAdapter* this,
        const char* reg_type,
        const char* domain,
        KNBrowseCallback callback,
        void* user_data
) {
    KNBrowseHandle* handle = calloc(1, sizeof(KNBrowseHandle));
    if (!handle) return NULL;

    handle->callback = callback;
    handle->user_data = user_data;

    DNSServiceErrorType err = DNSServiceBrowse(
        &handle->sd_ref,
        0,
        kDNSServiceInterfaceIndexAny,
        reg_type,
        domain,
        bonjourBrowseReply,
        handle
    );

    if (err != kDNSServiceErr_NoError) {
        free(handle);
        return NULL;
    }

    return handle;
}

static size_t BONJOUR_BrowseGetSockets(KNBrowseHandle* handle, KNSocket* sockets, size_t count) {
    if (!handle || count < 1) return 0;
    dnssd_sock_t fd = DNSServiceRefSockFD(handle->sd_ref);
#if defined(_WIN32)
    if (fd == INVALID_SOCKET) return 0;
#else
    if (fd < 0) return 0;
#endif
    sockets[0] = (KNSocket)fd;
    return 1;
}

static void BONJOUR_BrowseNotify(KNBrowseHandle* handle, KNSocket socket) {
    if (!handle) return;
    DNSServiceProcessResult(handle->sd_ref);
}

static void BONJOUR_BrowseStop(KNBrowseHandle* handle) {
    if (!handle) return;
    DNSServiceRefDeallocate(handle->sd_ref);
    free(handle);
}

static void bonjourResolveReply(
        DNSServiceRef sd_ref,
        DNSServiceFlags flags,
        uint32_t interface_index,
        DNSServiceErrorType error_code,
        const char* fullname,
        const char* hosttarget,
        uint16_t port,
        uint16_t txt_len,
        const unsigned char* txt_record,
        void* context
) {
    if (error_code != kDNSServiceErr_NoError) return;

    KNResolveHandle* handle = (KNResolveHandle*)context;
    if (!handle || !handle->callback) return;

    KNResolveReply reply = {0};

    reply.host_name = hosttarget;
    reply.port = ntohs(port);
    reply.ip = NULL;

    handle->callback(&reply, handle->user_data);
}

static KNResolveHandle* BONJOUR_ResolveService(
        KNDiscoveryAdapter* this,
        const char* service_name,
        const char* reg_type,
        const char* domain,
        KNResolveCallback callback,
        void* user_data
) {
    KNResolveHandle* handle = calloc(1, sizeof(KNResolveHandle));
    if (!handle) return NULL;

    handle->callback = callback;
    handle->user_data = user_data;

    DNSServiceErrorType err = DNSServiceResolve(
        &handle->sd_ref,
        0,
        kDNSServiceInterfaceIndexAny,
        service_name,
        reg_type,
        domain,
        bonjourResolveReply,
        handle
    );

    if (err != kDNSServiceErr_NoError) {
        free(handle);
        return NULL;
    }

    return handle;
}

static size_t BONJOUR_ResolveGetSockets(KNResolveHandle* handle, KNSocket* sockets, size_t count) {
    if (!handle || count < 1) return 0;
    dnssd_sock_t fd = DNSServiceRefSockFD(handle->sd_ref);
#if defined(_WIN32)
    if (fd == INVALID_SOCKET) return 0;
#else
    if (fd < 0) return 0;
#endif
    sockets[0] = (KNSocket)fd;
    return 1;
}

static void BONJOUR_ResolveNotify(KNResolveHandle* handle, KNSocket socket) {
    if (!handle) return;
    DNSServiceProcessResult(handle->sd_ref);
}

static void BONJOUR_ResolveStop(KNResolveHandle* handle) {
    if (!handle) return;
    DNSServiceRefDeallocate(handle->sd_ref);
    free(handle);
}

static void bonjourQueryReply(
        DNSServiceRef sd_ref,
        DNSServiceFlags flags,
        uint32_t interface_index,
        DNSServiceErrorType error_code,
        const char* fullname,
        uint16_t rrtype,
        uint16_t rrclass,
        uint16_t rdlen,
        const void* rdata,
        uint32_t ttl,
        void* context
) {
    if (error_code != kDNSServiceErr_NoError) return;

    KNQueryHandle* handle = (KNQueryHandle*)context;
    if (!handle || !handle->callback) return;

    KNIpAddress ip;
    memset(&ip, 0, sizeof(ip));

    if (rdlen == 4) {
        ip.family = KN_IP_V4;
        memcpy(ip.addr.v4, rdata, 4);
    } else if (rdlen == 16) {
        ip.family = KN_IP_V6;
        memcpy(ip.addr.v6, rdata, 16);
    } else {
        return;
    }

    handle->callback(&ip, handle->user_data);
}

static KNQueryHandle* BONJOUR_QueryIpAddress(
        KNDiscoveryAdapter* this,
        const char* host_name,
        KNIpFamily ip_family,
        KNQueryCallback callback,
        void* user_data
) {
    KNQueryHandle* handle = calloc(1, sizeof(KNQueryHandle));
    if (!handle) return NULL;

    handle->callback = callback;
    handle->user_data = user_data;

    uint16_t rrtype = ip_family == KN_IP_V6
        ? kDNSServiceType_AAAA
        : kDNSServiceType_A;

    DNSServiceErrorType err = DNSServiceQueryRecord(
        &handle->sd_ref,
        0,
        kDNSServiceInterfaceIndexAny,
        host_name,
        rrtype,
        kDNSServiceClass_IN,
        bonjourQueryReply,
        handle
    );

    if (err != kDNSServiceErr_NoError) {
        free(handle);
        return NULL;
    }

    return handle;
}

static size_t BONJOUR_QueryGetSockets(KNQueryHandle* handle, KNSocket* sockets, size_t count) {
    if (!handle || count < 1) return 0;
    dnssd_sock_t fd = DNSServiceRefSockFD(handle->sd_ref);
#if defined(_WIN32)
    if (fd == INVALID_SOCKET) return 0;
#else
    if (fd < 0) return 0;
#endif
    sockets[0] = (KNSocket)fd;
    return 1;
}

static void BONJOUR_QueryNotify(KNQueryHandle* handle, KNSocket socket) {
    if (!handle) return;
    DNSServiceProcessResult(handle->sd_ref);
}

static void BONJOUR_QueryStop(KNQueryHandle* handle) {
    if (!handle) return;
    DNSServiceRefDeallocate(handle->sd_ref);
    free(handle);
}

static void BONJOUR_Free(KNDiscoveryAdapter* this) {
    free(this);
}

KNDiscoveryAdapter* KNDiscovery_bonjour_create() {
#if BONJOUR_DYNAMIC
    if (!KN_DNSSD_LOADED) {
        if (!KNLoadBonjour()) return NULL;
    }
#endif
    KNDiscoveryAdapter* adapter = calloc(1, sizeof(KNDiscoveryAdapter));
    if (!adapter) return NULL;
    adapter->RegisterService = BONJOUR_RegisterService;
    adapter->ServiceGetSockets = BONJOUR_ServiceGetSockets;
    adapter->ServiceNotify = BONJOUR_ServiceNotify;
    adapter->ServiceStop = BONJOUR_ServiceStop;
    adapter->BrowseServices = BONJOUR_BrowseServices;
    adapter->BrowseGetSockets = BONJOUR_BrowseGetSockets;
    adapter->BrowseNotify = BONJOUR_BrowseNotify;
    adapter->BrowseStop = BONJOUR_BrowseStop;
    adapter->ResolveService = BONJOUR_ResolveService;
    adapter->ResolveGetSockets = BONJOUR_ResolveGetSockets;
    adapter->ResolveNotify = BONJOUR_ResolveNotify;
    adapter->ResolveStop = BONJOUR_ResolveStop;
    adapter->QueryIpAddress = BONJOUR_QueryIpAddress;
    adapter->QueryGetSockets = BONJOUR_QueryGetSockets;
    adapter->QueryNotify = BONJOUR_QueryNotify;
    adapter->QueryStop = BONJOUR_QueryStop;
    adapter->free = BONJOUR_Free;
    return adapter;
}
