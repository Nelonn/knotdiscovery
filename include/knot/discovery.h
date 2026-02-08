/*
 * This file is part of knotdiscovery.
 *
 * For license and copyright information please follow this link:
 * https://github.com/nelonn/knotdiscovery/blob/master/README.md
 */

#ifndef KNOT_DISCOVERY_H
#define KNOT_DISCOVERY_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define KNOTDISCOVERY_DLL_EXPORT __declspec(dllexport)
#define KNOTDISCOVERY_DLL_IMPORT __declspec(dllimport)
#else
#define KNOTDISCOVERY_DLL_EXPORT __attribute__((visibility("default")))
#define KNOTDISCOVERY_DLL_IMPORT __attribute__((visibility("default")))
#endif

#if defined(KNOTDISCOVERY_DYNAMIC_IMPORT)
#if defined(KNOTDISCOVERY_DYNAMIC)
#define KNOTDISCOVERY_EXPORT KNOTDISCOVERY_DLL_EXPORT
#else
#define KNOTDISCOVERY_EXPORT KNOTDISCOVERY_DLL_IMPORT
#endif
#else
#define KNOTDISCOVERY_EXPORT
#endif

#include <stdint.h>

typedef enum {
    KN_IP_V4 = 0,
    KN_IP_V6 = 1,
} KNIpFamily;

typedef struct {
    KNIpFamily family;
    union {
        uint8_t v4[4];
        uint8_t v6[16];
    } addr;
} KNIpAddress;

typedef struct {
    char* key;
    char* value;
} KNTxtEntry;

typedef struct {
    char* service_name;
    char* reg_type;
    char* reply_domain;
} KNBrowseReply;

typedef struct {
    const char* host_name; /* NULL if not available */
    KNIpAddress* ip; /* NULL if not available */
    uint16_t port;
    size_t txt_count;
    KNTxtEntry* txt_entries;
} KNResolveReply;

#if defined(_WIN64)
    typedef uint64_t KNSocket;
#define KN_INVALID_SOCKET ((KNSocket)-1)
#else
    typedef int KNSocket;
#define KN_INVALID_SOCKET (-1)
#endif

typedef struct KNDiscovery KNDiscovery;

typedef struct KNServiceHandle KNServiceHandle;
typedef struct KNBrowseHandle KNBrowseHandle;
typedef struct KNResolveHandle KNResolveHandle;
typedef struct KNQueryHandle KNQueryHandle;

typedef void (*KNRegisterCallback)(const KNBrowseReply* reply, void* user_data);
typedef void (*KNBrowseCallback)(const KNBrowseReply* reply, void* user_data);
typedef void (*KNResolveCallback)(const KNResolveReply* reply, void* user_data);
typedef void (*KNQueryCallback)(const KNIpAddress* ip, void* user_data);

KNOTDISCOVERY_EXPORT
KNDiscovery* KNDiscoveryCreate();

KNOTDISCOVERY_EXPORT
void KNDiscoveryFree(KNDiscovery* discovery);

KNOTDISCOVERY_EXPORT
KNServiceHandle* KNRegisterService(
    KNDiscovery* core,
    const char* service_name,
    const char* reg_type,
    uint16_t port,
    const KNTxtEntry* txt_entries,
    size_t txt_count);

KNOTDISCOVERY_EXPORT
size_t KNServiceGetSockets(KNDiscovery* core, KNServiceHandle* handle, KNSocket* sockets, size_t count);

KNOTDISCOVERY_EXPORT
void KNServiceNotify(KNDiscovery* core, KNServiceHandle* handle, KNSocket socket);

KNOTDISCOVERY_EXPORT
void KNServiceStop(KNDiscovery* core, KNServiceHandle* handle);

KNOTDISCOVERY_EXPORT
KNBrowseHandle* KNBrowseServices(
    KNDiscovery* core,
    const char* reg_type,
    const char* domain,
    KNBrowseCallback callback,
    void* user_data);

KNOTDISCOVERY_EXPORT
size_t KNBrowseGetSockets(KNDiscovery* core, KNBrowseHandle* handle, KNSocket* sockets, size_t count);

KNOTDISCOVERY_EXPORT
void KNBrowseNotify(KNDiscovery* core, KNBrowseHandle* handle, KNSocket socket);

KNOTDISCOVERY_EXPORT
void KNBrowseStop(KNDiscovery* core, KNBrowseHandle* handle);

KNOTDISCOVERY_EXPORT
KNResolveHandle* KNResolveService(
    KNDiscovery* core,
    const char* service_name,
    const char* reg_type,
    const char* domain,
    KNResolveCallback callback,
    void* user_data);

KNOTDISCOVERY_EXPORT
size_t KNResolveGetSockets(KNDiscovery* core, KNResolveHandle* handle, KNSocket* sockets, size_t count);

KNOTDISCOVERY_EXPORT
void KNResolveNotify(KNDiscovery* core, KNResolveHandle* handle, KNSocket socket);

KNOTDISCOVERY_EXPORT
void KNResolveStop(KNDiscovery* core, KNResolveHandle* handle);

KNOTDISCOVERY_EXPORT
KNQueryHandle* KNQueryIpAddress(
    KNDiscovery* core,
    const char* host_name,
    KNIpFamily ip_family,
    KNQueryCallback callback,
    void* user_data);

KNOTDISCOVERY_EXPORT
size_t KNQueryGetSockets(KNDiscovery* core, KNQueryHandle* handle, KNSocket* sockets, size_t count);

KNOTDISCOVERY_EXPORT
void KNQueryNotify(KNDiscovery* core, KNQueryHandle* handle, KNSocket socket);

KNOTDISCOVERY_EXPORT
void KNQueryStop(KNDiscovery* core, KNQueryHandle* handle);

#ifdef __cplusplus
} // extern "C"
#endif

#endif //KNOT_DISCOVERY_H
