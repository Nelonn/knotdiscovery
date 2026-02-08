/*
 * This file is part of knotdiscovery.
 *
 * For license and copyright information please follow this link:
 * https://github.com/nelonn/knotdiscovery/blob/master/README.md
 */

#pragma once

#include <knot/discovery.h>

typedef struct KNDiscoveryAdapter KNDiscoveryAdapter;

struct KNDiscoveryAdapter {
    KNServiceHandle* (*RegisterService)(
            KNDiscoveryAdapter* this,
            const char* service_name,
            const char* reg_type,
            uint16_t port,
            const KNTxtEntry* txt_entries,
            size_t txt_count);
    size_t (*ServiceGetSockets)(KNServiceHandle* handle, KNSocket* sockets, size_t count);
    void (*ServiceNotify)(KNServiceHandle* handle, KNSocket socket);
    void (*ServiceStop)(KNServiceHandle* handle);
    KNBrowseHandle* (*BrowseServices)(
            KNDiscoveryAdapter* this,
            const char* reg_type,
            const char* domain,
            KNBrowseCallback callback,
            void* user_data);
    size_t (*BrowseGetSockets)(KNBrowseHandle* handle, KNSocket* sockets, size_t count);
    void (*BrowseNotify)(KNBrowseHandle* handle, KNSocket socket);
    void (*BrowseStop)(KNBrowseHandle* handle);
    KNResolveHandle* (*ResolveService)(
            KNDiscoveryAdapter* this,
            const char* service_name,
            const char* reg_type,
            const char* domain,
            KNResolveCallback callback,
            void* user_data);
    size_t (*ResolveGetSockets)(KNResolveHandle* handle, KNSocket* sockets, size_t count);
    void (*ResolveNotify)(KNResolveHandle* handle, KNSocket socket);
    void (*ResolveStop)(KNResolveHandle* handle);
    KNQueryHandle* (*QueryIpAddress)(
            KNDiscoveryAdapter* this,
            const char* host_name,
            KNIpFamily ip_family,
            KNQueryCallback callback,
            void* user_data);
    size_t (*QueryGetSockets)(KNQueryHandle* handle, KNSocket* sockets, size_t count);
    void (*QueryNotify)(KNQueryHandle* handle, KNSocket socket);
    void (*QueryStop)(KNQueryHandle* handle);
    void (*free)(KNDiscoveryAdapter* this);

    void* internal;
};

KNDiscoveryAdapter* KNDiscovery_android_create();
KNDiscoveryAdapter* KNDiscovery_avahi_create();
KNDiscoveryAdapter* KNDiscovery_bonjour_create();
KNDiscoveryAdapter* KNDiscovery_esp_create();
KNDiscoveryAdapter* KNDiscovery_mdnsh_create();
