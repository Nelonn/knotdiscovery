/*
 * This file is part of knotdiscovery.
 *
 * For license and copyright information please follow this link:
 * https://github.com/nelonn/knotdiscovery/blob/master/README.md
 */

#include "adapter.h"

#include <stdlib.h>

KNDiscovery* KNDiscoveryCreate() {
    KNDiscoveryAdapter* adapter = NULL;

    // Try platform-specific adapters first
#if defined(KNOTDISCOVERY_ANDROID)
    adapter = KNDiscovery_android_create();
#elif defined(KNOTDISCOVERY_ESP)
    adapter = KNDiscovery_esp_create();
#elif defined(KNOTDISCOVERY_BONJOUR)
    adapter = KNDiscovery_bonjour_create();
#if defined(KNOTDISCOVERY_AVAHI)
    if (!adapter) {
        adapter = KNDiscovery_avahi_create();
    }
#endif
#elif defined(KNOTDISCOVERY_AVAHI)
    adapter = KNDiscovery_avahi_create();
#endif

    // Fallback to generic mDNSh
#if defined(KNOTDISCOVERY_MDNSH)
    if (!adapter) {
        adapter = KNDiscovery_mdnsh_create();
    }
#endif

    if (!adapter) {
        return NULL;
    }

    return (KNDiscovery*)adapter;
}

void KNDiscoveryFree(KNDiscovery* discovery) {
    if (!discovery) return;
    KNDiscoveryAdapter* adapter = (KNDiscoveryAdapter*)discovery;
    adapter->free(adapter);
}

KNServiceHandle* KNRegisterService(
        KNDiscovery* core,
        const char* service_name,
        const char* reg_type,
        uint16_t port,
        const KNTxtEntry* txt_entries,
        size_t txt_count) {
    if (!core) return NULL;
    KNDiscoveryAdapter* adapter = (KNDiscoveryAdapter*)core;
    return adapter->RegisterService(adapter, service_name, reg_type, port, txt_entries, txt_count);
}

size_t KNServiceGetSockets(KNDiscovery* core, KNServiceHandle* handle, KNSocket* sockets, size_t count) {
    if (!core) return 0;
    return ((KNDiscoveryAdapter*)core)->ServiceGetSockets(handle, sockets, count);
}

void KNServiceNotify(KNDiscovery* core, KNServiceHandle* handle, KNSocket socket) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->ServiceNotify(handle, socket);
}

void KNServiceStop(KNDiscovery* core, KNServiceHandle* handle) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->ServiceStop(handle);
}

KNBrowseHandle* KNBrowseServices(
        KNDiscovery* core,
        const char* reg_type,
        const char* domain,
        KNBrowseCallback callback,
        void* user_data) {
    if (!core) return NULL;
    KNDiscoveryAdapter* adapter = (KNDiscoveryAdapter*)core;
    return adapter->BrowseServices(adapter, reg_type, domain, callback, user_data);
}

size_t KNBrowseGetSockets(KNDiscovery* core, KNBrowseHandle* handle, KNSocket* sockets, size_t count) {
    if (!core) return 0;
    return ((KNDiscoveryAdapter*)core)->BrowseGetSockets(handle, sockets, count);
}

void KNBrowseNotify(KNDiscovery* core, KNBrowseHandle* handle, KNSocket socket) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->BrowseNotify(handle, socket);
}

void KNBrowseStop(KNDiscovery* core, KNBrowseHandle* handle) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->BrowseStop(handle);
}

KNResolveHandle* KNResolveService(
        KNDiscovery* core,
        const char* service_name,
        const char* reg_type,
        const char* domain,
        KNResolveCallback callback,
        void* user_data) {
    if (!core) return NULL;
    KNDiscoveryAdapter* adapter = (KNDiscoveryAdapter*)core;
    return adapter->ResolveService(adapter, service_name, reg_type, domain, callback, user_data);
}

size_t KNResolveGetSockets(KNDiscovery* core, KNResolveHandle* handle, KNSocket* sockets, size_t count) {
    if (!core) return 0;
    return ((KNDiscoveryAdapter*)core)->ResolveGetSockets(handle, sockets, count);
}

void KNResolveNotify(KNDiscovery* core, KNResolveHandle* handle, KNSocket socket) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->ResolveNotify(handle, socket);
}

void KNResolveStop(KNDiscovery* core, KNResolveHandle* handle) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->ResolveStop(handle);
}

KNQueryHandle* KNQueryIpAddress(
        KNDiscovery* core,
        const char* host_name,
        KNIpFamily ip_family,
        KNQueryCallback callback,
        void* user_data) {
    if (!core) return NULL;
    KNDiscoveryAdapter* adapter = (KNDiscoveryAdapter*)core;
    return adapter->QueryIpAddress(adapter, host_name, ip_family, callback, user_data);
}

size_t KNQueryGetSockets(KNDiscovery* core, KNQueryHandle* handle, KNSocket* sockets, size_t count) {
    if (!core) return 0;
    return ((KNDiscoveryAdapter*)core)->QueryGetSockets(handle, sockets, count);
}

void KNQueryNotify(KNDiscovery* core, KNQueryHandle* handle, KNSocket socket) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->QueryNotify(handle, socket);
}

void KNQueryStop(KNDiscovery* core, KNQueryHandle* handle) {
    if (!core) return;
    ((KNDiscoveryAdapter*)core)->QueryStop(handle);
}
