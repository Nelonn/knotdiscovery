/*
 * This file is part of knotdiscovery.
 *
 * For license and copyright information please follow this link:
 * https://github.com/nelonn/knotdiscovery/blob/master/README.md
 */

#include "adapter.h"
#include "mdns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

#if defined(_WIN32)
#define gethostname_func gethostname
static char* strndup(const char *s, size_t n) {
  size_t len = strlen(s);
  if (len > n)
    len = n;
  char *res = (char *)malloc(len + 1);
  if (res) {
    memcpy(res, s, len);
    res[len] = '\0';
  }
  return res;
}
#else
#define gethostname_func gethostname
#endif

struct KNServiceHandle {
  mdns_sock_t *sockets;
  size_t socket_count;
  mdns_string_t service_instance;
  mdns_string_t service_type;
  mdns_string_t hostname;
  uint16_t port;
  mdns_record_t *txt_records;
  size_t txt_count;
  KNIpAddress *addresses;
  size_t address_count;
};

struct KNBrowseHandle {
  mdns_sock_t *sockets;
  size_t socket_count;
  mdns_string_t service_type;
  mdns_string_t domain;
  KNBrowseCallback callback;
  void *user_data;
  int running;
};

struct KNResolveHandle {
  mdns_sock_t *sockets;
  size_t socket_count;
  mdns_string_t service_name;
  mdns_string_t service_type;
  mdns_string_t domain;
  KNResolveCallback callback;
  void *user_data;
  int running;
  char hostname_buffer[256];
};

struct KNQueryHandle {
  mdns_sock_t *sockets;
  size_t socket_count;
  mdns_string_t host_name;
  KNIpFamily ip_family;
  KNQueryCallback callback;
  void *user_data;
  int running;
};

static const char *dns_sd_name = "_services._dns-sd._udp.local.";

static void sockaddrToKNIpAddress(const struct sockaddr *addr,
                                  KNIpAddress *ip_addr) {
  if (!addr || !ip_addr)
    return;
  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
    ip_addr->family = KN_IP_V4;
    memcpy(ip_addr->addr.v4, &addr4->sin_addr, 4);
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
    ip_addr->family = KN_IP_V6;
    memcpy(ip_addr->addr.v6, &addr6->sin6_addr, 16);
  }
}

static struct sockaddr_in knIpToSockaddr(const KNIpAddress *ip) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  if (ip) {
    memcpy(&addr.sin_addr, ip->addr.v4, 4);
  }
  return addr;
}

static struct sockaddr_in6 knIpToSockaddr6(const KNIpAddress *ip) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  if (ip) {
    memcpy(&addr.sin6_addr, ip->addr.v6, 16);
  }
  return addr;
}

static int countCommonLeadingBits(uint32_t int1, uint32_t int2) {
  int count = 0;
  while (int1 != 0 && int2 != 0) {
    if ((int1 & 0x80000000) == (int2 & 0x80000000)) {
      count++;
      int1 <<= 1;
      int2 <<= 1;
    } else {
      break;
    }
  }
  return count;
}

static KNIpAddress findBestAddressMatchV4(const KNServiceHandle *handle,
                                          const struct sockaddr *from) {
  if (handle->address_count == 0 || !from || from->sa_family != AF_INET) {
    for (size_t i = 0; i < handle->address_count; i++) {
      if (handle->addresses[i].family == KN_IP_V4)
        return handle->addresses[i];
    }
    KNIpAddress empty = {0};
    return empty;
  }
  struct sockaddr_in *other_addr = (struct sockaddr_in *)from;
  uint32_t other_ip = ntohl(other_addr->sin_addr.s_addr);
  int best_bits = -1;
  size_t best_idx = 0;
  int found = 0;
  for (size_t i = 0; i < handle->address_count; i++) {
    if (handle->addresses[i].family == KN_IP_V4) {
      uint32_t my_ip;
      memcpy(&my_ip, handle->addresses[i].addr.v4, 4);
      my_ip = ntohl(my_ip);
      int bits = countCommonLeadingBits(my_ip, other_ip);
      if (bits > best_bits) {
        best_bits = bits;
        best_idx = i;
        found = 1;
      }
    }
  }
  if (found)
    return handle->addresses[best_idx];
  KNIpAddress empty = {0};
  return empty;
}

static KNIpAddress findBestAddressMatchV6(const struct KNServiceHandle *handle,
                                          const struct sockaddr *from) {
  for (size_t i = 0; i < handle->address_count; i++) {
    if (handle->addresses[i].family == KN_IP_V6)
      return handle->addresses[i];
  }
  KNIpAddress empty = {0};
  return empty;
}

static mdns_record_t createMdnsRecord(const struct KNServiceHandle *handle,
                                      mdns_record_type_t type,
                                      const struct sockaddr *from,
                                      size_t txt_index) {
  mdns_record_t answer;
  memset(&answer, 0, sizeof(answer));
  answer.type = type;
  switch (type) {
  case MDNS_RECORDTYPE_PTR:
    answer.name = handle->service_type;
    answer.data.ptr.name = handle->service_instance;
    break;
  case MDNS_RECORDTYPE_SRV:
    answer.name = handle->service_instance;
    answer.data.srv.name = handle->hostname;
    answer.data.srv.port = handle->port;
    break;
  case MDNS_RECORDTYPE_A: {
    answer.name = handle->hostname;
    KNIpAddress ip = findBestAddressMatchV4(handle, from);
    answer.data.a.addr = knIpToSockaddr(&ip);
    break;
  }
  case MDNS_RECORDTYPE_AAAA: {
    answer.name = handle->hostname;
    KNIpAddress ip = findBestAddressMatchV6(handle, from);
    answer.data.aaaa.addr = knIpToSockaddr6(&ip);
    break;
  }
  case MDNS_RECORDTYPE_TXT:
    answer.name = handle->service_instance;
    answer.data.txt.key = handle->txt_records[txt_index].data.txt.key;
    answer.data.txt.value = handle->txt_records[txt_index].data.txt.value;
    break;
  default:
    break;
  }
  return answer;
}

static mdns_sock_t *openServiceSockets(size_t *socket_count, int port) {
  mdns_sock_t *sockets = NULL;
  *socket_count = 0;
#if defined(_WIN32)
  IP_ADAPTER_ADDRESSES *adapter_address = NULL;
  ULONG address_size = 8000;
  unsigned int ret;
  do {
    adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
    ret = GetAdaptersAddresses(AF_UNSPEC,
                               GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
                               NULL, adapter_address, &address_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(adapter_address);
      adapter_address = NULL;
    }
  } while (ret == ERROR_BUFFER_OVERFLOW);
  if (ret == NO_ERROR) {
    IP_ADAPTER_ADDRESSES *adapter = adapter_address;
    while (adapter) {
      if (adapter->OperStatus == IfOperStatusUp) {
        IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
        while (unicast) {
          if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
            int sock = mdns_socket_open_ipv4(
                (struct sockaddr_in *)unicast->Address.lpSockaddr);
            if (sock >= 0) {
              sockets = (mdns_sock_t *)realloc(
                  sockets, sizeof(mdns_sock_t) * (*socket_count + 1));
              sockets[(*socket_count)++] = sock;
            }
          } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
            int sock = mdns_socket_open_ipv6(
                (struct sockaddr_in6 *)unicast->Address.lpSockaddr);
            if (sock >= 0) {
              sockets = (mdns_sock_t *)realloc(
                  sockets, sizeof(mdns_sock_t) * (*socket_count + 1));
              sockets[(*socket_count)++] = sock;
            }
          }
          unicast = unicast->Next;
        }
      }
      adapter = adapter->Next;
    }
  }
  free(adapter_address);
#else
  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) == 0) {
    struct ifaddrs *ifa = ifaddr;
    while (ifa) {
      if (ifa->ifa_addr) {
        if (ifa->ifa_addr->sa_family == AF_INET) {
          struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
          if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            mdns_sock_t sock = mdns_socket_open_ipv4(saddr);
            if (sock >= 0) {
              sockets = (mdns_sock_t *)realloc(
                  sockets, sizeof(mdns_sock_t) * (*socket_count + 1));
              sockets[(*socket_count)++] = sock;
            }
          }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
          struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
          static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                                    0, 0, 0, 0, 0, 0, 0, 1};
          if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) != 0) {
            mdns_sock_t sock = mdns_socket_open_ipv6(saddr);
            if (sock >= 0) {
              sockets = (mdns_sock_t *)realloc(
                  sockets, sizeof(mdns_sock_t) * (*socket_count + 1));
              sockets[(*socket_count)++] = sock;
            }
          }
        }
      }
      ifa = ifa->ifa_next;
    }
    freeifaddrs(ifaddr);
  }
#endif
  return sockets;
}

static void closeSockets(mdns_sock_t *sockets, size_t socket_count) {
  for (size_t i = 0; i < socket_count; i++)
    mdns_socket_close(sockets[i]);
  free(sockets);
}

static void sendMulticastAnnounce(KNServiceHandle *handle, int is_goodbye) {
  mdns_record_t ptr_record =
      createMdnsRecord(handle, MDNS_RECORDTYPE_PTR, NULL, 0);
  mdns_record_t additional[16];
  size_t add_count = 0;
  additional[add_count++] =
      createMdnsRecord(handle, MDNS_RECORDTYPE_SRV, NULL, 0);
  additional[add_count++] =
      createMdnsRecord(handle, MDNS_RECORDTYPE_A, NULL, 0);
  for (size_t i = 0; i < handle->txt_count && add_count < 16; i++) {
    additional[add_count++] =
        createMdnsRecord(handle, MDNS_RECORDTYPE_TXT, NULL, i);
  }
  static char buffer[2048];
  for (size_t i = 0; i < handle->socket_count; i++) {
    if (is_goodbye)
      mdns_goodbye_multicast(handle->sockets[i], buffer, sizeof(buffer),
                             ptr_record, NULL, 0, additional, add_count);
    else
      mdns_announce_multicast(handle->sockets[i], buffer, sizeof(buffer),
                              ptr_record, NULL, 0, additional, add_count);
  }
}

static int serviceCallback(mdns_sock_t sock, const struct sockaddr *from,
                           size_t addrlen, mdns_entry_type_t entry,
                           uint16_t query_id, uint16_t rtype, uint16_t rclass,
                           uint32_t ttl, const void *data, size_t size,
                           size_t name_offset, size_t name_length,
                           size_t record_offset, size_t record_length,
                           void *user_data) {
  KNServiceHandle *handle = (KNServiceHandle *)user_data;
  if (entry != MDNS_ENTRYTYPE_QUESTION)
    return 0;
  char name_buffer[256];
  mdns_string_t name = mdns_string_extract(data, size, &name_offset,
                                           name_buffer, sizeof(name_buffer));
  static char sendbuffer[2048];
  int ret = 0;
  if (name.length == strlen(dns_sd_name) &&
      memcmp(name.str, dns_sd_name, name.length) == 0) {
    if (rtype == MDNS_RECORDTYPE_PTR || rtype == MDNS_RECORDTYPE_ANY) {
      mdns_record_t answer =
          createMdnsRecord(handle, MDNS_RECORDTYPE_PTR, from, 0);
      if (rclass & MDNS_UNICAST_RESPONSE)
        ret = mdns_query_answer_unicast(
            sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
            rtype, name.str, name.length, answer, NULL, 0, NULL, 0);
      else
        ret = mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer),
                                          answer, NULL, 0, NULL, 0);
    }
  } else if (name.length == handle->service_type.length &&
             memcmp(name.str, handle->service_type.str, name.length) == 0) {
    if (rtype == MDNS_RECORDTYPE_PTR || rtype == MDNS_RECORDTYPE_ANY) {
      mdns_record_t answer =
          createMdnsRecord(handle, MDNS_RECORDTYPE_PTR, from, 0);
      mdns_record_t additional[16];
      size_t add_count = 0;
      additional[add_count++] =
          createMdnsRecord(handle, MDNS_RECORDTYPE_SRV, from, 0);
      additional[add_count++] =
          createMdnsRecord(handle, MDNS_RECORDTYPE_A, from, 0);
      for (size_t i = 0; i < handle->txt_count && add_count < 16; i++)
        additional[add_count++] =
            createMdnsRecord(handle, MDNS_RECORDTYPE_TXT, from, i);
      if (rclass & MDNS_UNICAST_RESPONSE)
        ret = mdns_query_answer_unicast(sock, from, addrlen, sendbuffer,
                                        sizeof(sendbuffer), query_id, rtype,
                                        name.str, name.length, answer, NULL, 0,
                                        additional, add_count);
      else
        ret =
            mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer),
                                        answer, NULL, 0, additional, add_count);
    }
  } else if (name.length == handle->service_instance.length &&
             memcmp(name.str, handle->service_instance.str, name.length) == 0) {
    if (rtype == MDNS_RECORDTYPE_SRV || rtype == MDNS_RECORDTYPE_ANY) {
      mdns_record_t answer =
          createMdnsRecord(handle, MDNS_RECORDTYPE_SRV, from, 0);
      mdns_record_t additional[16];
      size_t add_count = 0;
      additional[add_count++] =
          createMdnsRecord(handle, MDNS_RECORDTYPE_A, from, 0);
      for (size_t i = 0; i < handle->txt_count && add_count < 16; i++)
        additional[add_count++] =
            createMdnsRecord(handle, MDNS_RECORDTYPE_TXT, from, i);
      if (rclass & MDNS_UNICAST_RESPONSE)
        ret = mdns_query_answer_unicast(sock, from, addrlen, sendbuffer,
                                        sizeof(sendbuffer), query_id, rtype,
                                        name.str, name.length, answer, NULL, 0,
                                        additional, add_count);
      else
        ret =
            mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer),
                                        answer, NULL, 0, additional, add_count);
    }
  } else if (name.length == handle->hostname.length &&
             memcmp(name.str, handle->hostname.str, name.length) == 0) {
    if (rtype == MDNS_RECORDTYPE_A || rtype == MDNS_RECORDTYPE_ANY) {
      mdns_record_t answer =
          createMdnsRecord(handle, MDNS_RECORDTYPE_A, from, 0);
      if (rclass & MDNS_UNICAST_RESPONSE)
        ret = mdns_query_answer_unicast(
            sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
            rtype, name.str, name.length, answer, NULL, 0, NULL, 0);
      else
        ret = mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer),
                                          answer, NULL, 0, NULL, 0);
    }
  }
  return ret;
}

static int browseCallback(mdns_sock_t sock, const struct sockaddr *from,
                          size_t addrlen, mdns_entry_type_t entry,
                          uint16_t query_id, uint16_t rtype, uint16_t rclass,
                          uint32_t ttl, const void *data, size_t size,
                          size_t name_offset, size_t name_length,
                          size_t record_offset, size_t record_length,
                          void *user_data) {
  KNBrowseHandle *handle = (KNBrowseHandle *)user_data;
  if (entry != MDNS_ENTRYTYPE_ANSWER)
    return 0;
  if (rtype == MDNS_RECORDTYPE_PTR) {
    char service_name_buffer[256];
    mdns_string_t name =
        mdns_record_parse_ptr(data, size, record_offset, record_length,
                              service_name_buffer, sizeof(service_name_buffer));
    if (handle->callback && name.length > 0) {
      KNBrowseReply reply = {0};
      reply.service_name = service_name_buffer;
      reply.reg_type = (char *)handle->service_type.str;
      reply.reply_domain = (char *)handle->domain.str;
      handle->callback(&reply, handle->user_data);
    }
  }
  return 0;
}

static int resolveCallback(mdns_sock_t sock, const struct sockaddr *from,
                           size_t addrlen, mdns_entry_type_t entry,
                           uint16_t query_id, uint16_t rtype, uint16_t rclass,
                           uint32_t ttl, const void *data, size_t size,
                           size_t name_offset, size_t name_length,
                           size_t record_offset, size_t record_length,
                           void *user_data) {
  KNResolveHandle *handle = (KNResolveHandle *)user_data;
  if (entry != MDNS_ENTRYTYPE_ANSWER)
    return 0;
  if (rtype == MDNS_RECORDTYPE_SRV) {
    mdns_record_srv_t srv = mdns_record_parse_srv(
        data, size, record_offset, record_length, handle->hostname_buffer,
        sizeof(handle->hostname_buffer));
    if (handle->callback) {
      KNResolveReply reply = {0};
      reply.port = srv.port;
      reply.host_name = handle->hostname_buffer;
      handle->callback(&reply, handle->user_data);
    }
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    if (handle->callback) {
      KNIpAddress ip_addr;
      sockaddrToKNIpAddress((struct sockaddr *)&addr, &ip_addr);
      KNResolveReply reply = {0};
      reply.host_name = handle->hostname_buffer;
      reply.ip = &ip_addr;
      handle->callback(&reply, handle->user_data);
    }
  } else if (rtype == MDNS_RECORDTYPE_AAAA) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    if (handle->callback) {
      KNIpAddress ip_addr;
      sockaddrToKNIpAddress((struct sockaddr *)&addr, &ip_addr);
      KNResolveReply reply = {0};
      reply.host_name = handle->hostname_buffer;
      reply.ip = &ip_addr;
      handle->callback(&reply, handle->user_data);
    }
  } else if (rtype == MDNS_RECORDTYPE_TXT) {
    mdns_record_txt_t txt[16];
    size_t parsed = mdns_record_parse_txt(data, size, record_offset,
                                          record_length, txt, 16);
    if (handle->callback && parsed > 0) {
      KNTxtEntry *entries = (KNTxtEntry *)calloc(parsed, sizeof(KNTxtEntry));
      for (size_t i = 0; i < parsed; i++) {
        entries[i].key = strndup(txt[i].key.str, txt[i].key.length);
        entries[i].value = strndup(txt[i].value.str, txt[i].value.length);
      }
      KNResolveReply reply = {0};
      reply.host_name = handle->hostname_buffer;
      reply.txt_count = parsed;
      reply.txt_entries = entries;
      handle->callback(&reply, handle->user_data);
      for (size_t i = 0; i < parsed; i++) {
        free(entries[i].key);
        free(entries[i].value);
      }
      free(entries);
    }
  }
  return 0;
}

static int queryCallback(mdns_sock_t sock, const struct sockaddr *from,
                         size_t addrlen, mdns_entry_type_t entry,
                         uint16_t query_id, uint16_t rtype, uint16_t rclass,
                         uint32_t ttl, const void *data, size_t size,
                         size_t name_offset, size_t name_length,
                         size_t record_offset, size_t record_length,
                         void *user_data) {
  KNQueryHandle *handle = (KNQueryHandle *)user_data;
  if (entry != MDNS_ENTRYTYPE_ANSWER) return 0;
  KNIpAddress ip_addr = {0};
  if (rtype == MDNS_RECORDTYPE_A && handle->ip_family != KN_IP_V6) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    sockaddrToKNIpAddress((struct sockaddr *)&addr, &ip_addr);
    if (handle->callback) {
      handle->callback(&ip_addr, handle->user_data);
    }
  } else if (rtype == MDNS_RECORDTYPE_AAAA && handle->ip_family != KN_IP_V4) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    sockaddrToKNIpAddress((struct sockaddr *)&addr, &ip_addr);
    if (handle->callback) {
      handle->callback(&ip_addr, handle->user_data);
    }
  }
  return 0;
}

static KNServiceHandle *
MDNSH_RegisterService(KNDiscoveryAdapter *this, const char *service_name,
                      const char *reg_type, uint16_t port,
                      const KNTxtEntry *txt_entries, size_t txt_count) {
  KNServiceHandle *handle =
      (KNServiceHandle *)calloc(1, sizeof(KNServiceHandle));
  if (!handle)
    return NULL;
  handle->sockets = openServiceSockets(&handle->socket_count, 0);
  if (!handle->sockets || handle->socket_count == 0) {
    free(handle);
    return NULL;
  }
  char hostname[256];
  gethostname(hostname, sizeof(hostname));
  char full_hostname[512];
  snprintf(full_hostname, sizeof(full_hostname), "%s.local.", hostname);
  handle->hostname.str = strdup(full_hostname);
  handle->hostname.length = strlen(full_hostname);
  char full_reg_type[256];
  if (reg_type[strlen(reg_type) - 1] == '.')
    snprintf(full_reg_type, sizeof(full_reg_type), "%s", reg_type);
  else
    snprintf(full_reg_type, sizeof(full_reg_type), "%s.", reg_type);
  handle->service_type.str = strdup(full_reg_type);
  handle->service_type.length = strlen(full_reg_type);
  char full_instance[512];
  snprintf(full_instance, sizeof(full_instance), "%s.%s", service_name,
           full_reg_type);
  handle->service_instance.str = strdup(full_instance);
  handle->service_instance.length = strlen(full_instance);
  handle->port = port;
  if (txt_count > 0 && txt_entries) {
    handle->txt_records =
        (mdns_record_t *)calloc(txt_count, sizeof(mdns_record_t));
    handle->txt_count = txt_count;
    for (size_t i = 0; i < txt_count; i++) {
      handle->txt_records[i].type = MDNS_RECORDTYPE_TXT;
      handle->txt_records[i].data.txt.key.str = strdup(txt_entries[i].key);
      handle->txt_records[i].data.txt.key.length = strlen(txt_entries[i].key);
      handle->txt_records[i].data.txt.value.str = strdup(txt_entries[i].value);
      handle->txt_records[i].data.txt.value.length =
          strlen(txt_entries[i].value);
    }
  }
#if defined(_WIN32)
  IP_ADAPTER_ADDRESSES *adapter_address = NULL;
  ULONG address_size = 8000;
  unsigned int ret;
  do {
    adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
    ret = GetAdaptersAddresses(AF_UNSPEC,
                               GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
                               NULL, adapter_address, &address_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(adapter_address);
      adapter_address = NULL;
    }
  } while (ret == ERROR_BUFFER_OVERFLOW);
  if (ret == NO_ERROR) {
    IP_ADAPTER_ADDRESSES *adapter = adapter_address;
    while (adapter) {
      if (adapter->OperStatus == IfOperStatusUp) {
        IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
        while (unicast) {
          handle->addresses = (KNIpAddress *)realloc(
              handle->addresses,
              sizeof(KNIpAddress) * (handle->address_count + 1));
          sockaddrToKNIpAddress(unicast->Address.lpSockaddr,
                                &handle->addresses[handle->address_count++]);
          unicast = unicast->Next;
        }
      }
      adapter = adapter->Next;
    }
  }
  free(adapter_address);
#else
  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) == 0) {
    struct ifaddrs *ifa = ifaddr;
    while (ifa) {
      if (ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET ||
                            ifa->ifa_addr->sa_family == AF_INET6)) {
        handle->addresses = (KNIpAddress *)realloc(
            handle->addresses,
            sizeof(KNIpAddress) * (handle->address_count + 1));
        sockaddrToKNIpAddress(ifa->ifa_addr,
                              &handle->addresses[handle->address_count++]);
      }
      ifa = ifa->ifa_next;
    }
    freeifaddrs(ifaddr);
  }
#endif
  for (size_t i = 0; i < handle->socket_count; i++) {
    static char buffer[2048];
    mdns_socket_listen(handle->sockets[i], buffer, sizeof(buffer),
                       serviceCallback, handle);
  }
  sendMulticastAnnounce(handle, 0);
  return handle;
}

static size_t MDNSH_ServiceGetSockets(KNServiceHandle *handle,
                                      KNSocket *sockets, size_t count) {
  if (!handle)
    return 0;
  size_t copy_count =
      handle->socket_count < count ? handle->socket_count : count;
  if (sockets && copy_count > 0)
    for (size_t i = 0; i < copy_count; i++)
      sockets[i] = handle->sockets[i];
  return handle->socket_count;
}

static void MDNSH_ServiceNotify(KNServiceHandle *handle, KNSocket socket) {
  if (!handle)
    return;
  int found = 0;
  for (size_t i = 0; i < handle->socket_count; i++)
    if (handle->sockets[i] == socket) {
      found = 1;
      break;
    }
  if (!found)
    return;
  static char buffer[2048];
  mdns_socket_listen(socket, buffer, sizeof(buffer), serviceCallback, handle);
}

static void MDNSH_ServiceStop(KNServiceHandle *handle) {
  if (!handle)
    return;
  sendMulticastAnnounce(handle, 1);
  closeSockets(handle->sockets, handle->socket_count);
  if (handle->service_instance.str) {
    free((void *)handle->service_instance.str);
  }
  if (handle->service_type.str) {
    free((void *)handle->service_type.str);
  }
  if (handle->hostname.str) {
    free((void *)handle->hostname.str);
  }
  for (size_t i = 0; i < handle->txt_count; i++) {
    if (handle->txt_records[i].data.txt.key.str) {
      free((void *)handle->txt_records[i].data.txt.key.str);
    }
    if (handle->txt_records[i].data.txt.value.str) {
      free((void *)handle->txt_records[i].data.txt.value.str);
    }
  }
  if (handle->txt_records) {
    free(handle->txt_records);
  }
  if (handle->addresses) {
    free(handle->addresses);
  }
  free(handle);
}

static KNBrowseHandle *MDNSH_BrowseServices(KNDiscoveryAdapter *this,
                                            const char *reg_type,
                                            const char *domain,
                                            KNBrowseCallback callback,
                                            void *user_data) {
  KNBrowseHandle *handle = (KNBrowseHandle *)calloc(1, sizeof(KNBrowseHandle));
  if (!handle)
    return NULL;
  handle->sockets = openServiceSockets(&handle->socket_count, 0);
  if (!handle->sockets || handle->socket_count == 0) {
    free(handle);
    return NULL;
  }
  handle->service_type.str = strdup(reg_type);
  handle->service_type.length = strlen(reg_type);
  if (domain) {
    handle->domain.str = strdup(domain);
    handle->domain.length = strlen(domain);
  } else {
    handle->domain.str = strdup("local.");
    handle->domain.length = 6;
  }
  handle->callback = callback;
  handle->user_data = user_data;
  handle->running = 1;
  for (size_t i = 0; i < handle->socket_count; i++)
    mdns_query_send(handle->sockets[i], MDNS_RECORDTYPE_PTR, reg_type,
                    strlen(reg_type), NULL, 0, 0);
  return handle;
}

static size_t MDNSH_BrowseGetSockets(KNBrowseHandle *handle, KNSocket *sockets,
                                     size_t count) {
  if (!handle)
    return 0;
  size_t copy_count =
      handle->socket_count < count ? handle->socket_count : count;
  if (sockets && copy_count > 0)
    for (size_t i = 0; i < copy_count; i++)
      sockets[i] = handle->sockets[i];
  return handle->socket_count;
}

static void MDNSH_BrowseNotify(KNBrowseHandle *handle, KNSocket socket) {
  if (!handle || !handle->running)
    return;
  int found = 0;
  for (size_t i = 0; i < handle->socket_count; i++)
    if (handle->sockets[i] == socket) {
      found = 1;
      break;
    }
  if (!found)
    return;
  static char buffer[2048];
  mdns_query_recv(socket, buffer, sizeof(buffer), browseCallback, handle, 0);
}

static void MDNSH_BrowseStop(KNBrowseHandle *handle) {
  if (!handle)
    return;
  handle->running = 0;
  closeSockets(handle->sockets, handle->socket_count);
  if (handle->service_type.str)
    free((void *)handle->service_type.str);
  if (handle->domain.str)
    free((void *)handle->domain.str);
  free(handle);
}

static KNResolveHandle *
MDNSH_ResolveService(KNDiscoveryAdapter *this, const char *service_name,
                     const char *reg_type, const char *domain,
                     KNResolveCallback callback, void *user_data) {
  KNResolveHandle *handle =
      (KNResolveHandle *)calloc(1, sizeof(KNResolveHandle));
  if (!handle)
    return NULL;
  handle->sockets = openServiceSockets(&handle->socket_count, 0);
  if (!handle->sockets || handle->socket_count == 0) {
    free(handle);
    return NULL;
  }
  handle->service_name.str = strdup(service_name);
  handle->service_name.length = strlen(service_name);
  handle->service_type.str = strdup(reg_type);
  handle->service_type.length = strlen(reg_type);
  if (domain) {
    handle->domain.str = strdup(domain);
    handle->domain.length = strlen(domain);
  } else {
    handle->domain.str = strdup("local.");
    handle->domain.length = 6;
  }
  handle->callback = callback;
  handle->user_data = user_data;
  handle->running = 1;
  char full_name[512];
  if (domain && strlen(domain) > 0)
    snprintf(full_name, sizeof(full_name), "%s.%s.%s", service_name, reg_type,
             domain);
  else
    snprintf(full_name, sizeof(full_name), "%s.%s.local.", service_name,
             reg_type);
  mdns_query_t query;
  query.type = MDNS_RECORDTYPE_PTR;
  query.name = full_name;
  query.length = strlen(full_name);
  static char buffer[2048];
  for (size_t i = 0; i < handle->socket_count; i++)
    mdns_multiquery_send(handle->sockets[i], &query, 1, buffer, sizeof(buffer),
                         0);
  return handle;
}

static size_t MDNSH_ResolveGetSockets(KNResolveHandle *handle,
                                      KNSocket *sockets, size_t count) {
  if (!handle)
    return 0;
  size_t copy_count =
      handle->socket_count < count ? handle->socket_count : count;
  if (sockets && copy_count > 0)
    for (size_t i = 0; i < copy_count; i++)
      sockets[i] = handle->sockets[i];
  return handle->socket_count;
}

static void MDNSH_ResolveNotify(KNResolveHandle *handle, KNSocket socket) {
  if (!handle || !handle->running)
    return;
  int found = 0;
  for (size_t i = 0; i < handle->socket_count; i++)
    if (handle->sockets[i] == socket) {
      found = 1;
      break;
    }
  if (!found)
    return;
  static char buffer[2048];
  mdns_query_recv(socket, buffer, sizeof(buffer), resolveCallback, handle, 0);
}

static void MDNSH_ResolveStop(KNResolveHandle *handle) {
  if (!handle)
    return;
  handle->running = 0;
  closeSockets(handle->sockets, handle->socket_count);
  if (handle->service_name.str)
    free((void *)handle->service_name.str);
  if (handle->service_type.str)
    free((void *)handle->service_type.str);
  if (handle->domain.str)
    free((void *)handle->domain.str);
  free(handle);
}

static KNQueryHandle *MDNSH_QueryIpAddress(KNDiscoveryAdapter *this,
                                           const char *host_name,
                                           KNIpFamily ip_family,
                                           KNQueryCallback callback,
                                           void *user_data) {
  KNQueryHandle *handle = (KNQueryHandle *)calloc(1, sizeof(KNQueryHandle));
  if (!handle)
    return NULL;
  handle->sockets = openServiceSockets(&handle->socket_count, 0);
  if (!handle->sockets || handle->socket_count == 0) {
    free(handle);
    return NULL;
  }
  handle->host_name.str = strdup(host_name);
  handle->host_name.length = strlen(host_name);
  handle->ip_family = ip_family;
  handle->callback = callback;
  handle->user_data = user_data;
  handle->running = 1;
  for (size_t i = 0; i < handle->socket_count; i++) {
    if (ip_family != KN_IP_V6)
      mdns_query_send(handle->sockets[i], MDNS_RECORDTYPE_A, host_name,
                      strlen(host_name), NULL, 0, 0);
    if (ip_family != KN_IP_V4)
      mdns_query_send(handle->sockets[i], MDNS_RECORDTYPE_AAAA, host_name,
                      strlen(host_name), NULL, 0, 0);
  }
  return handle;
}

static size_t MDNSH_QueryGetSockets(KNQueryHandle *handle, KNSocket *sockets,
                                    size_t count) {
  if (!handle)
    return 0;
  size_t copy_count =
      handle->socket_count < count ? handle->socket_count : count;
  if (sockets && copy_count > 0)
    for (size_t i = 0; i < copy_count; i++)
      sockets[i] = handle->sockets[i];
  return handle->socket_count;
}

static void MDNSH_QueryNotify(KNQueryHandle *handle, KNSocket socket) {
  if (!handle || !handle->running)
    return;
  int found = 0;
  for (size_t i = 0; i < handle->socket_count; i++)
    if (handle->sockets[i] == socket) {
      found = 1;
      break;
    }
  if (!found)
    return;
  static char buffer[2048];
  mdns_query_recv(socket, buffer, sizeof(buffer), queryCallback, handle, 0);
}

static void MDNSH_QueryStop(KNQueryHandle *handle) {
  if (!handle)
    return;
  handle->running = 0;
  closeSockets(handle->sockets, handle->socket_count);
  free((void *)handle->host_name.str);
  free(handle);
}

static void MDNSH_Free(KNDiscoveryAdapter *handle) {
#if defined(_WIN32)
  WSACleanup();
#endif
  free(handle);
}

KNDiscoveryAdapter *KNDiscovery_mdnsh_create() {
#if defined(_WIN32)
  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    return NULL;
#endif
  KNDiscoveryAdapter *adapter = calloc(1, sizeof(KNDiscoveryAdapter));
  if (!adapter)
    return NULL;
  adapter->RegisterService = MDNSH_RegisterService;
  adapter->ServiceGetSockets = MDNSH_ServiceGetSockets;
  adapter->ServiceNotify = MDNSH_ServiceNotify;
  adapter->ServiceStop = MDNSH_ServiceStop;
  adapter->BrowseServices = MDNSH_BrowseServices;
  adapter->BrowseGetSockets = MDNSH_BrowseGetSockets;
  adapter->BrowseNotify = MDNSH_BrowseNotify;
  adapter->BrowseStop = MDNSH_BrowseStop;
  adapter->ResolveService = MDNSH_ResolveService;
  adapter->ResolveGetSockets = MDNSH_ResolveGetSockets;
  adapter->ResolveNotify = MDNSH_ResolveNotify;
  adapter->ResolveStop = MDNSH_ResolveStop;
  adapter->QueryIpAddress = MDNSH_QueryIpAddress;
  adapter->QueryGetSockets = MDNSH_QueryGetSockets;
  adapter->QueryNotify = MDNSH_QueryNotify;
  adapter->QueryStop = MDNSH_QueryStop;
  adapter->free = MDNSH_Free;
  return adapter;
}
