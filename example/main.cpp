#include <array>
#include <cstring>
#include <iostream>
#include <knot/discovery.h>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/select.h>
#include <unistd.h>
#endif

int main() {
  auto *discovery = KNDiscoveryCreate();
  if (!discovery) {
    std::cerr << "Failed to create discovery context" << std::endl;
    return -1;
  }

  KNTxtEntry txt;
  txt.key = (char *)"foo";
  txt.value = (char *)"bar";

  auto *service =
      KNRegisterService(discovery, "test_service", "_testreg._tcp", 5555, &txt, 1);
  if (!service) {
    std::cerr << "Failed to register service" << std::endl;
    KNDiscoveryFree(discovery);
    return -1;
  }

  std::cout << "Service 'test_service._testreg._tcp.local.' registered on port 5555."
            << std::endl;
  std::cout << "Polling for mDNS queries... Press Ctrl+C to exit." << std::endl;

  while (true) {
    std::vector<KNSocket> sockets(16);
    size_t count = KNServiceGetSockets(discovery, service, sockets.data(), sockets.size());
    if (count > sockets.size()) {
      sockets.resize(count);
      count = KNServiceGetSockets(discovery, service, sockets.data(), sockets.size());
    }

    if (count == 0) {
#ifdef _WIN32
      Sleep(100);
#else
      usleep(100000);
#endif
      continue;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    KNSocket max_fd = 0;
    for (size_t i = 0; i < count; ++i) {
      FD_SET(sockets[i], &read_fds);
      if (sockets[i] > max_fd)
        max_fd = sockets[i];
    }

    struct timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 100ms

#if defined(_WIN32)
    int ret = select(0, &read_fds, nullptr, nullptr, &timeout);
#else
    int ret = select((int)(max_fd + 1), &read_fds, nullptr, nullptr, &timeout);
#endif
    if (ret > 0) {
      for (size_t i = 0; i < count; ++i) {
        if (FD_ISSET(sockets[i], &read_fds)) {
          KNServiceNotify(discovery, service, sockets[i]);
          std::cout << "polled socket " << sockets[i] << std::endl;
        }
      }
    } else if (ret < 0) {
#if defined(_WIN32)
      if (WSAGetLastError() != WSAEINTR) {
        std::cerr << "select error: " << WSAGetLastError() << std::endl;
        break;
      }
#else
      if (errno != EINTR) {
        perror("select");
        break;
      }
#endif
    }
  }

  KNServiceStop(discovery, service);
  KNDiscoveryFree(discovery);

  return 0;
}
