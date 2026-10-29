#include "App.h"
#include <thread>
#include <vector>
// WebSocket echo on every path, n threads (SO_REUSEPORT), no compression.
int main(int argc, char **argv) {
  int n = argc > 1 ? atoi(argv[1]) : 6;
  struct PerSocketData {};
  std::vector<std::thread *> threads(n);
  for (auto &t : threads) {
    t = new std::thread([]() {
      uWS::App().ws<PerSocketData>("/*", {
        .compression = uWS::DISABLED,
        .maxPayloadLength = 16 * 1024 * 1024,
        .idleTimeout = 960,
        .maxBackpressure = 16 * 1024 * 1024,
        .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) { ws->send(message, opCode); },
      }).listen(8080, [](auto *s) { if (!s) { printf("listen failed\n"); exit(1); } }).run();
    });
  }
  for (auto t : threads) t->join();
}
