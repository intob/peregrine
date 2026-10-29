#include "App.h"
#include <thread>
#include <vector>
int main(int argc, char **argv) {
  int n = argc > 1 ? atoi(argv[1]) : 6;
  std::vector<std::thread *> threads(n);
  for (auto &t : threads) {
    t = new std::thread([]() {
      uWS::App().get("/*", [](auto *res, auto *) {
        res->writeHeader("Content-Type", "text/plain")->end("Hello, World!");
      }).listen(8080, [](auto *s) { if (!s) { printf("listen failed\n"); exit(1); } }).run();
    });
  }
  for (auto t : threads) t->join();
}
