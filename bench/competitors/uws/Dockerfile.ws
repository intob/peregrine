# uWebSockets echo on every path (compression off) and its benchmarks/load_test.c (GET /ws).
FROM comp-uws:latest
WORKDIR /src
COPY ws-echo.cpp /src/ws-echo.cpp
RUN g++ -O3 -march=native -flto -std=c++20 -DUWS_NO_ZLIB -DLIBUS_NO_SSL -IuSockets/src -Isrc ws-echo.cpp uSockets/*.o -o /usr/local/bin/uws-ws-echo -lpthread
RUN cd benchmarks && sed -i 's|GET / HTTP|GET /ws HTTP|' load_test.c && gcc -O3 -march=native -DLIBUS_NO_SSL -I../uSockets/src load_test.c ../uSockets/*.o -lz -o /usr/local/bin/uws-load-test
