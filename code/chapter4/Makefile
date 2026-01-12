CXX=g++
OBJ=loader_demo

.PHONY: all clean

all: $(OBJ)

loader.o: ../inc/loader.cc
	$(CXX) -std=c++11 -c ../inc/loader.cc

loader_demo: loader.o loader_demo.cc
	$(CXX) -std=c++11 -o loader_demo loader_demo.cc loader.o -lbfd

clean:
	rm -f $(OBJ) *.o


# 測試強弱符號覆蓋
test: main.o weak.o strong.o
	$(CC) -o test_weak_only main.o weak.o
	$(CC) -o test_strong_only main.o strong.o
	$(CC) -o test_weak_strong main.o weak.o strong.o
	@echo "==== test_weak_only (應該印出 weak foo) ===="
	./test_weak_only
	@echo "==== test_strong_only (應該印出 strong foo) ===="
	./test_strong_only
	@echo "==== test_weak_strong (應該印出 strong foo) ===="
	./test_weak_strong

main.o: main.c
	$(CC) -c main.c
weak.o: weak.c
	$(CC) -c weak.c
strong.o: strong.c
	$(CC) -c strong.c

