CC = g++
CFLAGS = -Wall
LDLIBS = -lpcap

all: airo-mon

airo-mon: main.cpp
	$(CC) $(CFLAGS) -o airo-mon main.cpp $(LDLIBS)

clean:
	rm -f airo-mon
