CC	   = g++
CFLAGS = -g -Wall
OBJS   = main.o
TARGET = PCAP_programming

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm *.o

main.o: PCAP_Programming.c

clean:
	rm -rf *.o $(TARGET)
