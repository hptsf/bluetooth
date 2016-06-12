# make file for ble ops
# data: 2016-05-12

OBJ1 = ble
OBJ2 = blescan

CC = gcc
CFLAGS = -O0 -g -Wall
LDFLAGS = -lpthread -lbluetooth

SRCS = $(wildcard *.c)
OBJS = $(patsubst %c, %o, $(SRCS))

TARGET = $(OBJ1) $(OBJ2)
all: $(TARGET)

$(OBJ1):$(OBJ1).o $(filter-out blescan.o, $(OBJS))
	$(CC) $(CLFAGS) -o $@ $^ $(LDFLAGS)

$(OBJ2): $(OBJ2).o $(filter-out ble.o, $(OBJS))
	$(CC) $(CLFAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY : clean

clean:
	rm -v $(OBJ1) $(OBJ2) *.o

# install:
# 	mv .....
