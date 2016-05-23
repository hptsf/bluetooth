OBJ1 = ble
OBJ2 = blescan

CC = gcc
CFLAGS = -O0 -g -Wall
LDFLAGS = -lpthread -lbluetooth

# SRCS = $(wildcard *.c)
# OBJS = $(patsubst %c, %o, $(SRCS))

TARGET = $(OBJ1) $(OBJ2)
all: $(TARGET)

$(OBJ1):$(OBJ1).o
	$(CC) $(CLFAGS) -o $@ $^ $(LDFLAGS)

$(OBJ2): $(OBJ2).o
	$(CC) $(CLFAGS) -o $@ $^ $(LDFLAGS)

.PHONY : clean

clean:
	rm -v $(OBJ1) $(OBJ2) *.o
