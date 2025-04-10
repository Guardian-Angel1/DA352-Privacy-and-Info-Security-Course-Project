# Compiler and flags
CC = gcc
CXX = g++
CFLAGS =  -O2 -MD 
CXXFLAGS =  -O2 -MD
LDFLAGS = -lgmp -lssl -lcrypto -lbcrypt -lreadline -lpdcurses -lpthread -lws2_32

# Targets
TARGETS = diffie-hellman.exe chat.exe

# Source files
C_SRCS = diffie-hellman.c diffie-hellman-example.c
CPP_SRCS = chat.cpp

# Object files
C_OBJS = $(C_SRCS:.c=.o)
CPP_OBJS = $(CPP_SRCS:.cpp=.o)

# Dependency files
C_DEPS = $(C_SRCS:.c=.d)
CPP_DEPS = $(CPP_SRCS:.cpp=.d)

# Default rule
all: $(TARGETS)

# Build diffie-hellman.exe
diffie-hellman.exe: diffie-hellman-example.o diffie-hellman.o
	$(CC) -o $@ $^ $(LDFLAGS)

# Build chat.exe
chat.exe: chat.o diffie-hellman.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# Compile C source
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile C++ source
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Include dependency files if they exist
-include $(C_DEPS) $(CPP_DEPS)

# Clean rule
clean:
	rm -f *.o *.d *.exe

.PHONY: all clean
