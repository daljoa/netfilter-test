CXX=g++
CXXFLAGS=-std=c++11 -Wall -Wextra -O2
CPPFLAGS=$(shell pkg-config --cflags libnetfilter_queue 2>/dev/null)
LDLIBS=$(shell pkg-config --libs libnetfilter_queue 2>/dev/null || echo -lnetfilter_queue)

TARGET=netfilter-test
SRCS=main.cpp
OBJS=$(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJS)
