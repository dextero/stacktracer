CXXFLAGS = -g

TEST_SOURCES = $(shell find ./ -name '*.cpp')
TESTS = $(TEST_SOURCES:.cpp=)

all: $(TESTS)

.PHONY: clean
clean:
	rm -f $(TESTS)

