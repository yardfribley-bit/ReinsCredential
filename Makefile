CXX := clang++
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread
LDLIBS := -framework CoreServices -lz
CORE := ProcessCache.cpp DarwinProcessSource.cpp EvidenceStore.cpp FileMonitor.cpp AgentMonitor.cpp ContentMatcher.cpp
HEADERS := $(wildcard *.h)

.PHONY: all check integration acceptance clean
all: agent-monitor agent-gateway
agent-gateway: ContentGateway.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) ContentGateway.cpp $(CORE) $(LDLIBS) -lcurl -lbsm -o $@
agent-monitor: main.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) main.cpp $(CORE) $(LDLIBS) -o $@
agent-unit: tests/unit.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. tests/unit.cpp $(CORE) $(LDLIBS) -o $@
agent-probe: tests/fixture.cpp
	$(CXX) $(CXXFLAGS) $< -o $@
check: agent-unit
	./agent-unit
integration: agent-monitor agent-probe
	/usr/bin/python3 tests/integration.py
acceptance: all
	/usr/bin/python3 tests/acceptance_matrix.py --require-full-acceptance
clean:
	rm -f agent-monitor agent-gateway agent-unit agent-probe
