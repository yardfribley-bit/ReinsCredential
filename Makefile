CXX := clang++
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread
LDLIBS := -framework CoreServices -lz
CORE := ProcessCache.cpp DarwinProcessSource.cpp EvidenceStore.cpp FileMonitor.cpp AgentMonitor.cpp ContentMatcher.cpp SubtreeWatcher.cpp EgressVerdict.cpp
HEADERS := $(wildcard *.h)

.PHONY: all check audit-check audit-native shutdown-probe integration acceptance clean live-flow-verdict
all: agent-monitor agent-gateway agent-egress
agent-gateway: ContentGateway.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) ContentGateway.cpp $(CORE) $(LDLIBS) -lcurl -lbsm -o $@
agent-monitor: main.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) main.cpp $(CORE) $(LDLIBS) -o $@
agent-egress: EgressProxy.cpp TlsIntercept.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) EgressProxy.cpp TlsIntercept.cpp $(CORE) $(LDLIBS) -framework Security -framework CoreFoundation -o $@
agent-unit: tests/unit.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. tests/unit.cpp $(CORE) $(LDLIBS) -o $@
agent-probe: tests/fixture.cpp
	$(CXX) $(CXXFLAGS) $< -o $@
agent-generations: tests/process_generations.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. $< $(CORE) $(LDLIBS) -o $@
agent-callback-tests: tests/callback_unit.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. $< $(CORE) $(LDLIBS) -o $@
agent-store-tests: tests/store_durability.cpp EvidenceStore.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. $< EvidenceStore.cpp $(LDLIBS) -o $@
agent-shutdown-probe: tests/file_shutdown.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I. $< $(CORE) $(LDLIBS) -o $@
check: agent-unit audit-check live-flow-verdict
	./agent-unit
	./live-flow-verdict
live-flow-verdict: tests/live_flow_verdict.cpp EgressVerdict.cpp EgressVerdict.h
	$(CXX) -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -I. tests/live_flow_verdict.cpp EgressVerdict.cpp -o $@
audit-check: agent-generations agent-callback-tests agent-store-tests
	./agent-generations
	./agent-callback-tests
	./agent-store-tests
audit-native: all
	/usr/bin/python3 tests/rotation.py
	/usr/bin/python3 tests/gateway_durability.py
# This deliberately strict pre-Stop write probe remains a failing capability
# probe where macOS has not yet delivered the operation to fseventsd. It is not
# weakened or silently counted as a passing cleanup test.
shutdown-probe: agent-shutdown-probe
	./agent-shutdown-probe
integration: agent-monitor agent-probe agent-short-read agent-egress
	/usr/bin/python3 tests/integration.py
	/usr/bin/python3 tests/short_read.py
	/usr/bin/python3 tests/egress_verdict.py
agent-short-read: tests/short_read_fixture.cpp
	$(CXX) $(CXXFLAGS) $< -o $@
acceptance: all
	/usr/bin/python3 tests/acceptance_matrix.py --require-full-acceptance
clean:
	rm -f agent-monitor agent-gateway agent-egress agent-unit agent-probe agent-short-read agent-generations agent-callback-tests agent-store-tests agent-shutdown-probe live-agent live-flow-verdict
