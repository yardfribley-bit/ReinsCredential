#define main monitor_entry
#include "../main.cpp"
#undef main
#include <cassert>
int main() {
    Options options;
    ProcessNode p; p.pid = 42; p.executable = "/usr/local/bin/node";
    p.arguments = {"node", "app.js", "prompt mentions /@anthropic-ai/claude-code/"};
    assert(MatchAgent(p, options).empty());
    p.arguments[1] = "/opt/node_modules/@anthropic-ai/claude-code/cli.js";
    assert(MatchAgent(p, options).rfind("package_entrypoint:", 0) == 0);
    p.executable = "/usr/bin/python3"; p.arguments = {"python3", "-m", "aider"};
    assert(MatchAgent(p, options) == "python_module:aider");
    p.arguments = {"python3", "app.py"};
    assert(MatchAgent(p, options).empty());
    options.includeRuntimes = true;
    assert(MatchAgent(p, options) == "generic_runtime_candidate");
    options.includeRuntimes = false; options.extraNames = {"MyAgent"};
    p.executable = "/tmp/myagent";
    assert(MatchAgent(p, options) == "configured_name:MyAgent");
    p.executable = "/tmp/not-myagent";
    assert(MatchAgent(p, options).empty());
    p.executable = "/Applications/Cursor.app/Contents/MacOS/Cursor Helper";
    assert(MatchAgent(p, options).rfind("application_bundle:", 0) == 0);
    auto first = Identity(p); ++p.startMicroseconds;
    assert(first != Identity(p));
    assert(Json("x\n\"\\") == "\"x\\u000a\\\"\\\\\"");
    assert(PositiveInt("100") == 100);
    for (const auto& value : {"0", "-1", "10x", "9999999999999999999999"}) {
        bool rejected = false;
        try { PositiveInt(value); } catch (const std::exception&) { rejected = true; }
        assert(rejected);
    }
    std::cout << "PASS: agent classification, runtime opt-in, prompt false-positive exclusion, process identity, JSON escaping, numeric input validation\n";
}
