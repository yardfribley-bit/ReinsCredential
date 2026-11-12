#include "EgressVerdict.h"
#include <cassert>
#include <iostream>
#include <string>

using namespace agentsec;

LiveFlow Tcp(const std::string& destination, uint64_t baseline, uint64_t latest, bool established, bool loopback = false) {
    LiveFlow flow;
    flow.destination = destination;
    flow.kind = LiveFlowKind::TcpMeasured;
    flow.loopback = loopback;
    flow.tx_baseline = baseline;
    flow.tx_latest = latest;
    flow.established = established;
    flow.preexisting = baseline != 0;
    return flow;
}

LiveAccessView Seen(uint64_t file_bytes, std::vector<LiveFlow> flows, bool file_open = true) {
    LiveAccessView view;
    view.agent_visible = true;
    view.inspection_complete = true;
    view.file_open = file_open;
    view.file_bytes = file_bytes;
    view.flows = std::move(flows);
    return view;
}

int main() {
    const uint64_t file_bytes = 48;
    const auto off = std::string("203.0.113.10:443");
    const auto loop = std::string("127.0.0.1:9");

    LiveAccessView invisible;
    const auto hidden_agent = CloseLiveAccess(invisible);
    assert(hidden_agent.verdict == UploadVerdict::NotVisible);
    assert(hidden_agent.match_basis == "observation_impossible");
    assert(hidden_agent.transfer_outcome == "agent_not_visible");

    auto incomplete = Seen(file_bytes, {});
    incomplete.inspection_complete = false;
    const auto unread = CloseLiveAccess(incomplete);
    assert(unread.verdict == UploadVerdict::NotVisible);
    assert(unread.transfer_outcome == "descriptors_or_flows_incomplete");
    assert(std::string(UploadVerdictLabel(unread.verdict)) == "看不到");

    // A measured off-host send still counts when some other sample could not list descriptors.
    auto incomplete_but_sent = Seen(file_bytes, {Tcp(off, 0, file_bytes, true)});
    incomplete_but_sent.inspection_complete = false;
    const auto recovered = CloseLiveAccess(incomplete_but_sent);
    assert(recovered.verdict == UploadVerdict::Uploaded);
    assert(recovered.match_basis == "flow_txbytes");

    const auto idle = CloseLiveAccess(Seen(0, {}, false));
    assert(idle.verdict == UploadVerdict::NotFound);
    assert(idle.match_basis == "live_agent_observed");
    assert(idle.transfer_outcome == "live_agent_observed_no_access");
    assert(std::string(LiveVerdictSummary(idle, "codex", "")).rfind("未发现", 0) == 0);

    LiveFlow quic;
    quic.destination = "203.0.113.50:443";
    quic.kind = LiveFlowKind::UdpOrQuic;
    const auto quic_only = CloseLiveAccess(Seen(0, {quic}, false));
    assert(quic_only.verdict == UploadVerdict::NotFound);
    assert(quic_only.verdict != UploadVerdict::NotVisible);

    const auto opened = CloseLiveAccess(Seen(file_bytes, {Tcp(off, 100, 100, true)}));
    assert(opened.verdict == UploadVerdict::NotFound);
    assert(opened.transfer_outcome == "live_agent_observed_no_upload");
    assert(std::string(LiveVerdictSummary(opened, "codex", "/tmp/synthetic.env")).rfind("未发现", 0) == 0);
    assert(LiveVerdictSummary(opened, "codex", "/tmp/synthetic.env").find("看不到。") == std::string::npos);

    const auto local = CloseLiveAccess(Seen(file_bytes, {Tcp(loop, 0, file_bytes + 200, true, true)}));
    assert(local.verdict == UploadVerdict::NotFound);
    assert(local.destination == loop);
    assert(local.transfer_outcome.find("loopback_not_off_host") != std::string::npos);
    assert(local.verdict != UploadVerdict::Uploaded);
    auto local_gap = Seen(file_bytes, {Tcp(loop, 0, file_bytes + 200, true, true)});
    local_gap.inspection_complete = false;
    const auto local_incomplete = CloseLiveAccess(local_gap);
    assert(local_incomplete.verdict == UploadVerdict::NotFound);
    assert(local_incomplete.destination == loop);
    assert(local_incomplete.transfer_outcome.find("loopback_not_off_host") != std::string::npos);
    assert(local_incomplete.transfer_outcome != "descriptors_or_flows_incomplete");

    const auto uploaded = CloseLiveAccess(Seen(file_bytes, {Tcp(off, 0, file_bytes, true)}));
    assert(uploaded.verdict == UploadVerdict::Uploaded);
    assert(uploaded.destination == off);
    assert(uploaded.match_basis == "flow_txbytes");
    assert(uploaded.detail.find("match=flow_txbytes") != std::string::npos);
    assert(uploaded.transfer_outcome.find("left_host") != std::string::npos);
    assert(std::string(LiveVerdictSummary(uploaded, "Cursor", "/tmp/synthetic.env")).rfind("已上传", 0) == 0);
    assert(LiveVerdictSummary(uploaded, "Cursor", "/tmp/synthetic.env").find("flow_txbytes") != std::string::npos);

    const auto slack = CloseLiveAccess(Seen(file_bytes, {Tcp(off, 10, 10 + file_bytes + kFlowTxSlack, true)}));
    assert(slack.verdict == UploadVerdict::Uploaded);
    const auto too_wide = CloseLiveAccess(Seen(file_bytes, {Tcp(off, 0, file_bytes + kFlowTxSlack + 1, true)}));
    assert(too_wide.verdict == UploadVerdict::NotFound);
    assert(!IsProviderOrRelay(off));
    assert(IsProviderOrRelay("api.anthropic.com:443"));
    assert(IsProviderOrRelay("relay.openai.com:443"));
    LiveFlow provider_tls;
    provider_tls.destination = "api.anthropic.com:443";
    provider_tls.kind = LiveFlowKind::Unreadable;
    const auto provider_hidden = CloseLiveAccess(Seen(file_bytes, {provider_tls}));
    assert(provider_hidden.verdict == UploadVerdict::NotVisible);
    assert(provider_hidden.verdict != UploadVerdict::NotFound);
    assert(provider_hidden.transfer_outcome == "provider_or_relay_body_not_visible");
    const auto provider_wide = CloseLiveAccess(Seen(file_bytes, {Tcp("api.anthropic.com:443", 0, file_bytes + kFlowTxSlack + 1, true)}));
    assert(provider_wide.verdict == UploadVerdict::NotVisible);
    assert(provider_wide.verdict != UploadVerdict::NotFound);
    const auto provider_proven = CloseLiveAccess(Seen(file_bytes, {Tcp("api.anthropic.com:443", 0, file_bytes, true)}));
    assert(provider_proven.verdict == UploadVerdict::Uploaded);
    assert(provider_proven.match_basis == "flow_txbytes");

    LiveFlow syn = Tcp("203.0.113.10:443", 0, 0, false);
    syn.failed = true;
    syn.preexisting = false;
    const auto attempted = CloseLiveAccess(Seen(file_bytes, {syn}));
    assert(attempted.verdict == UploadVerdict::Attempted);
    assert(attempted.match_basis == "flow_attempt");
    assert(attempted.destination == off);
    assert(std::string(LiveVerdictSummary(attempted, "codex", "/tmp/synthetic.env")).rfind("已尝试未成功", 0) == 0);

    LiveFlow old_syn = Tcp(off, 0, 0, false);
    old_syn.failed = true;
    old_syn.preexisting = true;
    const auto refused = CloseLiveAccess(Seen(file_bytes, {old_syn}));
    assert(refused.verdict == UploadVerdict::Attempted);
    assert(refused.match_basis == "flow_attempt");
    assert(refused.destination == off);
    LiveFlow seen_refused = Tcp("192.168.1.11:59999", 0, 0, false);
    seen_refused.failed = true;
    seen_refused.preexisting = true;
    const auto local_refused = CloseLiveAccess(Seen(37, {seen_refused}));
    assert(local_refused.verdict == UploadVerdict::Attempted);
    assert(local_refused.destination == "192.168.1.11:59999");
    uint8_t compatible[16] = {};
    compatible[12] = 192; compatible[13] = 168; compatible[14] = 1; compatible[15] = 11;
    assert(FormatSocketPeer(false, compatible, 59999) == "192.168.1.11:59999");
    uint8_t mapped[16] = {};
    mapped[10] = 0xff; mapped[11] = 0xff;
    mapped[12] = 192; mapped[13] = 168; mapped[14] = 1; mapped[15] = 11;
    assert(FormatSocketPeer(false, mapped, 59999) == "192.168.1.11:59999");
    uint8_t flagged[16] = {};
    flagged[12] = 10; flagged[13] = 1; flagged[14] = 2; flagged[15] = 3;
    assert(FormatSocketPeer(true, flagged, 9) == "10.1.2.3:9");
    uint8_t loop6[16] = {};
    loop6[15] = 1;
    assert(FormatSocketPeer(false, loop6, 9) == "[::1]:9");

    const auto udp = CloseLiveAccess(Seen(file_bytes, {quic}));
    assert(udp.verdict == UploadVerdict::NotVisible);
    assert(udp.transfer_outcome == "udp_or_quic_body_not_visible");
    assert(udp.destination == quic.destination);
    auto udp_and_gap = Seen(file_bytes, {quic});
    udp_and_gap.inspection_complete = false;
    const auto udp_gap = CloseLiveAccess(udp_and_gap);
    assert(udp_gap.verdict == UploadVerdict::NotVisible);
    assert(udp_gap.transfer_outcome == "udp_or_quic_body_not_visible");
    assert(udp_gap.destination == quic.destination);
    assert(udp_gap.verdict != UploadVerdict::NotFound);
    assert(std::string(LiveVerdictSummary(udp, "codex", "/tmp/synthetic.env")).rfind("看不到", 0) == 0);
    assert(udp.verdict != UploadVerdict::NotFound);

    const auto udp_and_tcp = CloseLiveAccess(Seen(file_bytes, {quic, Tcp(off, 0, file_bytes + 100, true)}));
    assert(udp_and_tcp.verdict == UploadVerdict::Uploaded);

    LiveFlow proxy = Tcp("127.0.0.1:9", 0, file_bytes + 100, true, true);
    proxy.to_local_proxy = true;
    const auto via_proxy = CloseLiveAccess(Seen(file_bytes, {proxy}));
    assert(via_proxy.verdict == UploadVerdict::NotFound);

    auto unknown_size = Seen(0, {Tcp(off, 0, 100, true)});
    const auto no_size = CloseLiveAccess(unknown_size);
    assert(no_size.verdict == UploadVerdict::NotVisible);
    assert(no_size.transfer_outcome == "registered_file_size_unknown");

    std::cout << "PASS: live-agent flow verdicts\n";
    return 0;
}
