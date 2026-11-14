#include "EgressVerdict.h"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace agentsec;

LiveFlow Tcp(const std::string& destination, uint64_t baseline, uint64_t latest, bool established, bool loopback = false) {
    LiveFlow flow;
    flow.destination = destination;
    flow.kind = LiveFlowKind::TcpMeasured;
    flow.loopback = loopback;
    flow.tx_baseline = baseline;
    flow.tx_latest = latest;
    flow.established = established;
    flow.measured = true;
    flow.preexisting = baseline != 0;
    return flow;
}

LiveFlow Udp(const std::string& destination, uint64_t baseline, uint64_t latest, bool loopback = false) {
    LiveFlow flow;
    flow.destination = destination;
    flow.kind = LiveFlowKind::UdpOrQuic;
    flow.loopback = loopback;
    flow.measured = true;
    flow.tx_baseline = baseline;
    flow.tx_latest = latest;
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
    const auto off = std::string("203.0.113.10:8443");
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
    assert(too_wide.verdict == UploadVerdict::NotVisible);
    assert(too_wide.verdict != UploadVerdict::NotFound);
    assert(too_wide.transfer_outcome == "aggregate_above_window");
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
    const auto provider_wide = CloseLiveAccess(Seen(file_bytes, {Tcp("api.anthropic.com:443", 0, file_bytes + kFlowTxSlack + kTlsHandshakeAllowance + 1, true)}));
    assert(provider_wide.verdict == UploadVerdict::NotVisible);
    assert(provider_wide.verdict != UploadVerdict::NotFound);
    const auto provider_handshake = CloseLiveAccess(Seen(37, {Tcp("api.anthropic.com:443", 0, 206, true)}));
    assert(provider_handshake.verdict == UploadVerdict::NotVisible);
    assert(provider_handshake.verdict != UploadVerdict::Uploaded);
    assert(provider_handshake.verdict != UploadVerdict::NotFound);
    assert(provider_handshake.transfer_outcome == "provider_or_relay_body_not_visible");
    const auto provider_hello = CloseLiveAccess(Seen(37, {Tcp("192.168.1.20:443", 0, 299, true)}));
    assert(provider_hello.verdict == UploadVerdict::NotVisible);
    assert(provider_hello.verdict != UploadVerdict::NotFound);
    assert(provider_hello.transfer_outcome == "tls_handshake_body_not_visible");
    LiveFlow named = Tcp("192.168.1.20:443", 0, 299, true);
    named.sni = "api.anthropic.com";
    const auto named_hello = CloseLiveAccess(Seen(37, {named}));
    assert(named_hello.verdict == UploadVerdict::NotVisible);
    assert(named_hello.detail.find("sni=api.anthropic.com") != std::string::npos);
    // Port 443 with no application-data record is a handshake, not a body,
    // even when the raw counter is file size plus the old 1024-byte allowance.
    const auto provider_proven = CloseLiveAccess(Seen(file_bytes, {Tcp("api.anthropic.com:443", 0, file_bytes + kTlsHandshakeAllowance, true)}));
    assert(provider_proven.verdict == UploadVerdict::NotVisible);
    assert(provider_proven.verdict != UploadVerdict::Uploaded);
    assert(provider_proven.transfer_outcome == "provider_or_relay_body_not_visible");

    LiveFlow syn = Tcp(off, 0, 0, false);
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
    LiveFlow loopback_udp = quic;
    loopback_udp.destination = "127.0.0.1:9";
    loopback_udp.loopback = true;
    const auto local_udp = CloseLiveAccess(Seen(file_bytes, {loopback_udp}));
    assert(local_udp.verdict == UploadVerdict::NotVisible);
    assert(local_udp.verdict != UploadVerdict::NotFound);
    assert(local_udp.transfer_outcome == "udp_or_quic_body_not_visible");
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

    const auto udp_large = CloseLiveAccess(Seen(file_bytes, {Udp(off, 0, file_bytes)}));
    assert(udp_large.verdict == UploadVerdict::Uploaded);
    assert(udp_large.match_basis == "flow_txbytes_udp");
    assert(udp_large.transfer_outcome.find("left_host") != std::string::npos);
    const auto udp_small = CloseLiveAccess(Seen(file_bytes, {Udp(off, 0, 1)}));
    assert(udp_small.verdict == UploadVerdict::NotFound);
    assert(udp_small.verdict != UploadVerdict::NotVisible);
    assert(udp_small.match_basis == "live_agent_observed");
    auto compressed = Seen(1000, {Tcp(off, 0, 80, true)});
    compressed.content_lower_bound = 40;
    const auto compressed_upload = CloseLiveAccess(compressed);
    assert(compressed_upload.verdict == UploadVerdict::Uploaded);
    assert(compressed_upload.match_basis == "flow_txbytes");
    assert(compressed_upload.detail.find("lower_bound=40") != std::string::npos);
    const auto chunked = CloseLiveAccess(Seen(file_bytes, {
        Tcp("203.0.113.10:8443", 0, 16, true),
        Tcp("203.0.113.11:8443", 0, 16, true),
        Tcp("203.0.113.12:8443", 0, 16, true)}));
    assert(chunked.verdict == UploadVerdict::Uploaded);
    assert(chunked.match_basis == "flow_txbytes");
    LiveFlow partial_gap;
    partial_gap.destination = "198.51.100.8:8443";
    partial_gap.kind = LiveFlowKind::Unreadable;
    const auto partial = CloseLiveAccess(Seen(file_bytes, {Tcp(off, 0, 4, true), partial_gap}));
    assert(partial.verdict == UploadVerdict::NotVisible);
    assert(partial.verdict != UploadVerdict::NotFound);
    assert(partial.transfer_outcome == "off_host_measurement_incomplete");
    assert(!IsProviderOrRelay(partial_gap.destination));
    auto waiting = Seen(file_bytes, {Tcp(off, 100, 100, true)});
    waiting.window_settled = false;
    const auto still_open = CloseLiveAccess(waiting);
    assert(still_open.defer);
    assert(still_open.verdict != UploadVerdict::NotVisible || still_open.defer);

    const uint64_t canary = 37;
    const auto upper = canary + kFlowTxSlack + kTlsHandshakeAllowance;
    assert(InitialFlowBaseline(false, 180, upper) == 0);
    assert(InitialFlowBaseline(false, 0, upper) == 0);
    assert(InitialFlowBaseline(false, upper + 1, upper) == upper + 1);
    assert(InitialFlowBaseline(true, upper + 1, upper) == 0);
    const auto posted = CloseLiveAccess(Seen(canary, {Tcp("192.168.1.11:53429", 0, 180, true)}));
    assert(posted.verdict == UploadVerdict::Uploaded);
    assert(posted.verdict != UploadVerdict::NotFound);
    assert(posted.verdict != UploadVerdict::NotVisible);
    assert(posted.destination == "192.168.1.11:53429");
    assert(posted.match_basis == "flow_txbytes");
    assert(posted.detail.find("tx_sum=180") != std::string::npos);
    LiveFlow hello = Tcp("192.168.1.11:53431", 0, 300, true);
    hello.sni = "api.anthropic.com";
    const auto sni_hello = CloseLiveAccess(Seen(canary, {hello}));
    assert(sni_hello.verdict == UploadVerdict::NotVisible);
    assert(sni_hello.verdict != UploadVerdict::Uploaded);
    assert(sni_hello.verdict != UploadVerdict::NotFound);
    assert(sni_hello.destination == "192.168.1.11:53431");
    assert(sni_hello.transfer_outcome == "provider_or_relay_body_not_visible");
    LiveFlow records_only = Tcp("192.168.1.11:53431", 0, 400, true);
    records_only.tls_handshake = true;
    const auto record_hello = CloseLiveAccess(Seen(canary, {records_only}));
    assert(record_hello.verdict == UploadVerdict::NotVisible);
    assert(record_hello.verdict != UploadVerdict::Uploaded);
    assert(record_hello.transfer_outcome == "tls_handshake_body_not_visible");
    assert(record_hello.destination == "192.168.1.11:53431");
    LiveFlow encrypted = Tcp("192.168.1.11:443", 0, 300, true);
    encrypted.tls_handshake = true;
    encrypted.tls_app_data = true;
    encrypted.tls_app_bytes = canary;
    const auto encrypted_body = CloseLiveAccess(Seen(canary, {encrypted}));
    assert(encrypted_body.verdict == UploadVerdict::Uploaded);
    assert(encrypted_body.match_basis == "flow_txbytes");
    const auto quiet = CloseLiveAccess(Seen(canary, {}));
    assert(quiet.verdict == UploadVerdict::NotVisible);
    assert(quiet.verdict != UploadVerdict::NotFound);
    assert(quiet.transfer_outcome == "unseen_channel");
    assert(quiet.destination.empty());
    const auto measured_idle = CloseLiveAccess(Seen(canary, {Tcp("192.168.1.11:53429", 100, 100, true)}));
    assert(measured_idle.verdict == UploadVerdict::NotFound);
    assert(measured_idle.destination == "192.168.1.11:53429");
    assert(measured_idle.transfer_outcome == "live_agent_observed_no_upload");

    auto record = [](uint8_t type, size_t payload) {
        std::vector<uint8_t> bytes(5 + payload);
        bytes[0] = type;
        bytes[1] = 0x03;
        bytes[2] = 0x03;
        bytes[3] = static_cast<uint8_t>((payload >> 8) & 0xff);
        bytes[4] = static_cast<uint8_t>(payload & 0xff);
        return bytes;
    };
    // Handshake records only, about 1646 bytes on the wire, no content type 23.
    const auto hello_bytes = record(22, 1641);
    assert(hello_bytes.size() == 1646);
    const auto hello_records = ClassifyTlsRecords(hello_bytes.data(), hello_bytes.size());
    assert(hello_records.saw_handshake);
    assert(!hello_records.saw_app_data);
    assert(hello_records.app_bytes == 0);
    assert(hello_records.handshake_bytes == 1641);
    LiveFlow handshake_only = Tcp("192.168.1.11:54531", 0, hello_bytes.size(), true);
    handshake_only.tls_handshake = hello_records.saw_handshake;
    handshake_only.tls_app_data = hello_records.saw_app_data;
    handshake_only.tls_app_bytes = hello_records.app_bytes;
    const auto hello_close = CloseLiveAccess(Seen(canary, {handshake_only}));
    assert(hello_close.verdict == UploadVerdict::NotVisible);
    assert(hello_close.verdict != UploadVerdict::Uploaded);
    assert(hello_close.verdict != UploadVerdict::NotFound);
    assert(hello_close.transfer_outcome == "tls_handshake_body_not_visible");
    assert(hello_close.destination == "192.168.1.11:54531");
    assert(hello_close.match_basis != "flow_txbytes");
    LiveClose second_upload;
    second_upload.verdict = UploadVerdict::Uploaded;
    second_upload.transfer_outcome = "flow_txbytes;left_host;tx_sum=1646";
    assert(!ShouldEmitCloseUpdate(4, "flow_txbytes;left_host;tx_sum=1615", second_upload));
    assert(ShouldEmitCloseUpdate(0, "", second_upload));
    // The field failure: the session was seen, the counter stayed 0, and no
    // record flag was attached. That is an invisible body, not 未发现.
    LiveFlow counter_zero = Tcp("192.168.1.11:54631", 0, 0, true);
    assert(!counter_zero.tls_handshake);
    assert(!counter_zero.tls_app_data);
    assert(counter_zero.tx_latest == 0);
    const auto zero_close = CloseLiveAccess(Seen(canary, {counter_zero}));
    assert(zero_close.verdict == UploadVerdict::NotVisible);
    assert(zero_close.verdict != UploadVerdict::NotFound);
    assert(zero_close.verdict != UploadVerdict::Uploaded);
    assert(zero_close.transfer_outcome == "tls_handshake_body_not_visible");
    assert(zero_close.destination == "192.168.1.11:54631");
    assert(zero_close.detail.find("tx_sum=0") != std::string::npos);
    LiveClose zero_again = zero_close;
    assert(!ShouldEmitCloseUpdate(2, zero_close.transfer_outcome, zero_again));
    // A refused connect is still attempted, and a stable non-zero counter is still 未发现.
    LiveFlow refused_zero = Tcp("192.168.1.11:54630", 0, 0, false);
    refused_zero.failed = true;
    const auto refused_close = CloseLiveAccess(Seen(canary, {refused_zero}));
    assert(refused_close.verdict == UploadVerdict::Attempted);
    assert(refused_close.verdict != UploadVerdict::NotVisible);
    // Handshake-only kernel counter: 1615 bytes, 37-byte file. Not an upload.
    // The connection has ended (window settled). While it is still open the
    // same counter is deferred so a later body can still be counted.
    LiveFlow handshake_counter = Tcp("192.168.1.11:54731", 0, 1615, true);
    const auto handshake_done = CloseLiveAccess(Seen(canary, {handshake_counter}));
    assert(handshake_done.verdict == UploadVerdict::NotVisible);
    assert(handshake_done.verdict != UploadVerdict::Uploaded);
    assert(handshake_done.verdict != UploadVerdict::NotFound);
    assert(handshake_done.transfer_outcome == "tls_handshake_body_not_visible");
    assert(handshake_done.destination == "192.168.1.11:54731");
    assert(!ShouldEmitCloseUpdate(2, handshake_done.transfer_outcome, handshake_done));
    auto handshake_holding = Seen(canary, {handshake_counter});
    handshake_holding.window_settled = false;
    assert(CloseLiveAccess(handshake_holding).defer);
    // The acceptance POST is HTTP-sized and still uploads.
    const auto short_post = CloseLiveAccess(Seen(canary, {Tcp("192.168.1.11:54629", 0, 167, true)}));
    assert(short_post.verdict == UploadVerdict::Uploaded);
    assert(short_post.match_basis == "flow_txbytes");
    assert(short_post.detail.find("tx_sum=167") != std::string::npos);
    // Handshake 1615, then 2085 bytes of application data. Not closed at 1615.
    LiveFlow after_body = Tcp("192.168.1.11:54732", 0, 1615 + 2085, true);
    after_body.tx_previous = 1615;
    after_body.tls_app_data = true;
    after_body.tls_app_bytes = 2085;
    after_body.tls_handshake = true;
    const auto body_later = CloseLiveAccess(Seen(canary, {after_body}));
    assert(body_later.verdict == UploadVerdict::Uploaded);
    assert(body_later.verdict != UploadVerdict::NotVisible);
    assert(body_later.detail.find("tls_app_bytes=2085") != std::string::npos);
    assert(body_later.detail.find("tx_sum=2085") != std::string::npos || body_later.detail.find("tls_app_bytes=2085") != std::string::npos);
    LiveFlow grown = Tcp("192.168.1.11:54732", 0, 1615 + 2085, true);
    grown.tx_previous = 1615;
    const auto grown_close = CloseLiveAccess(Seen(canary, {grown}));
    assert(grown_close.verdict == UploadVerdict::Uploaded);
    assert(grown_close.detail.find("body_after_handshake=2085") != std::string::npos);
    assert(grown_close.detail.find("tx_sum=2085") != std::string::npos);

    // A handshake whose counter never reached the 1615-byte flight must still
    // not be called 未发现.
    LiveFlow short_handshake = Tcp("192.168.1.11:54831", 0, 20, true);
    const auto short_tls = CloseLiveAccess(Seen(canary, {short_handshake}));
    assert(short_tls.verdict == UploadVerdict::NotVisible);
    assert(short_tls.verdict != UploadVerdict::NotFound);
    assert(short_tls.transfer_outcome == "tls_handshake_body_not_visible");
    assert(FlowGraceActive(true, false, 9000));
    assert(FlowGraceActive(false, true, 1000));
    assert(!FlowGraceActive(false, true, kFlowGraceMs));
    assert(IdleWatchTeardownDue(false, true));
    assert(!IdleWatchTeardownDue(true, true));

    assert(FastTreeSampleDue(true, false, false));
    assert(FastTreeSampleDue(false, true, false));
    assert(!FastTreeSampleDue(false, false, false));
    assert(FastTreeSampleDue(false, false, true));
    assert(!SubscribeEveryProcessFlow());
    // A real application-data record still closes uploaded. 2085 is 1024+37+1024.
    const auto app_record = record(23, 2085);
    const auto app_records = ClassifyTlsRecords(app_record.data(), app_record.size());
    assert(app_records.saw_app_data);
    assert(app_records.app_bytes == 2085);
    LiveFlow with_body = Tcp("192.168.1.11:54532", 0, 1646 + app_record.size(), true);
    with_body.tls_handshake = true;
    with_body.tls_app_data = true;
    with_body.tls_app_bytes = app_records.app_bytes;
    const auto body_close = CloseLiveAccess(Seen(canary, {with_body}));
    assert(body_close.verdict == UploadVerdict::Uploaded);
    assert(body_close.match_basis == "flow_txbytes");
    assert(body_close.destination == "192.168.1.11:54532");
    // Change-cipher-spec before application data must not hide the body.
    auto prefixed = record(20, 1);
    prefixed.insert(prefixed.end(), app_record.begin(), app_record.end());
    const auto after_ccs = ClassifyTlsRecords(prefixed.data(), prefixed.size());
    assert(after_ccs.saw_app_data && after_ccs.app_bytes == 2085);

    assert(FastDiscoveryInspect(true, false, false, false));
    assert(!FastDiscoveryInspect(false, false, false, false));
    assert(!FastDiscoveryInspect(true, true, true, false));
    assert(!FastDiscoveryInspect(false, true, false, true));
    assert(SlowDiscoveryInspect(false, true, 0, 1));
    assert(!SlowDiscoveryInspect(false, true, 1, 1));
    assert(!SlowDiscoveryInspect(true, true, 0, 1));

    std::cout << "PASS: live-agent flow verdicts\n";
    return 0;
}
