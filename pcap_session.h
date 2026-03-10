#ifndef PCAP_SESSION_H
#define PCAP_SESSION_H

#include <napi.h>
#include <node_api.h>
#include <uv.h>
#ifndef _WIN32
#include <pcap/pcap.h>
#endif

class PcapSession : public Napi::ObjectWrap<PcapSession> {
public:
    static void Init(Napi::Env env, Napi::Object exports);
    PcapSession(const Napi::CallbackInfo& info);
    ~PcapSession();

private:
    Napi::Value Open(bool live, const Napi::CallbackInfo& info);
    Napi::Value OpenLive(const Napi::CallbackInfo& info);
    Napi::Value OpenOffline(const Napi::CallbackInfo& info);
    Napi::Value Dispatch(const Napi::CallbackInfo& info);
    void StartPolling(const Napi::CallbackInfo& info);
    void Close(const Napi::CallbackInfo& info);
    Napi::Value Stats(const Napi::CallbackInfo& info);
    void Inject(const Napi::CallbackInfo& info);
    static void PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    static void FinalizeClose(PcapSession *session);

    static void poll_handler(uv_poll_t* handle, int status, int events);

    Napi::FunctionReference packet_ready_cb;
    static Napi::FunctionReference constructor;

#ifndef _WIN32
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dump_handle;
#endif
    char *buffer_data;
    size_t buffer_length;
    size_t snap_length;
    char *header_data;

    uv_poll_t poll_handle;
    bool has_warned_poll_error = false;
    bool poll_init = false;
    bool dispatching = false;
};

#endif
