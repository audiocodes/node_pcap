#include <assert.h>
#include <cstring>
#include <string.h>
#ifndef _WIN32
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#endif

#include "pcap_session.h"

Napi::FunctionReference PcapSession::constructor;

PcapSession::PcapSession(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<PcapSession>(info) {
#ifndef _WIN32
    pcap_handle = NULL;
    pcap_dump_handle = NULL;
#endif
    buffer_data = NULL;
    buffer_length = 0;
    snap_length = 0;
    header_data = NULL;
}

PcapSession::~PcapSession() {
    FinalizeClose(this);
}

void PcapSession::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(
        env,
        "PcapSession",
        {
            InstanceMethod("open_live", &PcapSession::OpenLive),
            InstanceMethod("open_offline", &PcapSession::OpenOffline),
            InstanceMethod("dispatch", &PcapSession::Dispatch),
            InstanceMethod("start_polling", &PcapSession::StartPolling),
            InstanceMethod("close", &PcapSession::Close),
            InstanceMethod("stats", &PcapSession::Stats),
            InstanceMethod("inject", &PcapSession::Inject),
        }
    );

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();
    exports.Set("PcapSession", func);
}

void PcapSession::PacketReady(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
#ifdef _WIN32
    (void)s;
    (void)pkthdr;
    (void)packet;
#else
    PcapSession* session = reinterpret_cast<PcapSession*>(s);
    if (session == NULL) {
        return;
    }

    if (session->pcap_dump_handle != NULL) {
        pcap_dump(reinterpret_cast<u_char*>(session->pcap_dump_handle), pkthdr, packet);
    }

    size_t copy_len = pkthdr->caplen;
    if (copy_len > session->buffer_length) {
        copy_len = session->buffer_length;
    }

    memcpy(session->buffer_data, packet, copy_len);

    // copy header data to fixed offsets in second buffer from user
    memcpy(session->header_data, &(pkthdr->ts.tv_sec), 4);
    memcpy(session->header_data + 4, &(pkthdr->ts.tv_usec), 4);
    memcpy(session->header_data + 8, &(pkthdr->caplen), 4);
    memcpy(session->header_data + 12, &(pkthdr->len), 4);

    if (!session->packet_ready_cb.IsEmpty()) {
        session->packet_ready_cb.Call(session->Value(), {});
    }
#endif
}

Napi::Value PcapSession::Dispatch(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
    return env.Undefined();
#else
    int packet_count = 1;
    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Dispatch takes at least two arguments").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "First argument must be a buffer").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Second argument must be a buffer").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (info.Length() > 2) {
        if (!info[2].IsNumber()) {
            Napi::TypeError::New(env, "Third argument must be a Number").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        packet_count = info[2].As<Napi::Number>().Int32Value();
    }

    Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
    buffer_data = buffer.Data();
    buffer_length = buffer.Length();

    Napi::Buffer<char> header = info[1].As<Napi::Buffer<char>>();
    header_data = header.Data();

    dispatching = true;
    const int processed = pcap_dispatch(pcap_handle, packet_count, PacketReady, reinterpret_cast<u_char*>(this));
    dispatching = false;

    if (processed == PCAP_ERROR_BREAK) {
        FinalizeClose(this);
    }

    return Napi::Number::New(env, processed);
#endif
}

Napi::Value PcapSession::Open(bool live, const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 10) {
        Napi::TypeError::New(env, "pcap Open: expecting 10 arguments").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "pcap Open: info[0] must be a String").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[1].IsString()) {
        Napi::TypeError::New(env, "pcap Open: info[1] must be a String").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[2].IsNumber()) {
        Napi::TypeError::New(env, "pcap Open: info[2] must be a Number").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[3].IsNumber()) {
        Napi::TypeError::New(env, "pcap Open: info[3] must be a Number").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[4].IsString()) {
        Napi::TypeError::New(env, "pcap Open: info[4] must be a String").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[5].IsFunction()) {
        Napi::TypeError::New(env, "pcap Open: info[5] must be a Function").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[6].IsBoolean()) {
        Napi::TypeError::New(env, "pcap Open: info[6] must be a Boolean").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[7].IsNumber()) {
        Napi::TypeError::New(env, "pcap Open: info[7] must be a Number").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[8].IsFunction()) {
        Napi::TypeError::New(env, "pcap Open: info[8] must be a Function").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    if (!info[9].IsBoolean()) {
        Napi::TypeError::New(env, "pcap Open: info[9] must be a Boolean").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string device = info[0].As<Napi::String>().Utf8Value();
    std::string filter = info[1].As<Napi::String>().Utf8Value();
    int buffer_size = info[2].As<Napi::Number>().Int32Value();
    int snap_len = info[3].As<Napi::Number>().Int32Value();
    int buffer_timeout = info[7].As<Napi::Number>().Int32Value();
    std::string pcap_output_filename = info[4].As<Napi::String>().Utf8Value();

    packet_ready_cb.Reset(info[5].As<Napi::Function>(), 1);

#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
    return env.Undefined();
#else
    char errbuf[PCAP_ERRBUF_SIZE];
    Napi::Function warning_fn = info[8].As<Napi::Function>();

    pcap_dump_handle = NULL;
    if (live) {
        if (pcap_lookupnet(const_cast<char*>(device.c_str()), &net, &mask, errbuf) == -1) {
            net = 0;
            mask = 0;
            warning_fn.Call(env.Global(), {Napi::String::New(env, errbuf)});
        }

        pcap_handle = pcap_create(const_cast<char*>(device.c_str()), errbuf);
        if (pcap_handle == NULL) {
            Napi::Error::New(env, errbuf).ThrowAsJavaScriptException();
            return env.Undefined();
        }

        if (pcap_set_snaplen(pcap_handle, snap_len) != 0) {
            Napi::Error::New(env, "error setting snaplen").ThrowAsJavaScriptException();
            return env.Undefined();
        }

        if (info[9].As<Napi::Boolean>().Value()) {
            if (pcap_set_promisc(pcap_handle, 1) != 0) {
                Napi::Error::New(env, "error setting promiscuous mode").ThrowAsJavaScriptException();
                return env.Undefined();
            }
        }

        if (pcap_set_buffer_size(pcap_handle, buffer_size) != 0) {
            Napi::Error::New(env, "error setting buffer size").ThrowAsJavaScriptException();
            return env.Undefined();
        }

        if (buffer_timeout > 0) {
            if (pcap_set_timeout(pcap_handle, buffer_timeout) != 0) {
                Napi::Error::New(env, "error setting read timeout").ThrowAsJavaScriptException();
                return env.Undefined();
            }
        }

        if (pcap_set_immediate_mode(pcap_handle, (buffer_timeout <= 0)) != 0) {
            Napi::Error::New(env, "error setting immediate mode").ThrowAsJavaScriptException();
            return env.Undefined();
        }

        if (info[6].As<Napi::Boolean>().Value()) {
            if (pcap_set_rfmon(pcap_handle, 1) != 0) {
                Napi::Error::New(env, pcap_geterr(pcap_handle)).ThrowAsJavaScriptException();
                return env.Undefined();
            }
        }

        if (pcap_activate(pcap_handle) != 0) {
            Napi::Error::New(env, pcap_geterr(pcap_handle)).ThrowAsJavaScriptException();
            return env.Undefined();
        }

        if (!pcap_output_filename.empty()) {
            pcap_dump_handle = pcap_dump_open(pcap_handle, const_cast<char*>(pcap_output_filename.c_str()));
            if (pcap_dump_handle == NULL) {
                Napi::Error::New(env, "error opening dump").ThrowAsJavaScriptException();
                return env.Undefined();
            }
        }

        if (pcap_setnonblock(pcap_handle, 1, errbuf) == -1) {
            Napi::Error::New(env, errbuf).ThrowAsJavaScriptException();
            return env.Undefined();
        }
    } else {
        pcap_handle = pcap_open_offline(const_cast<char*>(device.c_str()), errbuf);
        if (pcap_handle == NULL) {
            Napi::Error::New(env, errbuf).ThrowAsJavaScriptException();
            return env.Undefined();
        }
    }

    if (!filter.empty()) {
        if (pcap_compile(pcap_handle, &fp, const_cast<char*>(filter.c_str()), 1, net) == -1) {
            Napi::Error::New(env, pcap_geterr(pcap_handle)).ThrowAsJavaScriptException();
            return env.Undefined();
        }

        if (pcap_setfilter(pcap_handle, &fp) == -1) {
            Napi::Error::New(env, pcap_geterr(pcap_handle)).ThrowAsJavaScriptException();
            return env.Undefined();
        }
        pcap_freecode(&fp);
    }

#if defined(__APPLE_CC__) || defined(__APPLE__)
    #include <net/bpf.h>
    int fd = pcap_get_selectable_fd(pcap_handle);
    if (fd < 0) {
        Napi::Error::New(env, pcap_geterr(pcap_handle)).ThrowAsJavaScriptException();
        return env.Undefined();
    }
    int v = 1;
    ioctl(fd, BIOCIMMEDIATE, &v);
#endif

    int link_type = pcap_datalink(pcap_handle);

    switch (link_type) {
    case DLT_NULL:
        return Napi::String::New(env, "LINKTYPE_NULL");
    case DLT_EN10MB:
        return Napi::String::New(env, "LINKTYPE_ETHERNET");
    case DLT_IEEE802_11_RADIO:
        return Napi::String::New(env, "LINKTYPE_IEEE802_11_RADIO");
    case DLT_RAW:
        return Napi::String::New(env, "LINKTYPE_RAW");
    case DLT_LINUX_SLL:
        return Napi::String::New(env, "LINKTYPE_LINUX_SLL");
    default:
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unknown linktype %d", link_type);
        return Napi::String::New(env, errbuf);
    }
#endif
}

Napi::Value PcapSession::OpenLive(const Napi::CallbackInfo& info) {
    return Open(true, info);
}

Napi::Value PcapSession::OpenOffline(const Napi::CallbackInfo& info) {
    return Open(false, info);
}

void PcapSession::Close(const Napi::CallbackInfo& info) {
    (void)info;
#ifdef _WIN32
    Napi::Env env = info.Env();
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
#else
    if (pcap_dump_handle != NULL) {
        pcap_dump_close(pcap_dump_handle);
        pcap_dump_handle = NULL;
    }

    if (pcap_handle != NULL) {
        if (dispatching) {
            pcap_breakloop(pcap_handle);
        } else {
            FinalizeClose(this);
        }
    }
#endif
}

void PcapSession::FinalizeClose(PcapSession *session) {
    if (session->poll_init) {
        uv_poll_stop(&session->poll_handle);
        uv_unref(reinterpret_cast<uv_handle_t*>(&session->poll_handle));
        session->poll_init = false;
    }

#ifndef _WIN32
    if (session->pcap_handle) {
        pcap_close(session->pcap_handle);
        session->pcap_handle = NULL;
    }
    if (session->pcap_dump_handle) {
        pcap_dump_close(session->pcap_dump_handle);
        session->pcap_dump_handle = NULL;
    }
#endif

    if (!session->packet_ready_cb.IsEmpty()) {
        session->packet_ready_cb.Reset();
    }
}

void PcapSession::poll_handler(uv_poll_t* handle, int status, int events) {
    (void)status;
    (void)events;

    PcapSession* session = reinterpret_cast<PcapSession*>(handle->data);
    if (session == NULL) {
        return;
    }

    Napi::Env env = session->Env();
    Napi::HandleScope scope(env);

    Napi::Value callback_v = session->Value().Get("read_callback");
    if (!callback_v.IsFunction()) {
        return;
    }

    Napi::Function callback = callback_v.As<Napi::Function>();
    callback.Call(session->Value(), {});
}

void PcapSession::StartPolling(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
#else
    if (poll_init) {
        return;
    }

    if (pcap_handle == NULL) {
        Napi::Error::New(env, "Error: pcap session already closed").ThrowAsJavaScriptException();
        return;
    }

    int fd = pcap_get_selectable_fd(pcap_handle);
    if (fd < 0) {
        Napi::Error::New(env, pcap_geterr(pcap_handle)).ThrowAsJavaScriptException();
        return;
    }

    uv_loop_t* loop = NULL;
    if (napi_get_uv_event_loop(env, &loop) != napi_ok || loop == NULL) {
        Napi::Error::New(env, "Couldn't get UV event loop").ThrowAsJavaScriptException();
        return;
    }

    poll_handle.data = this;
    if (uv_poll_init(loop, &poll_handle, fd) < 0) {
        Napi::Error::New(env, "Couldn't initialize UV poll").ThrowAsJavaScriptException();
        return;
    }
    poll_init = true;

    if (uv_poll_start(&poll_handle, UV_READABLE, poll_handler) < 0) {
        Napi::Error::New(env, "Couldn't start UV poll").ThrowAsJavaScriptException();
        return;
    }
    uv_ref(reinterpret_cast<uv_handle_t*>(&poll_handle));
#endif
}

Napi::Value PcapSession::Stats(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
    return env.Undefined();
#else
    struct pcap_stat ps;

    if (pcap_handle == NULL) {
        Napi::Error::New(env, "Error: pcap session already closed").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (pcap_stats(pcap_handle, &ps) == -1) {
        Napi::Error::New(env, "Error in pcap_stats").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Object stats_obj = Napi::Object::New(env);
    stats_obj.Set("ps_recv", Napi::Number::New(env, ps.ps_recv));
    stats_obj.Set("ps_drop", Napi::Number::New(env, ps.ps_drop));
    stats_obj.Set("ps_ifdrop", Napi::Number::New(env, ps.ps_ifdrop));

    return stats_obj;
#endif
}

void PcapSession::Inject(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
        Napi::TypeError::New(env, "Inject takes exactly one argument").ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "First argument must be a buffer").ThrowAsJavaScriptException();
        return;
    }

#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
#else
    if (pcap_handle == NULL) {
        Napi::Error::New(env, "Error: pcap session already closed").ThrowAsJavaScriptException();
        return;
    }

    Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
    if (pcap_inject(pcap_handle, buffer.Data(), buffer.Length()) != static_cast<int>(buffer.Length())) {
        Napi::Error::New(env, "Pcap inject failed.").ThrowAsJavaScriptException();
        return;
    }
#endif
}
