const { EventEmitter } = require("events");
const binding          = require("./out/pcap_binding");
const { decode }       = require("./decode");
const tcp_tracker      = require("./tcp_tracker");
const DNSCache         = require("./dns_cache");
const { setImmediate } = require("timers/promises");
const { Buffer }       = require("buffer");
const process          = require("process");

exports.decode = decode;
exports.TCPTracker = tcp_tracker.TCPTracker;
exports.TCPSession = tcp_tracker.TCPSession;
exports.DNSCache = DNSCache;

// This may be overriden by the user
exports.warningHandler = function warningHandler(x) {
    console.warn('warning: %s - this may not actually work', x);
};

class PcapSession extends EventEmitter {
    constructor(options) {
        super();
        this.options = {...options};
        this.options.filter ||= "";
        this.options.outfile ||= "";
        this.options.promiscuous ??= true;
        this.options.yield_after_packets ??= 1000;

        this.link_type = null;
        this.opened = null;
        this.buf = null;
        this.header = null;
        this.empty_reads = 0;
        this.packets_read = null;

        this.session = new binding.PcapSession();

        if (typeof this.options.buffer_size === "number" && !isNaN(this.options.buffer_size)) {
            this.options.buffer_size = Math.round(this.options.buffer_size);
        } else {
            this.options.buffer_size = 10 * 1024 * 1024; // Default buffer size is 10MB
        }

        if (typeof this.options.snap_length === "number" && !isNaN(this.options.snap_length)) {
            this.options.snap_length = Math.round(this.options.snap_length);
        } else {
            this.options.snap_length = 65535; // Default snap length is 65535
        }

        if (typeof this.options.buffer_timeout === "number" && !isNaN(this.options.buffer_timeout)) {
            this.options.buffer_timeout = Math.round(this.options.buffer_timeout);
        } else {
            this.options.buffer_timeout = 1000; // Default buffer timeout is 1s
        }

        const is_live = !options.path;
        const packet_ready = this.on_packet_ready.bind(this);
        if (is_live) {
            this.link_type = this.session.open_live(
                this.options.device || binding.default_device(),
                this.options.filter,
                this.options.buffer_size,
                this.options.snap_length,
                this.outfile,
                packet_ready,
                this.options.monitor,
                this.options.buffer_timeout,
                exports.warningHandler,
                this.options.promiscuous
            );
        } else {
            this.link_type = this.session.open_offline(
                this.options.path,
                this.options.filter,
                this.options.buffer_size,
                this.options.snap_length,
                this.outfile,
                packet_ready,
                this.options.monitor,
                this.options.buffer_timeout,
                exports.warningHandler,
                this.options.promiscuous
            );
        }

        this.opened = true;
        this.buf = Buffer.alloc(this.options.snap_length);
        this.header = Buffer.alloc(16);

        if (is_live) {
            // callback when pcap has data to read. multiple packets may be readable.
            this.session.read_callback = () => {
                var packets_read = this.session.dispatch(this.buf, this.header);
                if (packets_read < 1) {
                    this.empty_reads += 1;
                }
            };
            this.session.start_polling();
            process.nextTick(this.session.read_callback); // kickstart to prevent races
        } else {
            (async () => {
                const packets_to_yield = this.options.yield_after_packets;
                await setImmediate();
                for (let count = 1; ; ++count) {
                    if (packets_to_yield && count % packets_to_yield === 0)
                        await setImmediate();
                    const packets = this.session.dispatch(this.buf, this.header);
                    if (packets <= 0)
                        break;
                };
                this.emit("end");
                this.emit("complete");
                this.close();
            })();
        }
    }
    on_packet_ready() {
        var full_packet = new PacketWithHeader(this.buf, this.header, this.link_type);
        this.emit("packet", full_packet);
    }
    close() {
        if (!this.opened)
            return;

        this.opened = false;

        this.removeAllListeners();

        this.session.close();
    }
    stats() {
        return this.session.stats();
    }
    inject(data) {
        return this.session.inject(data);
    }
}

exports.lib_version = binding.lib_version();

exports.findalldevs = function () {
    return binding.findalldevs();
};

function PacketWithHeader(buf, header, link_type) {
    this.buf = buf;
    this.header = header;
    this.link_type = link_type;
}





exports.Pcap = PcapSession;
exports.PcapSession = PcapSession;

exports.createSession = function (device, options) {
    options = {
        device,
        ...options
    };
    return new PcapSession(options);
};

exports.createOfflineSession = function (path, options) {
    options = {
        path,
        buffer_size: 0,
        ...options
    };
    return new PcapSession(options);
};
