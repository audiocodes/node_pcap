var IPv4 = require("./ipv4");
var IPv6 = require("./ipv6");
var ARP = require("./arp");

class LogicalLinkControl {
    decoderName = "llc";
    eventsOnDecode = true;
    
    constructor(emitter) {
        this.emitter = emitter;
        this.dsap = undefined;
        this.ssap = undefined;
        this.controlField = undefined;
        this.orgCode = undefined;
        this.type = undefined;
        this._error = undefined;
    }
    decode(raw_packet, offset) {
        this.dsap = raw_packet[offset++];
        this.ssap = raw_packet[offset++];

        // https://en.wikipedia.org/wiki/IEEE_802.2#LSAP_Values
        // http://tools.ietf.org/html/rfc1700
        // 0xaa is SNAP
        // 0x00 is NULL LSAP
        if (((this.dsap === 0xaa) && (this.ssap === 0xaa)) ||
            ((this.dsap === 0x00) && (this.ssap === 0x00))) {
            this.controlField = raw_packet[offset++];
            this.orgCode = [
                raw_packet[offset++],
                raw_packet[offset++],
                raw_packet[offset++]
            ];
            this.type = raw_packet.readUInt16BE(offset); offset += 2;

            if (this.ethertype < 1536) {
                // this packet is actually some 802.3 type without an ethertype
                this.ethertype = 0;
            } else {
                switch (this.type) {
                    case 0x0800: // IPv4
                        this.payload = new IPv4(this.emitter).decode(raw_packet, offset);
                        break;
                    case 0x0806: // ARP
                        this.payload = new ARP(this.emitter).decode(raw_packet, offset);
                        break;
                    case 0x86dd: // IPv6
                        this.payload = new IPv6(this.emitter).decode(raw_packet, offset);
                        break;
                }
            }
        } else {
            this._error = "Unknown LLC types: DSAP: " + this.dsap + ", SSAP: " + this.ssap;
        }

        if (this.emitter) { this.emitter.emit("llc", this); }
        return this;
    }
}


module.exports = LogicalLinkControl;
