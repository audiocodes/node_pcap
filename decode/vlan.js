class Vlan {
    decoderName = "vlan";
    eventsOnDecode = false;
    
    constructor() {
        this.priority = null;
        this.canonical_format = null;
        this.id = null;
    }
    // http://en.wikipedia.org/wiki/IEEE_802.1Q
    decode(raw_packet, offset) {
        this.priority = (raw_packet[offset] & 0xE0) >> 5;
        this.canonical_format = (raw_packet[offset] & 0x10) >> 4;
        this.id = ((raw_packet[offset] & 0x0F) << 8) | raw_packet[offset + 1];

        return this;
    }
    toString() {
        return this.priority + " " + this.canonical_format + " " + this.id;
    }
}



module.exports = Vlan;
