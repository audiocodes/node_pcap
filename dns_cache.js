var dns = require("dns");

// cache reverse DNS lookups for the life of the program. No TTL checking. No tricks.

class DNSCache {
    constructor() {
        this.cache = {};
        this.requests = {};
    }
    ptr(ip) {
        if (this.cache[ip]) {
            return this.cache[ip];
        }

        if (this.requests[ip] === undefined) {
            this.requests[ip] = true;
            var self = this;
            dns.reverse(ip, function (err, domains) {
                self.on_ptr(err, ip, domains);
            });
        }

        return ip;
    }
    on_ptr(err, ip, domains) {
        // TODO - check for network and broadcast addrs, since we have iface info
        if (err) {
            this.cache[ip] = ip;
        } else {
            this.cache[ip] = domains[0];
        }
    }
}



module.exports = DNSCache;
