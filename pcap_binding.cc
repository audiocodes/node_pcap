#include <assert.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <pcap/pcap.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#endif

#include "pcap_session.h"

#ifndef _WIN32
// Helper method, convert a sockaddr* (AF_INET or AF_INET6) to a string, and set it as the property
// named 'key' in the Address object you pass in.
static void SetAddrStringHelper(const char* key, sockaddr *addr, Napi::Object& Address){
  if(key && addr){
    char dst_addr[INET6_ADDRSTRLEN + 1] = {0};
    char* src = 0;
    socklen_t size = 0;
    if(addr->sa_family == AF_INET){
      struct sockaddr_in* saddr = (struct sockaddr_in*) addr;
      src = (char*) &(saddr->sin_addr);
      size = INET_ADDRSTRLEN;
    }else{
      struct sockaddr_in6* saddr6 = (struct sockaddr_in6*) addr;
      src = (char*) &(saddr6->sin6_addr);
      size = INET6_ADDRSTRLEN;
    }
    const char* address = inet_ntop(addr->sa_family, src, dst_addr, size);
    if(address){
        Address.Set(key, Napi::String::New(Address.Env(), address));
    }
  }
}
#endif

Napi::Value FindAllDevs(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
    return env.Undefined();
#else
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        Napi::TypeError::New(env, errbuf).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Array DevsArray = Napi::Array::New(env);

    int i = 0;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        Napi::Object Dev = Napi::Object::New(env);

        Dev.Set("name", Napi::String::New(env, cur_dev->name));
        if (cur_dev->description != NULL) {
            Dev.Set("description", Napi::String::New(env, cur_dev->description));
        }

        Napi::Array AddrArray = Napi::Array::New(env);
        int j = 0;
        for (pcap_addr_t *cur_addr = cur_dev->addresses ; cur_addr != NULL ; cur_addr = cur_addr->next, j++) {
          if (cur_addr->addr){
              int af = cur_addr->addr->sa_family;
              if(af == AF_INET || af == AF_INET6){
                Napi::Object Address = Napi::Object::New(env);
                SetAddrStringHelper("addr", cur_addr->addr, Address);
                SetAddrStringHelper("netmask", cur_addr->netmask, Address);
                SetAddrStringHelper("broadaddr", cur_addr->broadaddr, Address);
                SetAddrStringHelper("dstaddr", cur_addr->dstaddr, Address);
                AddrArray.Set(j, Address);
              }
           }
        }

        Dev.Set("addresses", AddrArray);

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            Dev.Set("flags", Napi::String::New(env, "PCAP_IF_LOOPBACK"));
        }

        DevsArray.Set(i, Dev);
    }

    pcap_freealldevs(alldevs);
    return DevsArray;
#endif
}

Napi::Value DefaultDevice(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
#ifdef _WIN32
    Napi::Error::New(env, "Not supported on Windows").ThrowAsJavaScriptException();
    return env.Undefined();
#else
    char errbuf[PCAP_ERRBUF_SIZE];

    // Look up the first device with an address, pcap_lookupdev() just returns the first non-loopback device.
    pcap_if_t *alldevs, *dev;
    pcap_addr_t *addr;
    bool found = false;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      Napi::Error::New(env, errbuf).ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (alldevs == NULL) {
      Napi::Error::New(env, "pcap_findalldevs didn't find any devs").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Value result = env.Undefined();

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if (dev->addresses != NULL && !(dev->flags & PCAP_IF_LOOPBACK)) {
            for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                // TODO - include IPv6 addresses in DefaultDevice guess
                // if (addr->addr->sa_family == AF_INET || addr->addr->sa_family == AF_INET6) {
                if (addr->addr->sa_family == AF_INET) {
                    result = Napi::String::New(env, dev->name);
                    found = true;
                    break;
                }
            }

            if (found) {
                break;
            }
        }
    }

    pcap_freealldevs(alldevs);
    return result;
#endif
}

Napi::Value LibVersion(const Napi::CallbackInfo& info)
{
#ifdef _WIN32
    return Napi::String::New(info.Env(), "libpcap version 1.10.5 (dummy for Windows)");
#else
    return Napi::String::New(info.Env(), pcap_lib_version());
#endif
}

Napi::Object Initialize(Napi::Env env, Napi::Object exports)
{
    PcapSession::Init(env, exports);

    exports.Set("findalldevs", Napi::Function::New(env, FindAllDevs));
    exports.Set("default_device", Napi::Function::New(env, DefaultDevice));
    exports.Set("lib_version", Napi::Function::New(env, LibVersion));

    return exports;
}

NODE_API_MODULE(pcap_binding, Initialize)
