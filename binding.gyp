{
  "targets": [
    {
      "target_name": "pcap_binding",
      "sources": [ "pcap_binding.cc", "pcap_session.cc" ],
      "conditions": [
        ['OS!="win"', {
          "link_settings": {
            "libraries": [
              "-lpcap"
            ]
          }
        }],
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
    },
    {
      "target_name": "action_after_build",
      "type": "none",
      "dependencies": [ "pcap_binding" ],
      "copies": [ {
        "files": [ "<(PRODUCT_DIR)/pcap_binding.node" ],
        "destination": "out",
      } ],
    }
  ]
}
