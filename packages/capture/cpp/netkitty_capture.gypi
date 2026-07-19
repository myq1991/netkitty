{
  "targets": [
    {
      "target_name": "netkitty_capture",
      "product_dir": "<(module_root_dir)/bindings",
      "sources": [
        "src/binding.cc",
        "src/capture.cc",
        "src/utils.cc",
        "src/pcap_api.cc"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [
        "-fno-exceptions"
      ],
      "cflags_cc!": [
        "-fno-exceptions"
      ],
      "conditions": [
        [
          "OS==\"win\"",
          {
            "defines": [
              "WPCAP"
            ],
            "link_settings": {
              "libraries": [
                "ws2_32.lib",
                "iphlpapi.lib"
              ]
            },
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1
              }
            }
          }
        ],
        [
          "OS==\"mac\"",
          {
            "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "MACOSX_DEPLOYMENT_TARGET": "10.9",
              "OTHER_CFLAGS": [
                "-arch x86_64",
                "-arch arm64"
              ],
              "OTHER_LDFLAGS": [
                "-framework CoreFoundation",
                "-framework IOKit",
                "-arch x86_64",
                "-arch arm64"
              ]
            },
            "link_settings": {
              "libraries": [
                "-lpcap"
              ]
            }
          }
        ],
        [
          "OS!=\"win\"",
          {
            "link_settings": {
              "libraries": [
                "-lpcap"
              ]
            }
          }
        ]
      ]
    }
  ]
}
