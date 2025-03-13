{
  "targets": [
    {
      "target_name": "nodepcap",
      "product_dir": "<(module_root_dir)/bindings/nodepcap",
      "sources": [
        "cpp/nodepcap/src/binding.cc",
        "cpp/nodepcap/src/capture.cc",
        "cpp/nodepcap/src/utils.cc"
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
            "sources": [],
            "include_dirs": [
              "cpp/nodepcap/deps/include"
            ],
            "defines": [
              "WPCAP"
            ],
            "conditions": [
              [
                "target_arch==\"ia32\"",
                {
                  "link_settings": {
                    "libraries": [
                      "ws2_32.lib",
                      "<(PRODUCT_DIR)/../../cpp/nodepcap/deps/lib/wpcap.lib"
                    ]
                  }
                },
                {
                  "link_settings": {
                    "libraries": [
                      "ws2_32.lib",
                      "<(PRODUCT_DIR)/../../cpp/nodepcap/deps/lib/x64/wpcap.lib"
                    ]
                  }
                }
              ]
            ],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1
              },
              "VCLinkerTool": {
                "DelayLoadDLLs": [
                  "wpcap.dll"
                ]
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
