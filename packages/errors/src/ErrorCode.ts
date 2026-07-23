/**
 * Central error-code registry shared across the netkitty packages. Each entry pairs a numeric `errno`
 * with a stable string `code`. Numbers are grouped by package (1000s = capture, 2000s = codec,
 * 3000s = pcap/pcap-core, 4000s = analysis, 5000s = replay) so a code is globally unique and can be
 * switched on regardless of which package raised it. Concrete error classes reference these entries
 * when setting their `errno`/`code`.
 */
export const ErrorCode = {
    //capture (1000s)
    E_DEVICE_NOT_FOUND: {errno: 1000, code: 'E_DEVICE_NOT_FOUND'},
    E_NPCAP_LOAD: {errno: 1002, code: 'E_NPCAP_LOAD'},
    E_SOCKET_DOWN: {errno: 1003, code: 'E_SOCKET_DOWN'},
    E_UNKNOWN_PIPE_MESSAGE_TYPE: {errno: 1004, code: 'E_UNKNOWN_PIPE_MESSAGE_TYPE'},
    E_ACTION_NOT_FOUND: {errno: 1005, code: 'E_ACTION_NOT_FOUND'},
    E_CAPTURE_ARGUMENT: {errno: 1006, code: 'E_CAPTURE_ARGUMENT'},
    E_CAPTURE_OPEN: {errno: 1007, code: 'E_CAPTURE_OPEN'},
    E_CAPTURE_FILTER: {errno: 1008, code: 'E_CAPTURE_FILTER'},
    //codec (2000s)
    E_NO_AVAILABLE_CODEC: {errno: 2000, code: 'E_NO_AVAILABLE_CODEC'},
    E_CODEC_SCHEMA_VALIDATE: {errno: 2001, code: 'E_CODEC_SCHEMA_VALIDATE'},
    //pcap / pcap-core (3000s)
    E_PCAP_LZ4_FRAME: {errno: 3000, code: 'E_PCAP_LZ4_FRAME'},
    E_PCAP_EDIT_ARGUMENT: {errno: 3100, code: 'E_PCAP_EDIT_ARGUMENT'},
    E_PCAP_EDIT_STATE: {errno: 3101, code: 'E_PCAP_EDIT_STATE'},
    E_PCAP_PATCH_LENGTH: {errno: 3102, code: 'E_PCAP_PATCH_LENGTH'},
    E_PCAP_INVALID_MAC: {errno: 3103, code: 'E_PCAP_INVALID_MAC'},
    //analysis (4000s)
    E_ANALYSIS_STATE: {errno: 4000, code: 'E_ANALYSIS_STATE'},
    //replay (5000s)
    E_REPLAY_DEVICE_NOT_FOUND: {errno: 5000, code: 'E_REPLAY_DEVICE_NOT_FOUND'},
    E_REPLAY_ARGUMENT: {errno: 5001, code: 'E_REPLAY_ARGUMENT'},
    E_REPLAY_SEND: {errno: 5002, code: 'E_REPLAY_SEND'}
} as const
