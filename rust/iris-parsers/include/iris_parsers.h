#ifndef IRIS_PARSERS_H
#define IRIS_PARSERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================
// Common types
// ============================================================

/// Borrowed byte slice — valid only while the source buffer is alive.
typedef struct {
    const uint8_t *ptr;
    size_t len;
} IrisSlice;

/// Owned array of null-terminated C strings.
typedef struct {
    char **items;
    size_t count;
} IrisCStringArray;

/// Free a byte buffer allocated by any iris_* function.
void iris_free_bytes(uint8_t *data, size_t len);

// ============================================================
// HTTP parser
// ============================================================

typedef struct {
    IrisSlice name;
    IrisSlice value;
} IrisHttpHeader;

typedef struct {
    IrisSlice method;
    IrisSlice path;
    uint8_t version_minor;  // 0 = HTTP/1.0, 1 = HTTP/1.1
    size_t header_end_index;
    int64_t content_length;  // -1 = absent
    bool is_chunked;
    IrisHttpHeader *headers;
    size_t headers_count;
} IrisHttpRequest;

typedef struct {
    uint16_t status_code;
    IrisSlice reason;
    uint8_t version_minor;
    size_t header_end_index;
    int64_t content_length;
    bool is_chunked;
    bool has_body;
    bool has_framing;
    bool should_close;
    IrisHttpHeader *headers;
    size_t headers_count;
} IrisHttpResponse;

/// Parse HTTP request. Returns 0=ok, -1=incomplete, -2=error.
int32_t iris_http_parse_request(const uint8_t *data, size_t len, IrisHttpRequest *out);
int32_t iris_http_parse_response(const uint8_t *data, size_t len, IrisHttpResponse *out);
void iris_http_free_request(IrisHttpRequest *req);
void iris_http_free_response(IrisHttpResponse *resp);

// ============================================================
// Mach-O parser (goblin)
// ============================================================

typedef struct {
    IrisCStringArray load_dylibs;
    IrisCStringArray weak_dylibs;
    IrisCStringArray rpaths;
    IrisCStringArray reexport_dylibs;
    uint32_t file_type;
} IrisMachOInfo;

/// Parse a Mach-O binary at path. Returns 0=ok, -1=file error, -2=parse error.
int32_t iris_macho_parse(const char *path, IrisMachOInfo *out);
void iris_macho_free(IrisMachOInfo *info);

// ============================================================
// DNS parser (RFC 1035)
// ============================================================

typedef struct {
    char *name;
    uint16_t record_type;
    uint16_t qclass;
} IrisDnsQuestion;

typedef struct {
    char *name;
    uint16_t record_type;
    uint16_t rrclass;
    uint32_t ttl;
    uint8_t *rdata;
    size_t rdata_len;
    char *display_value;
} IrisDnsRecord;

typedef struct {
    uint16_t id;
    bool is_response;
    uint8_t opcode;
    bool is_authoritative;
    bool is_truncated;
    bool recursion_desired;
    bool recursion_available;
    uint8_t response_code;
    IrisDnsQuestion *questions;
    size_t questions_count;
    IrisDnsRecord *answers;
    size_t answers_count;
    IrisDnsRecord *authority;
    size_t authority_count;
    IrisDnsRecord *additional;
    size_t additional_count;
} IrisDnsMessage;

/// Parse DNS wire format. Returns 0=ok, -2=error.
int32_t iris_dns_parse(const uint8_t *data, size_t len, IrisDnsMessage *out);

/// Build a DNS query. Serialized bytes returned via out_data/out_len.
/// Free with iris_free_bytes.
int32_t iris_dns_build_query(
    const char *domain, uint16_t record_type, uint16_t id,
    bool recursion_desired, uint8_t **out_data, size_t *out_len);

void iris_dns_free_message(IrisDnsMessage *msg);

// ============================================================
// DER encoder (ASN.1)
// ============================================================
// All DER functions return 0=ok, -2=error.
// Output bytes are allocated — free with iris_free_bytes(out, out_len).

int32_t iris_der_build_integer_i64(int64_t value, uint8_t **out, size_t *out_len);
int32_t iris_der_build_integer_bytes(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_sequence(const uint8_t *content, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_set(const uint8_t *content, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_bit_string(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_octet_string(const uint8_t *data, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_boolean(bool value, uint8_t **out, size_t *out_len);
int32_t iris_der_build_oid(const uint32_t *components, size_t count, uint8_t **out, size_t *out_len);
int32_t iris_der_build_utf8_string(const char *str, uint8_t **out, size_t *out_len);
int32_t iris_der_build_printable_string(const char *str, uint8_t **out, size_t *out_len);
int32_t iris_der_build_explicit_tag(uint8_t tag, const uint8_t *content, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_implicit_tag(uint8_t tag, const uint8_t *content, size_t len, uint8_t **out, size_t *out_len);
int32_t iris_der_build_utc_time(int64_t unix_timestamp, uint8_t **out, size_t *out_len);
int32_t iris_der_build_generalized_time(int64_t unix_timestamp, uint8_t **out, size_t *out_len);

// ============================================================
// Batch operations (SHA256, entropy)
// ============================================================

/// SHA256 hash a file. Returns hex string via out_hex. Free with iris_free_string.
/// Returns 0=ok, -1=file error, -2=arg error.
int32_t iris_sha256_file(const char *path, char **out_hex);

/// Free a string from iris_sha256_file.
void iris_free_string(char *ptr);

/// Shannon entropy of a file (0.0–8.0). Returns 0=ok, -1=error.
int32_t iris_file_entropy(const char *path, double *out);

/// Batch SHA256: hash multiple files. Returns array of hex digests.
/// Empty string for files that failed. Free with iris_batch_sha256_free.
int32_t iris_batch_sha256(const char **paths, size_t count, IrisCStringArray *out);
void iris_batch_sha256_free(IrisCStringArray *arr);

/// Full entropy analysis result.
typedef struct {
    double entropy;               // Shannon entropy (0.0–8.0)
    double chi_square;            // Chi-square for uniform distribution
    double monte_carlo_pi_error;  // % error from true pi
    bool is_encrypted;            // Combined determination
    bool is_known_format;         // Magic bytes matched (analysis skipped)
} IrisEntropyResult;

/// Full entropy analysis: Shannon, chi-square, Monte Carlo pi, encrypted detection.
/// Reads up to 3MB. Returns 0=ok, -1=too small/error, -2=arg error, -3=known format.
int32_t iris_file_entropy_full(const char *path, IrisEntropyResult *out);

#endif
