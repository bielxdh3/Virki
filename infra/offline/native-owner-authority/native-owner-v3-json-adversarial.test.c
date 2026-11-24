/* Exercises the real C4 V3 JSON tokenizer, not a copied JSON grammar. */
#define main virki_owner_main_not_called_by_json_test
#include "native-owner-authority.c"
#undef main

static bool fixture_has_role(const char *json) {
  const char *begin = NULL, *end = NULL;
  const char *stop = json + strlen(json);
  /* Production's v3_validate_evidence_payload checks the WHOLE JSON syntax
   * before selecting fields. A field-only probe would bypass its admission. */
  return v3_json_skip_value(json, stop, 0) == stop &&
      v3_json_find_field(json, stop, "role", &begin, &end) &&
      v3_json_string_equals(begin, end, "runtime");
}

int main(void) {
  const char *valid = "{\"role\":\"runtime\",\"note\":\"m\\u0069grator\"}";
  if (!fixture_has_role(valid)) {
    puts("FAIL: canonical field rejected because a JSON value contains an escape");
    return 2;
  }
  const char *duplicate = "{\"role\":\"runtime\",\"role\":\"migrator\"}";
  if (fixture_has_role(duplicate)) {
    puts("FAIL: literal duplicate JSON key accepted");
    return 3;
  }
  /* Go encoding/json matches struct field tags case-insensitively, so the
   * downstream Go binding sees migrator even though the native C4 verifier
   * sees runtime. Both objects are otherwise valid JSON. */
  const char *case_alias = "{\"role\":\"runtime\",\"Role\":\"migrator\"}";
  if (fixture_has_role(case_alias)) {
    puts("FAIL: case-insensitive JSON key alias overrides C4's approval role");
    return 7;
  }
  /* JSON.parse treats \u0072ole as role, and its last value wins. The native
   * C4 reader previously read runtime instead. This must fail closed before
   * any field identity or signature claims can be admitted. */
  const char *escaped_alias = "{\"role\":\"runtime\",\"\\u0072ole\":\"migrator\"}";
  if (fixture_has_role(escaped_alias)) {
    puts("FAIL: escaped alias overrides the native C4 role in standard JSON");
    return 4;
  }
  const char *escaped_unknown = "{\"role\":\"runtime\",\"\\u006eote\":\"ok\"}";
  if (fixture_has_role(escaped_unknown)) {
    puts("FAIL: escaped object key passed C4's canonical JSON gate");
    return 5;
  }
  const char *nested_alias =
      "{\"role\":\"runtime\",\"other\":{\"\\u0072ole\":\"migrator\"}}";
  if (fixture_has_role(nested_alias)) {
    puts("FAIL: escaped nested object key passed the C4 tokenizer");
    return 6;
  }
  puts("C4_NATIVE_JSON_KEY_CANONICAL_PASS");
  return 0;
}
