/* Independent content-addressed OCI graph validation for the non-authorizing
 * V3 DEV protocol. Included after the bounded JSON span helpers. */
#ifndef VIRKI_NATIVE_OWNER_OCI_DAG_V3_H
#define VIRKI_NATIVE_OWNER_OCI_DAG_V3_H

#define V3_OCI_MAX_NODES 4096
#define V3_OCI_MAX_EDGES 16384
#define V3_OCI_MAX_DOCUMENT (4U * 1024U * 1024U)

enum v3_oci_kind { V3_OCI_UNKNOWN, V3_OCI_MANIFEST, V3_OCI_INDEX, V3_OCI_CONFIG, V3_OCI_LAYER };
typedef struct {
  v3_json_span digest, media;
  uint64_t size, offset;
  enum v3_oci_kind kind;
  unsigned state;
} v3_oci_node;

static enum v3_oci_kind v3_oci_kind_of(v3_json_span media) {
  const char *const manifests[] = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"};
  const char *const indexes[] = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"};
  const char *const configs[] = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"};
  const char *const layers[] = {
    "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.docker.image.rootfs.diff.tar.zstd",
    "application/vnd.docker.image.rootfs.foreign.diff.tar", "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
  };
  for (size_t i = 0; i < sizeof(manifests)/sizeof(*manifests); i++) if (v3_json_string_equals(media.s, media.e, manifests[i])) return V3_OCI_MANIFEST;
  for (size_t i = 0; i < sizeof(indexes)/sizeof(*indexes); i++) if (v3_json_string_equals(media.s, media.e, indexes[i])) return V3_OCI_INDEX;
  for (size_t i = 0; i < sizeof(configs)/sizeof(*configs); i++) if (v3_json_string_equals(media.s, media.e, configs[i])) return V3_OCI_CONFIG;
  for (size_t i = 0; i < sizeof(layers)/sizeof(*layers); i++) if (v3_json_string_equals(media.s, media.e, layers[i])) return V3_OCI_LAYER;
  return V3_OCI_UNKNOWN;
}

/* Structural fields must have unambiguous literal keys. The contents of
 * non-structural annotation/platform objects are not interpreted as edges. */
static bool v3_oci_object_keys_valid(v3_json_span obj) {
  if (*obj.s != '{') return false;
  const char *p = v3_json_skip_ws(obj.s + 1, obj.e);
  size_t count = 0;
  while (p < obj.e && *p != '}') {
    const char *key_end = v3_json_skip_string(p, obj.e);
    if (!key_end || ++count > 64 || key_end - p < 3 || key_end - p > 128 || memchr(p + 1, '\\', (size_t)(key_end - p - 2))) return false;
    char key[128];
    size_t len = (size_t)(key_end - p - 2);
    memcpy(key, p + 1, len); key[len] = '\0';
    v3_json_span value;
    if (!v3_json_field(obj, key, &value)) return false;
    p = v3_json_skip_ws(value.e, obj.e);
    if (p >= obj.e) return false;
    if (*p == '}') break;
    if (*p != ',') return false;
    p = v3_json_skip_ws(p + 1, obj.e);
  }
  return p == obj.e - 1;
}

static bool v3_oci_parse_descriptor(v3_json_span span, v3_oci_node *out) {
  return v3_oci_object_keys_valid(span) &&
      v3_json_field(span, "digest", &out->digest) && v3_json_digest(out->digest) &&
      v3_json_field(span, "mediaType", &out->media) && (out->kind = v3_oci_kind_of(out->media)) != V3_OCI_UNKNOWN &&
      v3_json_field_uint(span, "size", &out->size) && out->size > 0 && out->size <= VIRKI_OWNER_V3_OCI_MAX_BYTES;
}

static bool v3_oci_visit(int fd, v3_oci_node *nodes, size_t count, size_t index, unsigned depth, size_t *budget);

static bool v3_oci_child(int fd, v3_oci_node *nodes, size_t count, v3_json_span desc, enum v3_oci_kind kind, unsigned depth, size_t *budget) {
  if (*budget == 0) return false;
  --*budget;
  v3_oci_node declared = {0};
  if (!v3_oci_parse_descriptor(desc, &declared)) return false;
  if (kind == V3_OCI_INDEX) {
    if (declared.kind != V3_OCI_INDEX && declared.kind != V3_OCI_MANIFEST) return false;
  } else if (declared.kind != kind) return false;
  for (size_t i = 0; i < count; i++) {
    if (v3_json_same_span(nodes[i].digest, declared.digest)) {
      return nodes[i].size == declared.size && v3_json_same_span(nodes[i].media, declared.media) && v3_oci_visit(fd, nodes, count, i, depth, budget);
    }
  }
  return false;
}

static bool v3_oci_visit(int fd, v3_oci_node *nodes, size_t count, size_t index, unsigned depth, size_t *budget) {
  if (depth > 64 || nodes[index].state == 1) return false;
  v3_oci_node *node = &nodes[index];
  if (node->state == 2) return true;
  node->state = 1;
  if (node->kind == V3_OCI_CONFIG || node->kind == V3_OCI_LAYER) { node->state = 2; return true; }
  if (node->size == 0 || node->size > V3_OCI_MAX_DOCUMENT) return false;
  char *raw = malloc((size_t)node->size);
  if (!raw) return false;
  bool ok = false;
  if (!v3_read_exact_at(fd, raw, (size_t)node->size, (off_t)node->offset) || memchr(raw, '\0', (size_t)node->size)) goto done;
  const char *end = raw + node->size;
  const char *start = v3_json_skip_ws(raw, end);
  const char *stop = v3_json_skip_value(start, end, 0);
  if (!stop || v3_json_skip_ws(stop, end) != end) goto done;
  v3_json_span doc = {start, stop}, value, children, child;
  uint64_t version;
  if (!v3_oci_object_keys_valid(doc) || !v3_json_field_uint(doc, "schemaVersion", &version) || version != 2) goto done;
  if (v3_json_field(doc, "mediaType", &value) && !v3_json_same_span(value, node->media)) goto done;
  // Artifact/referrer graphs are not admitted by this ordinary image schema.
  if (v3_json_field(doc, "subject", &value) || v3_json_field(doc, "artifactType", &value)) goto done;
  if (node->kind == V3_OCI_MANIFEST) {
    if (v3_json_field(doc, "manifests", &value) || !v3_json_field(doc, "config", &value) ||
        !v3_oci_child(fd, nodes, count, value, V3_OCI_CONFIG, depth+1, budget) || !v3_json_field(doc, "layers", &children)) goto done;
  } else {
    if (v3_json_field(doc, "config", &value) || v3_json_field(doc, "layers", &value) || !v3_json_field(doc, "manifests", &children)) goto done;
  }
  if (*children.s != '[') goto done;
  const char *cursor = children.s + 1;
  size_t edges = 0;
  while (v3_json_array_item(&cursor, children.e, &child)) {
    if (++edges > V3_OCI_MAX_NODES || !v3_oci_child(fd, nodes, count, child,
        node->kind == V3_OCI_MANIFEST ? V3_OCI_LAYER : V3_OCI_INDEX, depth+1, budget)) goto done;
  }
  if (v3_json_skip_ws(cursor, children.e) != children.e - 1 || (node->kind == V3_OCI_INDEX && edges == 0)) goto done;
  node->state = 2;
  ok = true;
done:
  free(raw);
  return ok;
}

/* The archive is exactly the concatenation of unique node blobs. Rehash the
 * actual bytes, then independently traverse the graph from the signed root.
 * No edge, size or digest supplied by the exporter is sufficient on its own. */
static bool v3_verify_oci_archive(int fd, uint64_t archive_size, v3_json_span root, v3_json_span entries) {
  if (archive_size == 0 || archive_size > VIRKI_OWNER_V3_OCI_MAX_BYTES || *entries.s != '[') return false;
  v3_oci_node *nodes = calloc(V3_OCI_MAX_NODES, sizeof(*nodes));
  if (!nodes) return false;
  bool ok = false;
  size_t count = 0;
  uint64_t offset = 0;
  const char *cursor = entries.s + 1;
  v3_json_span entry;
  while (v3_json_array_item(&cursor, entries.e, &entry)) {
    if (count == V3_OCI_MAX_NODES || !v3_oci_parse_descriptor(entry, &nodes[count]) || nodes[count].size > archive_size - offset) goto done;
    v3_oci_node *node = &nodes[count];
    for (size_t i = 0; i < count; i++) if (v3_json_same_span(nodes[i].digest, node->digest)) goto done;
    char hash[65];
    if (!v3_hash_fd_range(fd, (off_t)offset, node->size, hash) || memcmp(node->digest.s + 8, hash, 64) != 0) goto done;
    node->offset = offset;
    offset += node->size;
    count++;
  }
  if (count == 0 || offset != archive_size || v3_json_skip_ws(cursor, entries.e) != entries.e - 1) goto done;
  v3_oci_node signed_root = {0};
  size_t budget = V3_OCI_MAX_EDGES;
  if (!v3_oci_parse_descriptor(root, &signed_root) || (signed_root.kind != V3_OCI_INDEX && signed_root.kind != V3_OCI_MANIFEST) ||
      !v3_json_same_span(nodes[0].digest, signed_root.digest) || !v3_json_same_span(nodes[0].media, signed_root.media) || nodes[0].size != signed_root.size ||
      !v3_oci_visit(fd, nodes, count, 0, 0, &budget)) goto done;
  for (size_t i = 0; i < count; i++) if (nodes[i].state != 2) goto done;
  ok = true;
done:
  free(nodes);
  return ok;
}
#endif
