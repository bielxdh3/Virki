// Synthetic SARIF restricted to fields documented by GitHub for CodeQL CLI.
// It validates parser compatibility, NOT CodeQL execution or scan coverage.
export function codeqlDocument(findings = []) {
  const ruleIds = [...new Set(["js/path-injection", ...findings.map((item) => item.ruleId)])];
  const rules = ruleIds.map((id) => ({ id, name: id }));
  const sourcePaths = [...new Set(findings.map((item) => item.path.replace(/^file:\/\/\/github\/workspace\//u, "")))];
  const artifacts = sourcePaths.map((uri) => ({ location: { uri, uriBaseId: "%SRCROOT%" } }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "CodeQL command-line toolchain", organization: "GitHub", version: "2.23.0", rules } },
      properties: { "semmle.formatSpecifier": "sarif-latest" },
      newLineSequences: ["\n", "\r\n"],
      columnKind: "utf16CodeUnits",
      artifacts,
      results: findings.map(({ ruleId, path, lineFingerprint, columnFingerprint }) => ({
        ruleId,
        ruleIndex: ruleIds.indexOf(ruleId),
        message: { text: `Synthetic finding for ${ruleId}` },
        locations: [{ physicalLocation: { artifactLocation: {
          uri: path, index: sourcePaths.indexOf(path.replace(/^file:\/\/\/github\/workspace\//u, ""))
        }, region: { startLine: 1 } } }],
        ...(lineFingerprint && columnFingerprint ? { partialFingerprints: {
          primaryLocationLineHash: lineFingerprint,
          primaryLocationStartColumnFingerprint: columnFingerprint
        } } : {})
      }))
    }]
  };
}

// Sanitized, synthetic counterpart to the hosted CodeQL 2.27.1 SARIF shape:
// CodeQL/GitHub/semanticVersion, grouped rules in extensions and result.rule.
// Observed in Virki hosted run 42033025663; no production SARIF content here.
export function codeqlHostedCliDocument(findings = []) {
  const document = codeqlDocument(findings);
  const run = document.runs[0];
  const rules = run.tool.driver.rules;
  run.tool.driver = { name: "CodeQL", organization: "GitHub", semanticVersion: "2.27.1", rules: [] };
  run.tool.extensions = [
    { name: "codeql-action/pr-diff-range", rules: [] },
    { name: "codeql/javascript-queries", rules },
    { name: "codeql/javascript-all", rules: [] },
    { name: "codeql/threat-models", rules: [] }
  ];
  for (const result of run.results) {
    result.rule = { id: result.ruleId, index: result.ruleIndex, toolComponent: { index: 1 } };
    delete result.ruleIndex;
  }
  return document;
}
