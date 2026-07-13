// LoomScan Regex Engine — Rust core for high-performance pattern matching.
//
// v5.7: Now compiles to a Python-native extension via pyo3 + maturin.
// The Python `yaml_engine.py` module auto-detects this extension and uses
// it for 10-50x faster regex matching. Falls back to Python `re` if the
// extension isn't installed.
//
// Build:
//   cd rust-core
//   maturin build --release         # produces wheel in target/wheels/
//   pip install target/wheels/loomscan_regex-*.whl
//
// Or develop mode:
//   maturin develop --release       # installs into current venv
//
// Benchmark:
//   cargo bench                     # uses benches/scan_benchmark.rs

use regex::Regex;
use std::collections::HashMap;
use rayon::prelude::*;

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyList;
#[cfg(feature = "python")]
use pyo3::Bound;

pub struct CompiledRule {
    pub rule_id: String,
    pub pattern: Regex,
    pub severity: String,
    pub message: String,
    pub cwe: String,
}

pub struct RegexEngine {
    rules: Vec<CompiledRule>,
}

impl RegexEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule_id: &str, pattern: &str, severity: &str, message: &str, cwe: &str) -> Result<(), String> {
        match Regex::new(pattern) {
            Ok(re) => {
                self.rules.push(CompiledRule {
                    rule_id: rule_id.to_string(),
                    pattern: re,
                    severity: severity.to_string(),
                    message: message.to_string(),
                    cwe: cwe.to_string(),
                });
                Ok(())
            }
            Err(e) => Err(format!("Invalid regex '{}': {}", pattern, e)),
        }
    }

    /// Scan a file's content against all rules. Returns Vec of (rule_id, line, message).
    pub fn scan(&self, content: &str) -> Vec<(String, usize, String)> {
        let lines: Vec<&str> = content.lines().collect();

        // Parallel scan: each rule checks all lines in parallel
        let results: Vec<Vec<(String, usize, String)>> = self.rules
            .par_iter()
            .map(|rule| {
                let mut hits = Vec::new();
                for (i, line) in lines.iter().enumerate() {
                    if rule.pattern.is_match(line) {
                        hits.push((rule.rule_id.clone(), i + 1, rule.message.clone()));
                    }
                }
                hits
            })
            .collect();

        results.into_iter().flatten().collect()
    }

    /// Batch scan: multiple files in parallel
    pub fn scan_files(&self, files: &HashMap<String, String>) -> Vec<(String, String, usize, String)> {
        files
            .par_iter()
            .flat_map(|(path, content)| {
                self.scan(content)
                    .into_iter()
                    .map(|(rule_id, line, msg)| (path.clone(), rule_id, line, msg))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for RegexEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// pyo3 Python bindings
// ============================================================================
//
// The Python module is named `loomscan_regex`. It exposes:
//   - RegexEngine class with add_rule(), scan(), scan_files(), rule_count()
//   - is_available() function (always True when module imports)
//   - engine_version() function (returns the crate version)
//
// Python usage:
//   from loomscan_regex import RegexEngine, is_available
//   if is_available():
//       eng = RegexEngine()
//       eng.add_rule("r1", r"\beval\s*\(", "high", "eval found", "CWE-95")
//       hits = eng.scan("x = eval('1+1')\n")
//       # hits = [("r1", 1, "eval found")]

#[cfg(feature = "python")]
#[pyclass(name = "RegexEngine")]
struct PyRegexEngine {
    inner: RegexEngine,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyRegexEngine {
    #[new]
    fn new() -> Self {
        Self { inner: RegexEngine::new() }
    }

    /// Add a rule. Returns True on success, False if the regex is invalid.
    fn add_rule(&mut self, rule_id: &str, pattern: &str, severity: &str, message: &str, cwe: &str) -> bool {
        match self.inner.add_rule(rule_id, pattern, severity, message, cwe) {
            Ok(()) => true,
            Err(_) => false,  // Invalid regex — caller should fall back
        }
    }

    /// Add multiple rules at once. Each rule is a tuple of (rule_id, pattern, severity, message, cwe).
    /// Returns the number of rules successfully added.
    fn add_rules(&mut self, rules: &Bound<PyList>) -> usize {
        let mut count = 0;
        for item in rules.iter() {
            if let Ok(tuple) = item.extract::<(String, String, String, String, String)>() {
                if self.inner.add_rule(&tuple.0, &tuple.1, &tuple.2, &tuple.3, &tuple.4).is_ok() {
                    count += 1;
                }
            }
        }
        count
    }

    /// Scan a string. Returns a list of (rule_id, line_number, message) tuples.
    fn scan(&self, content: &str) -> Vec<(String, usize, String)> {
        self.inner.scan(content)
    }

    /// Scan multiple files. Takes a dict of {path: content}.
    /// Returns a list of (path, rule_id, line_number, message) tuples.
    fn scan_files(&self, files: HashMap<String, String>) -> Vec<(String, String, usize, String)> {
        self.inner.scan_files(&files)
    }

    /// Number of compiled rules.
    #[getter]
    fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }
}

#[cfg(feature = "python")]
#[pyfunction]
fn is_available() -> bool {
    true
}

#[cfg(feature = "python")]
#[pyfunction]
fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(feature = "python")]
#[pymodule]
fn loomscan_regex(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyRegexEngine>()?;
    m.add_function(wrap_pyfunction!(is_available, m)?)?;
    m.add_function(wrap_pyfunction!(engine_version, m)?)?;
    Ok(())
}

// ============================================================================
// Tests (Rust-native — run with `cargo test`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_scan() {
        let mut engine = RegexEngine::new();
        engine.add_rule("eval-rule", r"\beval\s*\(", "high", "eval found", "CWE-95").unwrap();
        // Use raw string with hashes to avoid 2024 edition char-literal lint
        engine.add_rule("sql-rule", r#"\.execute\s*\(\s*f['"]"#, "critical", "SQL injection", "CWE-89").unwrap();

        let content = "x = eval(\"1+1\")\ny = 1\nz = cursor.execute(f\"SELECT * FROM users WHERE id = user_id\")\n";
        let results = engine.scan(content);

        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|(r, _, _)| r == "eval-rule"));
        assert!(results.iter().any(|(r, _, _)| r == "sql-rule"));
    }

    #[test]
    fn test_parallel_scan() {
        let mut engine = RegexEngine::new();
        // Use word-boundary patterns so pattern0 doesn't match pattern50
        for i in 0..100 {
            engine.add_rule(&format!("rule-{}", i), &format!(r"\bpattern{}\b", i), "low", "test", "").unwrap();
        }

        let content = "pattern50\npattern99\n";
        let results = engine.scan(content);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_invalid_regex_returns_error() {
        let mut engine = RegexEngine::new();
        let result = engine.add_rule("bad-rule", r"[unclosed", "low", "test", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_engine() {
        let engine = RegexEngine::new();
        assert_eq!(engine.rule_count(), 0);
        let results = engine.scan("any content");
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_files_parallel() {
        let mut engine = RegexEngine::new();
        engine.add_rule("eval-rule", r"\beval\s*\(", "high", "eval found", "CWE-95").unwrap();

        let mut files = HashMap::new();
        files.insert("file1.py".to_string(), "x = eval('1')\n".to_string());
        files.insert("file2.py".to_string(), "y = 1\n".to_string());
        files.insert("file3.py".to_string(), "z = eval('2')\n".to_string());

        let results = engine.scan_files(&files);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|(p, _, _, _)| p == "file1.py"));
        assert!(results.iter().any(|(p, _, _, _)| p == "file3.py"));
    }

    #[test]
    fn test_multiline_content() {
        let mut engine = RegexEngine::new();
        engine.add_rule("test", r"TODO", "low", "todo found", "").unwrap();

        let content = "line1\nTODO: fix this\nline3\nTODO: another\n";
        let results = engine.scan(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, 2);  // line 2
        assert_eq!(results[1].1, 4);  // line 4
    }
}
