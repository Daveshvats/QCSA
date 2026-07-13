// Benchmark for the LoomScan Rust regex engine.
//
// Run with: cargo bench
// Compares:
//   - Single-rule scan against a 10,000-line file
//   - 100-rule scan against the same file (parallelized)
//   - 1000-rule scan (stress test)

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use loomscan_regex::RegexEngine;

fn gen_content(lines: usize) -> String {
    (0..lines)
        .map(|i| {
            if i % 100 == 0 {
                format!("x = eval('expr_{}')\n", i)
            } else if i % 50 == 0 {
                format!("cursor.execute(f\"SELECT * FROM t WHERE id={i}\")\n")
            } else {
                format!("let var_{} = {} + {};\n", i, i, i + 1)
            }
        })
        .collect()
}

fn bench_scan_single_rule(c: &mut Criterion) {
    let mut engine = RegexEngine::new();
    engine.add_rule("eval-rule", r"\beval\s*\(", "high", "eval found", "CWE-95").unwrap();

    let mut group = c.benchmark_group("scan_single_rule");
    for size in [100, 1000, 10_000].iter() {
        let content = gen_content(*size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &content, |b, content| {
            b.iter(|| {
                let results = engine.scan(black_box(content));
                black_box(results);
            });
        });
    }
    group.finish();
}

fn bench_scan_many_rules(c: &mut Criterion) {
    // Build 100 and 1000-rule engines
    let mut engine_100 = RegexEngine::new();
    let mut engine_1000 = RegexEngine::new();
    for i in 0..100 {
        engine_100.add_rule(
            &format!("rule-{}", i),
            &format!(r"\bvar_{}\b", i),
            "low", "test", "",
        ).unwrap();
    }
    for i in 0..1000 {
        engine_1000.add_rule(
            &format!("rule-{}", i),
            &format!(r"\bvar_{}\b", i),
            "low", "test", "",
        ).unwrap();
    }

    let content = gen_content(10_000);

    let mut group = c.benchmark_group("scan_many_rules");
    group.bench_function("100_rules_10k_lines", |b| {
        b.iter(|| {
            let results = engine_100.scan(black_box(&content));
            black_box(results);
        });
    });
    group.bench_function("1000_rules_10k_lines", |b| {
        b.iter(|| {
            let results = engine_1000.scan(black_box(&content));
            black_box(results);
        });
    });
    group.finish();
}

fn bench_add_rules(c: &mut Criterion) {
    c.bench_function("add_1000_rules", |b| {
        b.iter(|| {
            let mut engine = RegexEngine::new();
            for i in 0..1000 {
                engine.add_rule(
                    &format!("rule-{}", i),
                    &format!(r"\bvar_{}\b", i),
                    "low", "test", "",
                ).unwrap();
            }
            black_box(engine);
        });
    });
}

criterion_group!(benches, bench_scan_single_rule, bench_scan_many_rules, bench_add_rules);
criterion_main!(benches);
