# HAKUZA Performance Optimization - Quick Reference

## Files in This Analysis

1. **HAKUZA_PERFORMANCE_OPTIMIZATION_REPORT.md** (Main document)
   - Complete performance analysis
   - Bottleneck identification
   - Detailed recommendations with impact estimates
   - Roadmap and success criteria

2. **OPTIMIZATION_CODE_EXAMPLES.md** (Implementation guide)
   - Ready-to-copy code snippets
   - Before/after comparisons
   - Verification procedures

3. **PERFORMANCE_BENCHMARK_SUITE.py** (Testing tool)
   - Automated benchmarks
   - Baseline tracking
   - Performance regression detection

4. **QUICK_REFERENCE.md** (This file)
   - Quick lookup table
   - Key metrics
   - Priority matrix

---

## Performance Summary

### Current Baseline (v2.0)
```
Startup:           1.83s  (target: <1.0s)
Single insert:     10.7ms per finding
1000 inserts:      10.7s
1000 PoC gen:      5-10 hours (blocking!)
Attack surface:    20ms (100 hosts)
Technique exec:    40s (40 params)
Memory:            500MB+ baseline
```

### Target Metrics (v3.0)
```
Startup:           <0.8s   (60% faster)
Single insert:     <3ms per finding
1000 inserts:      <3s
1000 PoC gen:      15-20 minutes (95% faster)
Attack surface:    <2ms (100 hosts)
Technique exec:    <10s (75% faster)
Memory:            <250MB baseline
```

---

## Optimization Priority Matrix

### P1 - CRITICAL (Do First)
Effort: 11 hours | Impact: 60% overall speedup

| # | Optimization | Location | Impact | Effort | Gain |
|---|---|---|---|---|---|
| 1 | Lazy import anthropic | hakuza.py | Startup | 2h | 550ms |
| 2 | Replace N+1 queries | mod_attack_graph.py | DB queries | 4h | 90-95% query reduction |
| 3 | Batch finding insertion | hakuza.py | Batch ops | 2h | 50-70% faster |
| 4 | Async PoC generation | mod_poc_generator.py | PoC gen | 3h | 80-90% faster |

### P2 - IMPORTANT (Do Second)
Effort: 7 hours | Impact: +25% additional speedup

| # | Optimization | Location | Impact | Effort | Gain |
|---|---|---|---|---|---|
| 5 | Lazy import flask | hakuza.py | Startup | 1h | 100-120ms |
| 6 | Add missing indices | mod_attack_graph.py | DB queries | 1h | 10-20% faster |
| 7 | Parallel HTTP requests | mod_active.py | Technique exec | 3h | 70-80% faster |
| 8 | Regex compilation cache | mod_active.py | Regex ops | 2h | 50-80ms |

### P3 - NICE-TO-HAVE (Do Later)
Effort: 5 hours | Impact: +10% additional

| # | Optimization | Location | Impact | Effort | Gain |
|---|---|---|---|---|---|
| 9 | Generator expressions | mod_active.py | Memory | 2h | 20-30% memory |
| 10 | LLM response cache | hakuza.py | Enrichment | 2h | 30-50% on repeats |
| 11 | Attack surface cache | mod_attack_graph.py | Graph queries | 1h | 10-20% faster |

---

## Implementation Timeline

### Week 1-2: P1 Optimizations
- [ ] Lazy import anthropic (2h) → 550ms startup gain
- [ ] Refactor get_client() pattern (1h)
- [ ] Test all LLM commands (1h)
- [ ] Replace N+1 queries in get_attack_surface() (4h)
- [ ] Add batch_add_findings() function (2h)
- [ ] Implement async PoC generation (3h)
- [ ] Run benchmarks (1h)
- **Target:** Startup <1.0s, 1000 findings in <3s

### Week 2-3: P2 Optimizations
- [ ] Lazy import flask (1h) → 100ms gain
- [ ] Add missing indices (1h)
- [ ] Implement ParallelHTTPTester (3h)
- [ ] Pre-compile regex patterns (2h)
- [ ] Run regression tests (1h)
- **Target:** Technique execution <10s, queries 10x faster

### Week 3-4: P3 Optimizations & Polish
- [ ] Generator expressions (2h)
- [ ] LLM response caching (2h)
- [ ] Attack surface caching (1h)
- [ ] Documentation updates (1h)
- [ ] Final benchmarking (1h)
- **Target:** v3.0 release ready

---

## Verification Checklist

### Before Each Commit
- [ ] Code compiles without errors
- [ ] All imports still work
- [ ] Benchmark suite passes
- [ ] No new warnings from linter

### Before Each Release
- [ ] Startup time <1.0s
- [ ] 1000 finding insert <3s
- [ ] Attack surface query <2ms
- [ ] Memory baseline <250MB
- [ ] All tests pass (regression + perf)
- [ ] Documentation updated

---

## Key Code Patterns

### Pattern 1: Lazy Imports
```python
# Instead of:
import expensive_module

# Do this:
_MODULE = None

def get_module():
    global _MODULE
    if _MODULE is None:
        import expensive_module
        _MODULE = expensive_module
    return _MODULE
```

### Pattern 2: Batch Operations
```python
# Instead of:
for item in items:
    db.execute(insert_query, item)
    db.commit()  # Commit each time

# Do this:
for item in items:
    db.execute(insert_query, item)
db.commit()  # Commit once
```

### Pattern 3: Join Queries
```python
# Instead of:
hosts = query_hosts()
for host in hosts:
    services = query_services(host.id)
    vulns = query_vulns(host.id)

# Do this:
rows = query_single_join("""
    SELECT h.*, s.*, v.*
    FROM hosts h
    LEFT JOIN services s ON s.host_id = h.id
    LEFT JOIN vulns v ON v.host_id = h.id
""")
# Reconstruct structure in Python
```

### Pattern 4: Regex Caching
```python
# Instead of:
if re.search(r'pattern', text):

# Do this:
_COMPILED['pattern'] = re.compile(r'pattern')
if _COMPILED['pattern'].search(text):
```

### Pattern 5: Parallel Execution
```python
# Instead of:
for item in items:
    result = slow_operation(item)
    results.append(result)

# Do this:
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(slow_operation, item) for item in items]
    results = [f.result() for f in as_completed(futures)]
```

---

## Quick Wins (< 1 hour each)

| Win | Gain | Effort |
|-----|------|--------|
| Lazy import anthropic | 550ms | 1h |
| Pre-compile top 5 regexes | 20-30ms | 30min |
| Add 3 key indices | 10-20% query speedup | 30min |
| Remove 1 unnecessary LLM call | 5-10s | 15min |

---

## Measuring Progress

### Run Benchmarks
```bash
# Establish baseline
python3 PERFORMANCE_BENCHMARK_SUITE.py --baseline

# After each optimization
python3 PERFORMANCE_BENCHMARK_SUITE.py --compare
```

### Track Specific Metrics
```bash
# Startup time
time python3 -c "import hakuza"

# Batch insertion
python3 -c "
from hakuza import add_findings_batch
import time
findings = [{'title': f'F{i}', 'url': 'http://test'} for i in range(1000)]
t0 = time.perf_counter()
add_findings_batch('eng1', findings)
print(f'{(time.perf_counter()-t0):.2f}s for 1000 findings')
"

# Query performance
python3 -c "
from mod_attack_graph import get_attack_surface
import time
t0 = time.perf_counter()
result = get_attack_surface('eng1')
print(f'{(time.perf_counter()-t0)*1000:.1f}ms for attack surface query')
"
```

---

## Common Issues & Fixes

### Issue: Lazy import breaks shared state
**Solution:** Store instance in module-level global variable, not class attribute

### Issue: Batch operations cause memory spike
**Solution:** Process in chunks of 1000, clear intermediate results

### Issue: Parallel requests trigger rate limiting
**Solution:** Add delay between requests, implement exponential backoff

### Issue: Cached data becomes stale
**Solution:** Add TTL (time-to-live) to caches, clear on update

### Issue: Tests fail after optimization
**Solution:** Add regression test for each optimization before committing

---

## Resources

- **Profiling:** Use `cProfile` and `tracemalloc`
- **Benchmarking:** Use `timeit` module
- **Testing:** Use `pytest` for regression tests
- **Monitoring:** Add metrics to production HAKUZA instances

---

## Success Indicators

✓ Startup drops from 1.83s to <0.8s  
✓ 1000 findings insert in <3s (vs 10.7s)  
✓ PoC generation parallelizes (5-10m vs 5-10h)  
✓ Attack surface queries sub-millisecond  
✓ Technique execution 4x faster (10s vs 40s)  
✓ Memory usage cut in half  
✓ All tests pass (no regressions)  
✓ Users report noticeably faster CLI experience  

---

## Need Help?

Refer to the main report for:
- Detailed analysis: `HAKUZA_PERFORMANCE_OPTIMIZATION_REPORT.md`
- Code examples: `OPTIMIZATION_CODE_EXAMPLES.md`
- Benchmarks: `PERFORMANCE_BENCHMARK_SUITE.py`

**Implementation Time Estimate:** 15-25 hours total  
**Expected Speedup:** 60-75% overall improvement
