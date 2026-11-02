//! Bounded algebra witnesses and reference illustrations, not a production rate limiter.
//! These tests exercise the public summary algebra, not membership storage or admission caps.
use rebase_semantic_proof::algebra::Summary;

type Point = (i64, Option<i128>);

fn fold(points: &[Point]) -> Summary {
    points.iter().fold(Summary::default(), |s, &(t, a)| {
        s.combine(Summary::leaf(t, a)).unwrap()
    })
}

// Derive every field directly from source prefixes, without combining cached summaries.
fn source_summary(points: &[Point]) -> Summary {
    let mut total = 0;
    let mut prefixes = vec![0];
    let mut boundaries = Vec::new();
    for (i, &(t, a)) in points.iter().enumerate() {
        total += a.unwrap_or(0);
        prefixes.push(total);
        if points.get(i + 1).is_some_and(|next| t < next.0) {
            boundaries.push(total);
        }
    }
    Summary {
        count: points.len() as u64,
        first: points.first().map(|p| p.0),
        last: points.last().map(|p| p.0),
        sum: total,
        min_prefix: *prefixes.iter().min().unwrap(),
        max_prefix: *prefixes.iter().max().unwrap(),
        boundary_min: boundaries.iter().copied().min(),
        boundary_max: boundaries.iter().copied().max(),
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed >> 32
}

fn vectors() -> Vec<Vec<Point>> {
    let mut seed = 719;
    (0..240)
        .map(|case| {
            let mut t = -5;
            (0..case % 13)
                .map(|_| {
                    t += (next(&mut seed) % 3) as i64;
                    let a = match next(&mut seed) % 7 {
                        0 => None,
                        v => Some(v as i128 - 3),
                    };
                    (t, a)
                })
                .collect()
        })
        .collect()
}

#[test]
fn ordered_regrouping_matches_source_prefixes_and_complete_boundaries() {
    for points in vectors() {
        let expected = source_summary(&points);
        assert_eq!(fold(&points), expected);
        let mut balance = 0;
        let mut complete = vec![0];
        for (i, &(t, amount)) in points.iter().enumerate() {
            balance += amount.unwrap_or(0);
            if points.get(i + 1).is_none_or(|next| next.0 != t) {
                complete.push(balance);
            }
        }
        assert_eq!(expected.complete_min(), *complete.iter().min().unwrap());
        assert_eq!(expected.complete_max(), *complete.iter().max().unwrap());
        for i in 0..=points.len() {
            for j in i..=points.len() {
                let a = fold(&points[..i]);
                let b = fold(&points[i..j]);
                let c = fold(&points[j..]);
                let left = a.combine(b).unwrap().combine(c).unwrap();
                let right = a.combine(b.combine(c).unwrap()).unwrap();
                assert_eq!(left, expected);
                assert_eq!(right, expected);
            }
        }
    }
}

#[test]
fn weighted_leaf_projection_supports_nonunit_signed_coefficients() {
    // A reference leaf projection, not a constraint solver or new native family.
    let coefficients = [-2_i128, 3, 5];
    let mut seed = 91;
    for n in 0..40 {
        let rows: Vec<[i128; 3]> = (0..n)
            .map(|_| std::array::from_fn(|_| (next(&mut seed) % 17) as i128 - 8))
            .collect();
        let projected: Vec<Point> = rows
            .iter()
            .enumerate()
            .map(|(t, row)| {
                let value = row.iter().zip(coefficients).map(|(x, c)| x * c).sum();
                (t as i64, Some(value))
            })
            .collect();
        let field_totals: [i128; 3] = std::array::from_fn(|j| rows.iter().map(|row| row[j]).sum());
        let expected: i128 = field_totals
            .iter()
            .zip(coefficients)
            .map(|(x, c)| x * c)
            .sum();
        assert_eq!(fold(&projected).sum, expected);
    }
}

#[test]
fn occurrence_prefixes_are_ordered_but_complete_time_groups_are_atomic() {
    let credit_first = fold(&[(7, Some(1)), (7, Some(-1))]);
    let debit_first = fold(&[(7, Some(-1)), (7, Some(1))]);
    assert_eq!(credit_first.min_prefix, 0);
    assert_eq!(debit_first.min_prefix, -1);
    assert_ne!(credit_first, debit_first);
    assert_eq!(credit_first.complete_min(), 0);
    assert_eq!(debit_first.complete_min(), 0);
    assert_eq!(credit_first.boundary_min, None);
    assert_eq!(debit_first.boundary_min, None);
}

#[test]
fn representable_final_sum_does_not_establish_intermediate_arithmetic_safety() {
    let m = i128::MAX;
    // Scalar reference: checked addition alone has shape-dependent failure.
    assert!(m.checked_add(1).is_none());
    assert_eq!(m.checked_add(1_i128.checked_add(-1).unwrap()), Some(m));
    // Algebra-level inputs: runtime model admission may impose much smaller caps.
    // Native summaries also retain maximum prefixes, rejecting both groupings.
    let a = Summary::leaf(0, Some(m));
    let b = Summary::leaf(1, Some(1));
    let c = Summary::leaf(2, Some(-1));
    assert!(a.combine(b).and_then(|ab| ab.combine(c)).is_err());
    assert!(b.combine(c).and_then(|bc| a.combine(bc)).is_err());
}

// Independent exhaustive endpoint oracle for nonnegative point weights and (t-W,t].
// This is a reference illustration; no production limiter/admission API is asserted.
fn rolling_at(points: &[(i64, i128)], width: i64, t: i64) -> i128 {
    assert!(width > 0);
    points
        .iter()
        .filter(|(at, weight)| {
            assert!(*weight >= 0);
            t - width < *at && *at <= t
        })
        .map(|(_, weight)| weight)
        .sum()
}

fn rolling_max(points: &[(i64, i128)], width: i64) -> i128 {
    points
        .iter()
        .map(|(t, _)| rolling_at(points, width, *t))
        .max()
        .unwrap_or(0)
}

#[test]
fn insertion_can_break_a_later_window_while_its_own_endpoint_passes() {
    let old = [(0, 1), (9, 1)];
    let changed = [(0, 1), (8, 1), (9, 1)];
    assert_eq!(rolling_max(&old, 10), 2);
    assert_eq!(rolling_at(&changed, 10, 8), 2);
    assert_eq!(rolling_at(&changed, 10, 9), 3);
    assert!(rolling_max(&changed, 10) > 2);
}

fn endpoint_summary(points: &[(i64, i128)], width: i64) -> Summary {
    let mut endpoints: Vec<Point> = points
        .iter()
        .flat_map(|&(t, w)| [(t, Some(w)), (t + width, Some(-w))])
        .collect();
    // Expire before admitting at equal times. Complete-time extrema remain the
    // specified observation rule, regardless of within-group occurrence prefixes.
    endpoints.sort_by_key(|&(t, w)| (t, w.unwrap()));
    fold(&endpoints)
}

#[test]
fn two_derived_endpoints_match_exhaustive_fixed_width_rolling_windows() {
    let width = 10;
    let mut seed = 421;
    for n in 0..240 {
        let points: Vec<(i64, i128)> = (0..n % 18)
            .map(|_| {
                (
                    (next(&mut seed) % 31) as i64 - 10,
                    (next(&mut seed) % 4) as i128,
                )
            })
            .collect();
        let summary = endpoint_summary(&points, width);
        assert_eq!(summary.complete_max(), rolling_max(&points, width));
        assert_eq!(summary.complete_min(), 0);
        assert_eq!(summary.sum, 0);
        assert_eq!(summary.count, 2 * points.len() as u64);
        // Check the entire bounded time domain, including expiries and gaps.
        for t in -21..=41 {
            let sweep: i128 = points
                .iter()
                .map(|&(at, w)| i128::from(at <= t) * w - i128::from(at + width <= t) * w)
                .sum();
            assert_eq!(sweep, rolling_at(&points, width, t));
        }
    }
}

#[test]
fn expiration_ties_and_occurrence_count_are_explicit() {
    let points = [(0, 1), (10, 1)];
    assert_eq!(rolling_at(&points, 10, 10), 1);
    assert_eq!(endpoint_summary(&points, 10).complete_max(), 1);
    // Two conceptual slots of one source record are two occurrences. This tests
    // Summary.count only, not stored memberships, rank APIs or ID deduplication.
    let same_record_slots = [(4, Some(3)), (4, Some(3))];
    assert_eq!(fold(&same_record_slots).count, 2);
    assert_eq!(fold(&same_record_slots).sum, 6);
    // Derived +/- endpoints count as two leaves even though their net sum is zero.
    let derived = endpoint_summary(&[(0, 1)], 10);
    assert_eq!(derived.count, 2);
    assert_eq!(derived.sum, 0);
}
