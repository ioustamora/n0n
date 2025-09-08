#[test]
fn test_estimate_chunks() {
    assert_eq!(n0n::utils::estimate_chunks(0, 1), 1);
    assert_eq!(n0n::utils::estimate_chunks(1, 1), 1);
    assert_eq!(n0n::utils::estimate_chunks(1, 2), 1);
    assert_eq!(n0n::utils::estimate_chunks(2, 2), 1);
    assert_eq!(n0n::utils::estimate_chunks(3, 2), 2);
    assert_eq!(n0n::utils::estimate_chunks(10, 3), 4);
}
