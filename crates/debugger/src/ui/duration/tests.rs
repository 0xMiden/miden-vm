use std::string::ToString;

use super::*;

#[test]
fn durations_render_singular_plural_and_abbreviated_units() {
    for (seconds, singular, plural, abbreviation) in [
        (1, "second", "seconds", "s"),
        (60, "minute", "minutes", "m"),
        (3600, "hour", "hours", "h"),
        (86400, "day", "days", "d"),
        (604800, "week", "weeks", "w"),
        (31536000, "year", "years", "y"),
    ] {
        let duration = HumanDuration::from(Duration::from_secs(seconds));
        assert_eq!(duration.to_string(), format!("1 {singular}"));
        assert_eq!(format!("{duration:#}"), format!("1{abbreviation}"));
        let duration = HumanDuration::from(Duration::from_secs(seconds * 2));
        assert_eq!(duration.to_string(), format!("2 {plural}"));
        assert_eq!(format!("{duration:#}"), format!("2{abbreviation}"));
        assert_eq!(format!("{duration:?}"), duration.to_string());
    }
    let milliseconds = HumanDuration::from(Duration::from_millis(42));
    assert_eq!(milliseconds.to_string(), "42 milliseconds");
    assert_eq!(format!("{milliseconds:#}"), "42ms");
    let zero = HumanDuration::from(Duration::ZERO);
    assert_eq!(zero.to_string(), "0 seconds");
    assert_eq!(format!("{zero:#}"), "0s");
}

#[test]
fn duration_arithmetic_preserves_precision_and_saturates() {
    let duration = HumanDuration::from(Duration::from_millis(1500));
    assert_eq!(duration.as_secs_f64(), 1.5);
    assert_eq!(Duration::from(duration + duration), Duration::from_secs(3));
    let mut sum = duration + Duration::from_millis(500);
    sum += duration;
    sum += Duration::from_millis(500);
    assert_eq!(Duration::from(sum), Duration::from_secs(4));
    assert_eq!(
        Duration::from(HumanDuration::from(Duration::MAX).saturating_add(duration)),
        Duration::MAX
    );
    let instant = Instant::now();
    assert!(Duration::from(HumanDuration::since(instant)) <= instant.elapsed());
}
