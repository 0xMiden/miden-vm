use alloc::string::ToString;

use super::*;

#[test]
fn validates_report_directory_and_instrument_dependencies() {
    assert!(
        ProfilerConfig::try_from(ProfilerCliArgs::default())
            .unwrap()
            .instruments
            .is_empty()
    );
    let directory = tempfile::tempdir().unwrap();
    for args in [
        ProfilerCliArgs {
            reports_dir: Some(directory.path().into()),
            instruments: vec![],
        },
        ProfilerCliArgs {
            reports_dir: None,
            instruments: vec!["unknown".into()],
        },
        ProfilerCliArgs {
            reports_dir: Some(directory.path().into()),
            instruments: vec!["unknown".into()],
        },
    ] {
        assert!(ProfilerConfig::try_from(args).is_err());
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    let error = ProfilerConfig::try_from(ProfilerCliArgs {
        reports_dir: Some(file.path().into()),
        instruments: vec!["unknown".into()],
    })
    .unwrap_err();
    assert!(error.to_string().contains("not a directory"));
}

#[test]
fn builds_known_instruments_once_in_sorted_order() {
    use crate::profiling::InstrumentRegistration;

    let global = crate::profiling::OpHistogramGlobal::NAME;
    let procedure = crate::profiling::OpHistogramProc::NAME;
    let directory = tempfile::tempdir().unwrap();
    let config = ProfilerConfig::try_from(ProfilerCliArgs {
        reports_dir: Some(directory.path().join("reports")),
        instruments: vec![procedure.into(), global.into(), procedure.into()],
    })
    .unwrap();
    let names: Vec<_> = config.instruments.iter().map(|instrument| instrument.name()).collect();
    let mut expected = vec![global, procedure];
    expected.sort();
    assert_eq!(names, expected);
    assert!(format!("{config:?}").contains(global));
    assert_eq!(config.reports_dir.as_deref(), Some(directory.path().join("reports").as_path()));
}
