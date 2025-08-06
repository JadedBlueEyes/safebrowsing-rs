use std::fs;

use snapbox::cmd::cargo_bin;
use snapbox::cmd::Command;
use snapbox::file;
use snapbox::Assert;

#[test]
fn test_snap_fixture() {
    let mut subst = snapbox::Redactions::new();
    subst.insert("[TIME]", regex::Regex::new(r"(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))|(\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z))").unwrap()).unwrap();
    subst
        .insert(
            "[DURATION]",
            regex::Regex::new(r#"(?:\s+)[0-9]+(\.[0-9]+)?(m|s|ms|µs|ns)(?:\s+)"#).unwrap(),
        )
        .unwrap();
    // subst.insert("[DATABASE]", regex::Regex::new(r#""([\\/][^\\/]*)+[\\/]database\.redb"#).unwrap()).unwrap();

    let db_path = safebrowsing::database::RedbDatabase::default_path().unwrap();
    let _ = subst.insert("[DATABASE]", &db_path);

    // Reset the database
    let _ = fs::remove_file(&db_path);

    let test_args = vec![
        "--",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/",
        "http://example.com",
        "https://console.cloud.google.com",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/UNWANTED_SOFTWARE/URL/",
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/",
        "http://www.google.com/",
    ];

    let _assert = Command::new(cargo_bin("sblookup"))
        // .timeout(std::time::Duration::from_secs(180))
        .args(&test_args)
        .env("RUST_LOG", "info,sblookup=debug")
        .with_assert(
            Assert::new()
                .redact_with(subst.clone())
                .action_env("SNAPBOX_ACTION"),
        )
        .assert()
        .success()
        .stdout_eq(file![_]);
    let _assert = Command::new(cargo_bin("sblookup"))
        // .timeout(std::time::Duration::from_secs(60))
        .args(&test_args)
        .with_assert(
            Assert::new()
                .redact_with(subst)
                .action_env("SNAPBOX_ACTION"),
        )
        .assert()
        .success()
        .stdout_eq(file![_]);
}
