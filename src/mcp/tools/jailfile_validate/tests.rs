use super::*;

fn report(content: &str, format: JailfileFormat) -> Value {
    diagnostic_report(Path::new("/tmp/Jailfile"), content, format)
}

#[test]
fn reports_one_diagnostic_per_bad_line_with_positions() {
    let content = "FROM 15.1-RELEASE\nBOGUS something\nRUN echo ok\n  ALSOBAD x\n# comment\n";
    let result = report(content, JailfileFormat::Line);

    assert_eq!(result["valid"], false);
    assert_eq!(result["diagnostic_count"], 2);

    let diagnostics = result["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0]["line"], 2);
    assert_eq!(diagnostics[0]["column"], 1);
    assert!(
        diagnostics[0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("BOGUS")),
        "first diagnostic should name the offending line: {:?}",
        diagnostics[0]["message"]
    );
    assert_eq!(diagnostics[1]["line"], 4);
    assert_eq!(diagnostics[1]["column"], 3);
}

#[test]
fn clean_line_format_has_no_diagnostics() {
    let result = report("FROM 15.1-RELEASE\nRUN echo ok\n", JailfileFormat::Line);

    assert_eq!(result["valid"], true);
    assert_eq!(result["diagnostic_count"], 0);
    assert_eq!(result["diagnostics"].as_array().map(Vec::len), Some(0));
}

/// The `auto` sniffer is textual, so a line-format body merely mentioning
/// `[build]` is routed to the TOML parser. The report must say which parser
/// actually ran, and only warn about it when `auto` was asked for.
#[test]
fn auto_reports_the_format_it_actually_chose() {
    let content = "FROM 15.1-RELEASE\nRUN echo '[build]'\n";

    let auto = report(content, JailfileFormat::Auto);
    assert_eq!(auto["requested_format"], "auto");
    assert_eq!(auto["resolved_format"], "toml");
    assert_eq!(auto["valid"], false);
    assert!(auto["format_note"].is_string());

    let forced = report(content, JailfileFormat::Line);
    assert_eq!(forced["requested_format"], "line");
    assert_eq!(forced["resolved_format"], "line");
    assert_eq!(forced["valid"], true);
    assert!(forced["format_note"].is_null());
}
