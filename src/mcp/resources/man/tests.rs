use super::*;

/// `Style::auto()` would emit colour when stdout looks like a terminal, which
/// would put control codes in the resource body.
#[test]
fn manual_is_plain_text() {
    let page = render_manual();
    assert!(
        !page.contains('\x1b'),
        "manual contains ANSI escapes; Style::PLAIN was not used"
    );
}

/// The walk must recurse, not stop at the root's direct children. `build
/// template validate` is three levels deep, so its page only appears if
/// `append_command` descends past depth one.
#[test]
fn manual_covers_nested_subcommands() {
    let page = render_manual();

    assert!(
        page.contains("# blackship\n"),
        "root page heading missing from manual"
    );
    assert!(
        page.contains("# blackship template\n"),
        "depth-2 heading missing; the tree walk is not recursing"
    );
    assert!(
        page.contains("# blackship template validate\n"),
        "depth-3 heading missing; the tree walk stops too early"
    );
}

/// Every rendered page must carry real help text, not the fallback.
#[test]
fn every_command_renders_a_help_page() {
    let page = render_manual();
    assert!(
        !page.contains("(no help page available"),
        "at least one command in the tree produced no help page:\n{page}"
    );
}
