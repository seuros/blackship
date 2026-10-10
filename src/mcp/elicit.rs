//! The one write gate every creating tool goes through.
//!
//! Nothing in this server touches the filesystem on its own authority: the
//! model proposes a file, the operator accepts an elicitation, and only then
//! does a byte land on disk. Every path that is not a clear accept-with-confirm
//! writes nothing, including a client that cannot do elicitation at all.
//!
//! The decision is split from the effect on purpose. [`verdict`] turns a
//! protocol answer into a yes or a no, [`apply`] is the only code here that
//! writes, and both are reachable from tests without a live client.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mcp_host::prelude::*;
use mcp_host::protocol::elicitation::ElicitationSchema;
use mcp_host::protocol::types::{CreateElicitationResult, ElicitationAction};
use serde_json::{Value, json};

/// How long the operator has to answer before the proposal is abandoned.
///
/// A client that never replies would otherwise hold the tool call, and with it
/// a server task, forever. This is handed to the request layer as the deadline
/// for this one call, replacing its much shorter default, so it is the single
/// authority on how long a human gets to read the form.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// Refusal used when the client has no way to ask its operator anything.
const NO_TRANSPORT: &str = "This client has no bidirectional transport, so the operator cannot be \
                            asked to approve the write. Nothing was written. Use a client that \
                            declares the `elicitation` capability, or save the rendered content \
                            yourself.";

/// What an elicitation answer authorizes.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::mcp) enum Verdict {
    /// Write the file. `replacing` records that an existing file is clobbered.
    Write { replacing: bool },
    /// Leave the filesystem alone, and tell the model why.
    Refuse(String),
}

/// Ask the operator to approve writing `content` to `path`, then obey them.
///
/// Returns the JSON body the calling tool reports, which always states whether
/// a file was written and, when it was not, why not.
pub(in crate::mcp) async fn write_with_approval(
    ctx: &Ctx<'_>,
    path: &Path,
    description: &str,
    content: &str,
) -> std::result::Result<Value, ToolError> {
    let target = absolute(path);

    if let Some(parent) = missing_parent(&target) {
        return Ok(refused(&target, &no_parent(&parent)));
    }

    let exists = target.exists();

    let verdict = match ctx.client_requester() {
        Some(requester) => ask(requester, &target, description, exists).await?,
        None => Verdict::Refuse(NO_TRANSPORT.to_string()),
    };

    apply(&target, description, content, verdict)
}

/// Put the proposal to the operator and reduce their answer to a verdict.
///
/// Both ends of the round-trip are logged to the server's log file, because a
/// failed approval is otherwise indistinguishable from a slow human: the
/// outcome discriminator separates a client that cannot elicit at all from one
/// whose operator ran out of time, and the elapsed time says which it was.
/// Only the path and metadata are recorded; the content being proposed may
/// carry secrets and never reaches the log.
async fn ask(
    requester: &ClientRequester,
    target: &Path,
    description: &str,
    exists: bool,
) -> std::result::Result<Verdict, ToolError> {
    let schema = schema(description, exists)?;
    let schema_value = serde_json::to_value(&schema)
        .map_err(|e| ToolError::Execution(format!("Failed to encode elicitation schema: {e}")))?;

    tracing::info!(
        path = %target.display(),
        target_exists = exists,
        timeout_secs = ANSWER_TIMEOUT.as_secs(),
        "asking the operator to approve a write"
    );

    let started = Instant::now();

    let answer = requester
        .request_elicitation(
            message(target, description, exists),
            schema_value,
            Some(ANSWER_TIMEOUT),
        )
        .await;

    let elapsed = started.elapsed();

    let (outcome, verdict) = match answer {
        Ok(result) => match verdict(&result, exists) {
            write @ Verdict::Write { .. } => ("accepted-write", write),
            refusal => ("refused-by-operator", refusal),
        },
        Err(MultiplexerError::Timeout(_)) => (
            "timeout",
            Verdict::Refuse(format!(
                "The operator did not answer within {}s. Nothing was written.",
                ANSWER_TIMEOUT.as_secs()
            )),
        ),
        Err(MultiplexerError::UnsupportedCapability(_)) => (
            "unsupported-capability",
            Verdict::Refuse(NO_TRANSPORT.to_string()),
        ),
        Err(e) => (
            "other-error",
            Verdict::Refuse(format!(
                "The approval request failed ({e}). Nothing was written."
            )),
        ),
    };

    tracing::info!(
        path = %target.display(),
        outcome,
        elapsed_secs = elapsed.as_secs_f64(),
        "operator approval round-trip settled"
    );

    Ok(verdict)
}

/// The form the operator fills in.
///
/// `overwrite` is only offered when the target really exists, so an accept can
/// never grant a clobber that was not on screen.
fn schema(description: &str, exists: bool) -> std::result::Result<ElicitationSchema, ToolError> {
    let mut builder = ElicitationSchema::builder()
        .required_bool("confirm")
        .title("blackship: approve file write")
        .description(format!(
            "Set `confirm` to write {description}. Leaving it unset writes nothing."
        ));

    if exists {
        builder = builder.optional_bool("overwrite", false);
    }

    builder
        .build()
        .map_err(|e| ToolError::Execution(format!("Schema error: {e}")))
}

/// The text the operator reads, naming the absolute target.
fn message(target: &Path, description: &str, exists: bool) -> String {
    let mut message = format!(
        "blackship wants to write {description} to {}.",
        target.display()
    );

    if exists {
        message.push_str(
            " A FILE ALREADY EXISTS AT THAT PATH and will be replaced. Set `overwrite` as well as \
             `confirm` to allow that; `confirm` alone leaves the existing file untouched.",
        );
    } else {
        message.push_str(" No file exists there yet.");
    }

    message.push_str(" Set `confirm` to approve. Nothing is written unless you do.");
    message
}

/// Reduce an elicitation result to a verdict.
///
/// `exists` is the state of the target observed before the operator was asked,
/// so a file that appeared in the meantime is still protected by `apply`.
fn verdict(result: &CreateElicitationResult, exists: bool) -> Verdict {
    match result.action {
        ElicitationAction::Decline => Verdict::Refuse(
            "The operator declined the write. Nothing was written; do not retry the same \
             proposal."
                .to_string(),
        ),
        ElicitationAction::Cancel => Verdict::Refuse(
            "The operator cancelled the approval request. Nothing was written.".to_string(),
        ),
        ElicitationAction::Accept if !flag(result.content.as_ref(), "confirm") => Verdict::Refuse(
            "The operator returned the form without setting `confirm`, which is not an approval. \
             Nothing was written."
                .to_string(),
        ),
        ElicitationAction::Accept if exists && !flag(result.content.as_ref(), "overwrite") => {
            Verdict::Refuse(
                "A file already exists at that path and the operator did not grant `overwrite`. \
                 Nothing was written."
                    .to_string(),
            )
        }
        ElicitationAction::Accept => Verdict::Write { replacing: exists },
    }
}

/// Whether `key` is present in the form response and set to `true`.
fn flag(content: Option<&Value>, key: &str) -> bool {
    content
        .and_then(|content| content.get(key))
        .and_then(Value::as_bool)
        == Some(true)
}

/// Carry out a verdict. The only function in this module that writes.
///
/// An existing file is re-checked here, because `Write { replacing: false }`
/// was decided against a filesystem that has since been free to change.
fn apply(
    target: &Path,
    description: &str,
    content: &str,
    verdict: Verdict,
) -> std::result::Result<Value, ToolError> {
    let replacing = match verdict {
        Verdict::Refuse(reason) => return Ok(refused(target, &reason)),
        Verdict::Write { replacing } => replacing,
    };

    if !replacing && target.exists() {
        return Ok(refused(
            target,
            "A file appeared at that path while the operator was being asked, and the approval \
             did not cover replacing it. Nothing was written.",
        ));
    }

    crate::atomic::write_atomic(target, content, description)
        .map_err(|e| ToolError::Execution(e.to_string()))?;

    Ok(json!({
        "path": target.display().to_string(),
        "written": true,
        "replaced": replacing,
        "bytes": content.len(),
    }))
}

/// The body reported when nothing was written.
fn refused(target: &Path, reason: &str) -> Value {
    json!({
        "path": target.display().to_string(),
        "written": false,
        "reason": reason,
    })
}

/// Refusal text for a target whose directory cannot hold it.
///
/// Names the absolute directory and states the way out, because this tool
/// writes exactly one file and will not create directories on the operator's
/// behalf. An absent directory is distinguished from a path already occupied by
/// something that is not a directory: the first wants a `mkdir`, the second
/// wants a different path, and telling a model the file it can see "does not
/// exist" would send it down the wrong one.
fn no_parent(parent: &Path) -> String {
    let shown = parent.display();

    if parent.exists() {
        format!(
            "{shown} already exists and is not a directory, so nothing can be written inside it. \
             Nothing was written, and the operator was not asked to approve anything. Choose a \
             path inside a directory that already exists."
        )
    } else {
        format!(
            "The directory {shown} does not exist, so nothing can be written there. Nothing was \
             written, and the operator was not asked to approve anything. Create that directory \
             first, or choose a path inside a directory that already exists."
        )
    }
}

/// Make `path` absolute without consulting the filesystem.
///
/// The operator is shown this, so a relative path from the model must not be
/// ambiguous. Failure to resolve leaves the path as given rather than aborting.
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The directory `target` would be written into, if it is not usable as one.
///
/// [`crate::atomic::write_atomic`] stages its temp file beside the target, so a
/// parent that is absent, or that is a file rather than a directory, dooms the
/// write before it starts. Returning it here lets the caller refuse up front
/// instead of spending the operator's approval on a write that cannot land.
/// `None` means the parent is a directory that exists, or that the path has no
/// parent component to check.
fn missing_parent(target: &Path) -> Option<PathBuf> {
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())?;

    if parent.is_dir() {
        None
    } else {
        Some(parent.to_path_buf())
    }
}

#[cfg(test)]
#[path = "elicit/tests.rs"]
mod tests;
