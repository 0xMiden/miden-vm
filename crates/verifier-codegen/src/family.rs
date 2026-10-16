//! One proof-header dispatch into a statically specialized relation subtree.
use std::fmt::Write;

/// Specialize the existing isolated call body while retaining the public request and call ABI.
/// A singleton family emits its original source verbatim and consumes no selector.
pub(crate) fn bind_dispatch(
    source: &str,
    variants: &[(u32, String)],
    full_selector: u32,
) -> Result<String, String> {
    if variants.is_empty() || !variants.iter().any(|(selector, _)| *selector == full_selector) {
        return Err("PVM family must contain its full relation".into());
    }
    let mut selectors = variants.iter().map(|(selector, _)| *selector).collect::<Vec<_>>();
    selectors.sort_unstable();
    if selectors.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate PVM relation selector".into());
    }
    if variants.len() == 1 {
        return Ok(source.to_string());
    }
    let marker =
        "proc verify_proof_inner(deferred_root: types::Digest) -> types::StackSecurityDescriptor\n";
    let (prefix, body) = source.split_once(marker).ok_or("missing PVM isolated verifier body")?;
    let security = "    exec.utils::load_security_params\n";
    let (_, relation_body) =
        body.split_once(security).ok_or("missing PVM security parameter load")?;
    let mut out = prefix.to_string();
    out.push_str(marker);
    // The recursive advice header precedes the common security parameters. Keep the selector
    // on the isolated operand stack while the stack-neutral loader consumes those parameters.
    out.push_str("    adv_push\n");
    out.push_str(security);
    writeln!(out, "    dup eq.{full_selector}\n    if.true\n        drop\n        exec.verify_relation\n    else").unwrap();
    let mut reduced = variants
        .iter()
        .filter(|(selector, _)| *selector != full_selector)
        .cloned()
        .collect::<Vec<_>>();
    reduced.sort_by_key(|(selector, _)| *selector);
    render_cases(&mut out, &reduced);
    out.push_str("    end\n");
    out.push_str("end\n\n");
    out.push_str("pub proc verify_relation(deferred_root: types::Digest) -> types::StackSecurityDescriptor\n");
    out.push_str(relation_body);
    // Subtrees live below the public PVM module, keeping the full relation's public hook paths.
    out = out.replacen("pub mod public_inputs\n", "pub mod public_inputs\npub mod relations\n", 1);
    for (_, module) in variants.iter().filter(|(selector, _)| *selector != full_selector) {
        out = out.replacen(
            "use miden::core::stark::utils\n",
            &format!(
                "use miden::core::sys::pvm::relations::{module}\nuse miden::core::stark::utils\n"
            ),
            1,
        );
    }
    Ok(out)
}

fn render_cases(out: &mut String, variants: &[(u32, String)]) {
    if variants.len() == 1 {
        let (selector, module) = &variants[0];
        writeln!(out, "        push.{selector} assert_eq.err=\"unsupported PVM relation selector\"\n        exec.{module}::verify_relation").unwrap();
    } else {
        let middle = variants.len() / 2;
        writeln!(out, "        dup u32lt.{}\n        if.true", variants[middle].0).unwrap();
        render_cases(out, &variants[..middle]);
        out.push_str("        else\n");
        render_cases(out, &variants[middle..]);
        out.push_str("        end\n");
    }
}

/// A selected subtree receives the common security parameters from the family dispatcher.
pub(crate) fn expose_relation_entry(source: &str) -> Result<String, String> {
    let (context, _) = source
        .split_once("#! Requests and stages a PVM proof package")
        .ok_or("missing PVM public wrapper boundary")?;
    let marker =
        "proc verify_proof_inner(deferred_root: types::Digest) -> types::StackSecurityDescriptor\n";
    let (_, body) = source.split_once(marker).ok_or("missing PVM isolated verifier body")?;
    let security = "    exec.utils::load_security_params\n";
    let (_, relation_body) =
        body.split_once(security).ok_or("missing PVM security parameter load")?;
    Ok(format!(
        "{}pub proc verify_relation(deferred_root: types::Digest) -> types::StackSecurityDescriptor\n{relation_body}",
        context.replace("use miden::core::stark::utils\n", "")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_does_not_consume_a_header_and_family_dispatches_once() {
        let source = include_str!("../templates/pvm/mod.masm");
        assert_eq!(bind_dispatch(source, &[(0, "pvm".into())], 0).unwrap(), source);
        let result = bind_dispatch(source, &[(0, "pvm_0".into()), (1, "pvm".into())], 1).unwrap();
        let inner = result
            .split_once("proc verify_proof_inner(")
            .unwrap()
            .1
            .split_once("\nend")
            .unwrap()
            .0;
        assert_eq!(inner.matches("adv_push").count(), 1);
        assert_eq!(inner.matches("load_security_params").count(), 1);
        assert!(
            inner.find("adv_push").unwrap() < inner.find("load_security_params").unwrap(),
            "the selector is the first recursive advice field, before four security parameters"
        );
        assert!(
            inner.find("load_security_params").unwrap() < inner.find("dup eq.1").unwrap(),
            "dispatch follows the common stack-neutral security parameter load"
        );
        assert!(inner.contains("exec.pvm_0::verify_relation"));
        assert!(inner.contains("exec.verify_relation"));
        assert!(inner.contains("unsupported PVM relation selector"));
    }
}
