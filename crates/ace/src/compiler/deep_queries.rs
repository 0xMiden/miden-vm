//! Authenticated DEEP query rows, specialized by each relation's generated parameters.

use std::string::String;

/// Renders authenticated row ingestion and Horner reduction in commitment-group order.
///
/// `parameters_module` supplies each group's positive count of eight-felt blocks and LMCS
/// initializer, plus the preprocessed tree depth and index mask. The relation's generator must
/// derive these constants from its compiled geometry and trusted setup. The generic verifier
/// initializes the query records and DEEP scratch before calling the generated hook.
pub fn render_masm_deep_queries(generated_by: &str, parameters_module: &str) -> String {
    let mut row_readers = String::new();
    for group in ["preprocessed", "main", "aux", "quotient"] {
        row_readers.push_str(
            &include_str!("templates/deep_query_row.masm")
                .replace("{{group}}", group)
                .replace("{{GROUP}}", &group.to_ascii_uppercase()),
        );
        row_readers.push('\n');
    }

    include_str!("templates/deep_queries.masm")
        .replace("{{generated_by}}", generated_by)
        .replace("{{parameters_module}}", parameters_module)
        .replace("{{row_readers}}", row_readers.trim_end())
}
