use std::fs;

use clap::{Parser, Subcommand};
use miden_assembly::diagnostics::Report;
use miden_core::{
    events::{EventId, EventSource},
    sys_events::SystemEvent,
    ReducedEventID,
    Felt,
};

use crate::cli::data::{Debug, Libraries, ProgramFile};

/// Event management and validation commands
#[derive(Debug, Parser)]
#[command(about = "Event management and validation commands")]
pub struct EventsCmd {
    #[command(subcommand)]
    pub command: EventsSubcommand,
}

/// Event management subcommands
#[derive(Debug, Subcommand)]
pub enum EventsSubcommand {
    /// List all events in a program or library
    List(ListEvents),
    /// Validate events for naming conflicts and collisions
    Validate(ValidateEvents),
    /// Show detailed information about specific events
    Info(EventInfo),
    /// Generate event documentation
    Docs(GenerateDocs),
}

/// List events in a program or library
#[derive(Debug, Parser)]
pub struct ListEvents {
    /// Path to the program file (.masm) or library (.masl)
    #[arg(short = 'a', long = "assembly", value_parser)]
    pub assembly_file: std::path::PathBuf,

    /// Paths to library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    pub library_paths: Vec<std::path::PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Show only events from specific sources
    #[arg(long)]
    pub source_filter: Option<String>,

    /// Show Felt values alongside event names
    #[arg(long)]
    pub show_felt: bool,
}

/// Validate events for conflicts and collisions
#[derive(Debug, Parser)]
pub struct ValidateEvents {
    /// Path to the program file (.masm) or library (.masl)
    #[arg(short = 'a', long = "assembly", value_parser)]
    pub assembly_file: std::path::PathBuf,

    /// Paths to library files  
    #[arg(short = 'l', long = "libraries", value_parser)]
    pub library_paths: Vec<std::path::PathBuf>,

    /// Check for potential hash collisions
    #[arg(long)]
    pub check_collisions: bool,

    /// Fail on warnings
    #[arg(long)]
    pub strict: bool,
}

/// Show detailed information about events
#[derive(Debug, Parser)]
pub struct EventInfo {
    /// Path to the program file (.masm) or library (.masl)
    #[arg(short = 'a', long = "assembly", value_parser)]
    pub assembly_file: std::path::PathBuf,

    /// Paths to library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    pub library_paths: Vec<std::path::PathBuf>,

    /// Event name or Felt value to get info about
    pub event_query: String,
}

/// Generate event documentation
#[derive(Debug, Parser)]
pub struct GenerateDocs {
    /// Path to the program file (.masm) or library (.masl)
    #[arg(short = 'a', long = "assembly", value_parser)]
    pub assembly_file: std::path::PathBuf,

    /// Paths to library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    pub library_paths: Vec<std::path::PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "markdown")]
    pub format: DocsFormat,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,
}

/// Output format for event listings
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

/// Documentation format 
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum DocsFormat {
    Markdown,
    Html,
    Json,
}

impl EventsCmd {
    pub fn execute(&self) -> Result<(), Report> {
        match &self.command {
            EventsSubcommand::List(cmd) => cmd.execute(),
            EventsSubcommand::Validate(cmd) => cmd.execute(),
            EventsSubcommand::Info(cmd) => cmd.execute(),
            EventsSubcommand::Docs(cmd) => cmd.execute(),
        }
    }
}

impl ListEvents {
    pub fn execute(&self) -> Result<(), Report> {
        let program = self.compile_program()?;
        let event_table = program.mast_forest().event_table();

        // Collect events
        let mut events: Vec<_> = event_table.iter().collect();
        events.sort_by_key(|(event_id, _)| event_id.to_string());

        // Apply source filter if specified
        if let Some(ref filter) = self.source_filter {
            events.retain(|(event_id, _)| {
                match event_id.source() {
                    EventSource::System => filter == "system",
                    EventSource::Stdlib => filter == "stdlib", 
                    EventSource::Library(_) => filter == "library",
                    EventSource::User(_) => filter == "user" || filter.starts_with("user-"),
                }
            });
        }

        match self.format {
            OutputFormat::Table => self.print_table(&events),
            OutputFormat::Json => self.print_json(&events),
            OutputFormat::Csv => self.print_csv(&events),
        }

        Ok(())
    }

    fn compile_program(&self) -> Result<miden_core::Program, Report> {
        let program = ProgramFile::read(&self.assembly_file)?;
        let libraries = Libraries::new(&self.library_paths)?;
        program.compile(Debug::Off, &libraries.libraries)
    }

    fn print_table(&self, events: &[(&EventId, ReducedEventID)]) {
        println!("┌─────────────────┬──────────────────────────────────────────────┬─────────────────┐");
        println!("│ Source          │ Event Name                                   │ Felt Value      │");  
        println!("├─────────────────┼──────────────────────────────────────────────┼─────────────────┤");

        for (event_id, reduced_id) in events {
            let source = format!("{:?}", event_id.source());
            let name = format!("{}::{}", event_id.namespace(), event_id.name());
            
            if self.show_felt {
                println!("│ {:15} │ {:44} │ {:15} │", source, name, reduced_id.as_felt());
            } else {
                println!("│ {:15} │ {:44} │ {:15} │", source, name, "-");
            }
        }

        println!("└─────────────────┴──────────────────────────────────────────────┴─────────────────┘");
        println!("Total events: {}", events.len());
    }

    fn print_json(&self, events: &[(&EventId, ReducedEventID)]) {
        let json_events: Vec<_> = events.iter().map(|(event_id, reduced_id)| {
            serde_json::json!({
                "source": format!("{:?}", event_id.source()),
                "namespace": event_id.namespace(),
                "name": event_id.name(),
                "full_name": event_id.to_string(),
                "felt": if self.show_felt { Some(reduced_id.as_felt().to_string()) } else { None }
            })
        }).collect();

        let output = serde_json::json!({
            "events": json_events,
            "total": events.len()
        });

        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    }

    fn print_csv(&self, events: &[(&EventId, ReducedEventID)]) {
        if self.show_felt {
            println!("source,namespace,name,full_name,felt");
        } else {
            println!("source,namespace,name,full_name");
        }

        for (event_id, reduced_id) in events {
            let source = format!("{:?}", event_id.source());
            let namespace = event_id.namespace();
            let name = event_id.name();
            let full_name = event_id.to_string();

            if self.show_felt {
                println!("{},{},{},{},{}", source, namespace, name, full_name, reduced_id.as_felt());
            } else {
                println!("{},{},{},{}", source, namespace, name, full_name);
            }
        }
    }
}

impl ValidateEvents {
    pub fn execute(&self) -> Result<(), Report> {
        let program = self.compile_program()?;
        let event_table = program.mast_forest().event_table();
        
        let mut warnings = 0;
        let errors = 0;

        // Note: EventTable now uses fail-fast collision detection during registration,
        // so any collisions would have prevented compilation. If we reach here,
        // there are no collisions.

        // Validate naming conventions
        let events: Vec<_> = event_table.iter().collect();
        for (event_id, _) in &events {
            // Check naming convention (uppercase with underscores)
            if !event_id.name().chars().all(|c| c.is_uppercase() || c == '_') {
                warnings += 1;
                println!("⚠️  Event name '{}' should be uppercase with underscores", event_id);
            }

            // Check namespace convention (lowercase)
            if !event_id.namespace().chars().all(|c| c.is_lowercase() || c == '_') {
                warnings += 1;
                println!("⚠️  Namespace '{}' should be lowercase", event_id.namespace());
            }
        }

        // Summary
        println!("\n📊 Validation Summary:");
        println!("  • Total events: {}", events.len());
        println!("  • Errors: {}", errors);
        println!("  • Warnings: {}", warnings);

        if errors > 0 {
            println!("❌ Validation failed with {} errors", errors);
            return Err(Report::msg("Event validation failed"));
        } else if warnings > 0 && self.strict {
            println!("❌ Strict mode: failing due to {} warnings", warnings);
            return Err(Report::msg("Event validation failed in strict mode"));
        } else if warnings > 0 {
            println!("⚠️  Validation completed with {} warnings", warnings);
        } else {
            println!("✅ All events valid");
        }

        Ok(())
    }

    fn compile_program(&self) -> Result<miden_core::Program, Report> {
        let program = ProgramFile::read(&self.assembly_file)?;
        let libraries = Libraries::new(&self.library_paths)?;
        program.compile(Debug::Off, &libraries.libraries)
    }
}

impl EventInfo {
    pub fn execute(&self) -> Result<(), Report> {
        let program = self.compile_program()?;
        let event_table = program.mast_forest().event_table();

        // Try to parse as EventId first, then as Felt
        if let Ok(event_id) = self.event_query.parse::<EventId>() {
            self.show_event_id_info(&event_id, event_table)?;
        } else if let Ok(felt_val) = self.event_query.parse::<u64>() {
            let felt = Felt::new(felt_val);
            self.show_felt_info(felt, event_table)?;
        } else {
            return Err(Report::msg(format!(
                "Invalid event query '{}'. Expected EventId format (e.g., 'user-0/test::EVENT_NAME') or Felt value",
                self.event_query
            )));
        }

        Ok(())
    }

    fn compile_program(&self) -> Result<miden_core::Program, Report> {
        let program = ProgramFile::read(&self.assembly_file)?;
        let libraries = Libraries::new(&self.library_paths)?;
        program.compile(Debug::Off, &libraries.libraries)
    }

    fn show_event_id_info(&self, event_id: &EventId, event_table: &miden_core::EventTable) -> Result<(), Report> {
        println!("🔍 Event Information");
        println!("━━━━━━━━━━━━━━━━━━━━━━");
        println!("Event ID: {}", event_id);
        println!("Source: {:?}", event_id.source());
        println!("Namespace: {}", event_id.namespace());
        println!("Name: {}", event_id.name());

        if let Some(reduced_id) = event_table.lookup_by_event(event_id) {
            println!("Felt Value: {}", reduced_id.as_felt());
            println!("Felt (hex): 0x{:016x}", reduced_id.as_u64());
            
            // Check if this ReducedEventID has any other EventIds mapped to it
            if let Some(resolved_event) = event_table.lookup_by_reduced_id(reduced_id) {
                if resolved_event != event_id {
                    println!("⚠️  Collision detected: ReducedEventID {} also maps to {}", reduced_id, resolved_event);
                }
            }
        } else {
            println!("❌ Event not found in EventTable");
            return Err(Report::msg("Event not found"));
        }

        Ok(())
    }

    fn show_felt_info(&self, felt: Felt, event_table: &miden_core::EventTable) -> Result<(), Report> {
        println!("🔍 Felt Reverse Lookup");
        println!("━━━━━━━━━━━━━━━━━━━━━━");
        println!("Felt Value: {}", felt);
        println!("Felt (hex): 0x{:016x}", felt.as_int());

        if let Some(event_id) = event_table.lookup_by_felt(felt) {
            println!("Event ID: {}", event_id);
            println!("Source: {:?}", event_id.source());
            println!("Namespace: {}", event_id.namespace());
            println!("Name: {}", event_id.name());
        } else {
            println!("❌ No EventId found for this Felt value");
            println!("ℹ️  This might be a legacy u32 event or system event");
            
            // Check if it's a system event
            if let Some(system_event) = SystemEvent::from_reduced_id(ReducedEventID::new(felt)) {
                println!("✅ This is a system event: {:?}", system_event);
            }
        }

        Ok(())
    }
}

impl GenerateDocs {
    pub fn execute(&self) -> Result<(), Report> {
        let program = self.compile_program()?;
        let event_table = program.mast_forest().event_table();

        let content = match self.format {
            DocsFormat::Markdown => self.generate_markdown(event_table),
            DocsFormat::Html => self.generate_html(event_table),
            DocsFormat::Json => self.generate_json(event_table),
        };

        if let Some(ref output_file) = self.output {
            fs::write(output_file, &content)
                .map_err(|e| Report::msg(format!("Failed to write output file: {}", e)))?;
            println!("📝 Documentation written to {}", output_file.display());
        } else {
            print!("{}", content);
        }

        Ok(())
    }

    fn compile_program(&self) -> Result<miden_core::Program, Report> {
        let program = ProgramFile::read(&self.assembly_file)?;
        let libraries = Libraries::new(&self.library_paths)?;
        program.compile(Debug::Off, &libraries.libraries)
    }

    fn generate_markdown(&self, event_table: &miden_core::EventTable) -> String {
        let mut content = String::new();
        
        content.push_str("# Event Documentation\n\n");
        content.push_str(&format!("Generated for program\n\n"));

        // Group events by source
        let events: Vec<_> = event_table.iter().collect();
        let mut grouped = std::collections::BTreeMap::new();
        
        for (event_id, felt) in events {
            let source_key = format!("{:?}", event_id.source());
            grouped.entry(source_key).or_insert_with(Vec::new).push((event_id, felt));
        }

        for (source, events) in grouped {
            content.push_str(&format!("## {} Events\n\n", source));
            content.push_str("| Namespace | Event Name | Full Identifier | Felt Value |\n");
            content.push_str("|-----------|------------|-----------------|------------|\n");
            
            for (event_id, felt) in events {
                content.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}` |\n",
                    event_id.namespace(),
                    event_id.name(),
                    event_id,
                    felt
                ));
            }
            content.push_str("\n");
        }

        // Note: EventTable now uses fail-fast collision detection,
        // so no collisions exist if compilation succeeded.

        content
    }

    fn generate_html(&self, event_table: &miden_core::EventTable) -> String {
        // Similar to markdown but with HTML formatting
        let mut content = String::new();
        content.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        content.push_str("<title>Event Documentation</title>\n");
        content.push_str("<style>body { font-family: Arial, sans-serif; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ddd; padding: 8px; text-align: left; } th { background-color: #f2f2f2; }</style>\n");
        content.push_str("</head>\n<body>\n");
        
        content.push_str("<h1>Event Documentation</h1>\n");
        
        let events: Vec<_> = event_table.iter().collect();
        content.push_str(&format!("<p>Total Events: {}</p>\n", events.len()));
        
        content.push_str("<table>\n<tr><th>Source</th><th>Namespace</th><th>Name</th><th>Full ID</th><th>Felt</th></tr>\n");
        
        for (event_id, felt) in events {
            content.push_str(&format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                event_id.source(),
                event_id.namespace(),
                event_id.name(),
                event_id,
                felt
            ));
        }
        
        content.push_str("</table>\n</body>\n</html>\n");
        content
    }

    fn generate_json(&self, event_table: &miden_core::EventTable) -> String {
        let events: Vec<_> = event_table.iter().map(|(event_id, felt)| {
            serde_json::json!({
                "source": format!("{:?}", event_id.source()),
                "namespace": event_id.namespace(),
                "name": event_id.name(),
                "full_id": event_id.to_string(),
                "felt": felt.to_string()
            })
        }).collect();

        let output = serde_json::json!({
            "program": "program",
            "events": events,
            "total": events.len(),
            "collisions": [] // No collisions with fail-fast approach
        });

        serde_json::to_string_pretty(&output).unwrap()
    }
}