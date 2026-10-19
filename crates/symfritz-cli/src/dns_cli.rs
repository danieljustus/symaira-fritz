//! Explicit opt-in DNS diagnosis; ordinary status/diagnose paths are unchanged.
use super::*;
use symfritz_cli::cli::DnsArgs;
use symfritz_tr064::dns::DnsDiagnosticOptions;

fn cancelled() -> bool {
    CANCEL_REQUESTED.load(Ordering::SeqCst)
}

pub(super) fn execute(args: DnsArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let mut options = DnsDiagnosticOptions::new(args.hostname);
    options.expected_host_ip = args.expected_ip;
    options.router_dns_ip = args.router_dns_ip;
    let (mut config, password) = load_connection()?;
    if !matches!(
        origin_url(&config.box_config, true)?.host(),
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))
    ) {
        return Err(HandlerError::config(
            "dns requires a literal router connection IP; set SYMFRITZ_HOST to its independently verified local IP (--router-dns-ip only selects the DNS comparison endpoint)",
        ));
    }
    // Local copy only: never persist configuration or retry via another origin.
    config.box_config.timeout_seconds = config.box_config.timeout_seconds.clamp(1, 2);
    config.box_config.allow_http_fallback = false;
    let mut client = make_tr064(&config.box_config, &password)?;
    options.system = dns_evidence::collect(&cancelled);
    let report = client
        .diagnose_dns(&options, &cancelled)
        .map_err(HandlerError::operation)?;
    if report.cancelled {
        return Err(HandlerError::cancelled());
    }
    let format = if format == OutputFormat::Text {
        OutputFormat::Json
    } else {
        format
    };
    output::write(&mut io::stdout(), &report, format)
        .map_err(|error| HandlerError::operation(error.to_string()))
}
