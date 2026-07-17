use std::hint::black_box;

use packrat_tui::analysis::profile_workload;

fn main() {
    let packets = packet_count(std::env::args().skip(1)).unwrap_or_else(|error| {
        eprintln!("packrat-profile: {error}");
        std::process::exit(2);
    });
    let summary = black_box(profile_workload::run(packets));
    let elapsed = summary.elapsed.as_secs_f64();
    let rate = if elapsed > 0.0 {
        summary.packets as f64 / elapsed
    } else {
        0.0
    };
    println!(
        "packets={} retained={} alerts={} elapsed_ms={:.3} packets_per_second={:.0}",
        summary.packets,
        summary.retained_packets,
        summary.alerts,
        elapsed * 1_000.0,
        rate,
    );
}

fn packet_count(mut args: impl Iterator<Item = String>) -> Result<usize, String> {
    let mut packets = 50_000;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--packets" => {
                let value = args.next().ok_or("--packets requires a value")?;
                packets = value.parse().map_err(|_| format!("invalid packet count: {value}"))?;
                if packets == 0 {
                    return Err("packet count must be greater than zero".into());
                }
            }
            "--help" | "-h" => {
                println!("Usage: packrat-profile [--packets COUNT]");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_count_is_validated() {
        assert_eq!(packet_count(["--packets", "42"].map(str::to_string).into_iter()), Ok(42));
        assert!(packet_count(["--packets", "0"].map(str::to_string).into_iter()).is_err());
        assert!(packet_count(["--unknown"].map(str::to_string).into_iter()).is_err());
    }
}
