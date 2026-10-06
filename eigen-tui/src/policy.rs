//! Checks which routes to a relay are allowed. Each refusal states the reason.
use eigen_transport::device::{self, Kind};

use crate::tor::RelayAddr;

/// Check relays against the chosen transports. Ok carries warnings to show.
pub fn admit(relays: &[RelayAddr], vpn: Option<&str>, risk: bool) -> Result<Vec<String>, String> {
    let mut warn = Vec::new();
    if let Some(dev) = vpn {
        match device::inspect(dev) {
            Ok(Kind::WireGuard) => {}
            Ok(Kind::Tunnel) => warn.push(format!("{dev} is a tunnel interface, but it could not be confirmed as WireGuard. Direct connections are bound to it.")),
            Ok(Kind::Other) => {
                if !risk {
                    return Err(format!("{dev} does not appear to be a VPN or WireGuard interface, so it was refused. To use it, add --i-accept-the-risk."));
                }
                warn.push(format!("{dev} does not appear to be a tunnel interface. Direct connections are bound to it because --i-accept-the-risk is set."));
            }
            Err(_) => return Err(format!("The interface {dev} does not exist. Start the tunnel first.")),
        }
        if !relays.iter().any(|r| r.is_clear()) {
            warn.push("--vpn applies to direct relays only. Tor and I2P relays use their own routes. To send Tor or I2P traffic through the VPN, run the Tor or I2P daemon over the VPN.".into());
        }
    }
    for r in relays.iter().filter(|r| r.is_clear()) {
        let name = format!("{}:{}", r.host, r.port);
        if vpn.is_some()
            && r.host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_err()
        {
            return Err(format!("Relay {name}: use an IP address with --vpn. Resolving a host name would send a DNS request outside the tunnel."));
        }
        let problem = match (vpn.is_some(), r.key.is_some()) {
            (true, true) => None,
            (true, false) => Some("The relay key (#KEY) is missing. Without it, the VPN provider can see which mailboxes you use. Give the relay as IP:PORT#KEY"),
            (false, true) => Some("No tunnel is set. The relay and your network can see your IP address. Use --vpn IFACE, or use a .onion or .i2p relay"),
            (false, false) => Some("No tunnel is set and the connection is not encrypted. Your network can see which mailboxes you use and when you use them. Use a .onion or .i2p relay, or use --vpn with IP:PORT#KEY"),
        };
        if let Some(why) = problem {
            if !risk {
                return Err(format!("Relay {name} refused. {why}.\nTo allow it, add --i-accept-the-risk. Use this option for development only."));
            }
            warn.push(format!("Relay {name}: {why}."));
        }
    }
    Ok(warn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> RelayAddr {
        RelayAddr::parse(s).unwrap()
    }

    #[test]
    fn routes() {
        let key = eigen_core::wire::base32(&[1u8; 32]);
        assert!(admit(&[r("abc.onion:7777"), r("abc.b32.i2p")], None, false)
            .unwrap()
            .is_empty());
        assert!(
            admit(&[r("1.2.3.4:7777")], None, false).is_err(),
            "plain clear-net refused"
        );
        assert!(
            admit(&[r(&format!("1.2.3.4:7777#{key}"))], None, false).is_err(),
            "IP exposed without tunnel"
        );
        assert!(
            admit(&[r("1.2.3.4:7777")], None, true).is_ok(),
            "consent overrides"
        );
        // `lo` is not a tunnel: refused without consent, allowed with it.
        assert!(admit(&[r(&format!("10.0.0.1:7777#{key}"))], Some("lo"), false).is_err());
        assert!(admit(&[r(&format!("10.0.0.1:7777#{key}"))], Some("lo"), true).is_ok());
        assert!(
            admit(&[r(&format!("relay.example:7777#{key}"))], Some("lo"), true).is_err(),
            "no DNS through a tunnel"
        );
        assert!(
            admit(&[], Some("eigen-nope0"), true).is_err(),
            "missing tunnel"
        );
    }
}
