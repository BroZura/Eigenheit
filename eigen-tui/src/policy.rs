//! Which routes to a relay I accept, and why. Refusals explain themselves.
use eigen_transport::device::{self, Kind};

use crate::tor::RelayAddr;

/// Check relays against the chosen transports. Ok carries warnings to show.
pub fn admit(relays: &[RelayAddr], vpn: Option<&str>, risk: bool) -> Result<Vec<String>, String> {
    let mut warn = Vec::new();
    if let Some(dev) = vpn {
        match device::inspect(dev) {
            Ok(Kind::WireGuard) => {}
            Ok(Kind::Tunnel) => warn.push(format!("{dev} is a tunnel interface (not WireGuard); direct links are bound to it.")),
            Ok(Kind::Other) => {
                if !risk {
                    return Err(format!("{dev} does not look like a VPN or WireGuard tunnel. refusing (or --i-accept-the-risk)."));
                }
                warn.push(format!("{dev} does not look like a tunnel. I bound to it anyway, because I was told to."));
            }
            Err(_) => return Err(format!("interface {dev} does not exist. nothing will leave around it: bring the tunnel up first.")),
        }
        if !relays.iter().any(|r| r.is_clear()) {
            warn.push("--vpn binds direct relays only; tor and i2p keep their own routes (run their daemons over the VPN if I want that too).".into());
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
            return Err(format!("{name}: through a tunnel I need an IP address; resolving a name would ask DNS outside it."));
        }
        let problem = match (vpn.is_some(), r.key.is_some()) {
            (true, true) => None,
            (true, false) => Some("no relay key (#KEY): the VPN provider would read which mailboxes I touch. use the relay's HOST:PORT#KEY"),
            (false, true) => Some("no tunnel: the relay and my network would see my IP. use --vpn <wg0>, or a .onion / .i2p relay"),
            (false, false) => Some("clear-net and unencrypted: my network sees which mailboxes I touch and when. use .onion, .i2p, or --vpn with HOST:PORT#KEY"),
        };
        if let Some(why) = problem {
            if !risk {
                return Err(format!("refusing relay {name}: {why}.\n(--i-accept-the-risk overrides this; development only.)"));
            }
            warn.push(format!("{name}: {why}."));
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
