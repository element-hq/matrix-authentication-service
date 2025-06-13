// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    net::{AddrParseError, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    str::Utf8Error,
};

use bytes::Buf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum ProxyProtocolV1Info {
    Tcp {
        source: SocketAddr,
        destination: SocketAddr,
    },
    Udp {
        source: SocketAddr,
        destination: SocketAddr,
    },
    Unknown,
}

#[derive(Error, Debug)]
#[error("Invalid proxy protocol header")]
pub enum ParseError {
    #[error("Not enough bytes provided")]
    NotEnoughBytes,
    NoCrLf,
    NoProxyPreamble,
    NoProtocol,
    InvalidProtocol,
    NoSourceAddress,
    NoDestinationAddress,
    NoSourcePort,
    NoDestinationPort,
    TooManyFields,
    InvalidUtf8(#[from] Utf8Error),
    InvalidAddress(#[from] AddrParseError),
    InvalidPort(#[from] ParseIntError),
}

impl ParseError {
    pub const fn not_enough_bytes(&self) -> bool {
        matches!(self, &Self::NotEnoughBytes)
    }
}

impl ProxyProtocolV1Info {
    #[allow(clippy::too_many_lines)]
    pub(super) fn parse<B>(buf: &mut B) -> Result<Self, ParseError>
    where
        B: Buf + AsRef<[u8]>,
    {
        use ParseError as E;
        // First, check if we *possibly* have enough bytes.
        // Minimum is 15: "PROXY UNKNOWN\r\n"

        if buf.remaining() < 15 {
            return Err(E::NotEnoughBytes);
        }

        // Let's check in the first 108 bytes if we find a CRLF
        let Some(crlf) = buf
            .as_ref()
            .windows(2)
            .take(108)
            .position(|needle| needle == [0x0D, 0x0A])
        else {
            // If not, it might be because we don't have enough bytes
            return if buf.remaining() < 108 {
                Err(E::NotEnoughBytes)
            } else {
                // Else it's just invalid
                Err(E::NoCrLf)
            };
        };

        // Trim to everything before the CRLF
        let bytes = &buf.as_ref()[..crlf];

        let mut it = bytes.splitn(6, |c| c == &b' ');
        // Check for the preamble
        if it.next() != Some(b"PROXY") {
            return Err(E::NoProxyPreamble);
        }

        let result = match it.next() {
            Some(b"TCP4") => {
                let source_address: Ipv4Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoSourceAddress)?)?.parse()?;
                let destination_address: Ipv4Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationAddress)?)?.parse()?;
                let source_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoSourcePort)?)?.parse()?;
                let destination_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationPort)?)?.parse()?;
                if it.next().is_some() {
                    return Err(E::TooManyFields);
                }

                let source = (source_address, source_port).into();
                let destination = (destination_address, destination_port).into();

                Self::Tcp {
                    source,
                    destination,
                }
            }
            Some(b"TCP6") => {
                let source_address: Ipv6Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoSourceAddress)?)?.parse()?;
                let destination_address: Ipv6Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationAddress)?)?.parse()?;
                let source_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoSourcePort)?)?.parse()?;
                let destination_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationPort)?)?.parse()?;
                if it.next().is_some() {
                    return Err(E::TooManyFields);
                }

                let source = (source_address, source_port).into();
                let destination = (destination_address, destination_port).into();

                Self::Tcp {
                    source,
                    destination,
                }
            }
            Some(b"UDP4") => {
                let source_address: Ipv4Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoSourceAddress)?)?.parse()?;
                let destination_address: Ipv4Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationAddress)?)?.parse()?;
                let source_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoSourcePort)?)?.parse()?;
                let destination_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationPort)?)?.parse()?;
                if it.next().is_some() {
                    return Err(E::TooManyFields);
                }

                let source = (source_address, source_port).into();
                let destination = (destination_address, destination_port).into();

                Self::Udp {
                    source,
                    destination,
                }
            }
            Some(b"UDP6") => {
                let source_address: Ipv6Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoSourceAddress)?)?.parse()?;
                let destination_address: Ipv6Addr =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationAddress)?)?.parse()?;
                let source_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoSourcePort)?)?.parse()?;
                let destination_port: u16 =
                    std::str::from_utf8(it.next().ok_or(E::NoDestinationPort)?)?.parse()?;
                if it.next().is_some() {
                    return Err(E::TooManyFields);
                }

                let source = (source_address, source_port).into();
                let destination = (destination_address, destination_port).into();

                Self::Udp {
                    source,
                    destination,
                }
            }
            Some(b"UNKNOWN") => Self::Unknown,
            Some(_) => return Err(E::InvalidProtocol),
            None => return Err(E::NoProtocol),
        };

        buf.advance(crlf + 2);

        Ok(result)
    }

    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        match self {
            Self::Udp {
                source,
                destination,
            }
            | Self::Tcp {
                source,
                destination,
            } => source.is_ipv4() && destination.is_ipv4(),
            Self::Unknown => false,
        }
    }

    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        match self {
            Self::Udp {
                source,
                destination,
            }
            | Self::Tcp {
                source,
                destination,
            } => source.is_ipv6() && destination.is_ipv6(),
            Self::Unknown => false,
        }
    }

    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp { .. })
    }

    #[must_use]
    pub const fn is_udp(&self) -> bool {
        matches!(self, Self::Udp { .. })
    }

    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    #[must_use]
    pub const fn source(&self) -> Option<&SocketAddr> {
        match self {
            Self::Udp { source, .. } | Self::Tcp { source, .. } => Some(source),
            Self::Unknown => None,
        }
    }

    #[must_use]
    pub const fn destination(&self) -> Option<&SocketAddr> {
        match self {
            Self::Udp { destination, .. } | Self::Tcp { destination, .. } => Some(destination),
            Self::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let mut buf =
            b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nhello world".as_slice();
        let info = ProxyProtocolV1Info::parse(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
        assert!(info.is_tcp());
        assert!(!info.is_udp());
        assert!(!info.is_unknown());
        assert!(info.is_ipv4());
        assert!(!info.is_ipv6());

        let mut buf =
            b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nhello world"
            .as_slice();
        let info = ProxyProtocolV1Info::parse(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
        assert!(info.is_tcp());
        assert!(!info.is_udp());
        assert!(!info.is_unknown());
        assert!(!info.is_ipv4());
        assert!(info.is_ipv6());

        let mut buf = b"PROXY UNKNOWN\r\nhello world".as_slice();
        let info = ProxyProtocolV1Info::parse(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
        assert!(!info.is_tcp());
        assert!(!info.is_udp());
        assert!(info.is_unknown());
        assert!(!info.is_ipv4());
        assert!(!info.is_ipv6());

        let mut buf =
            b"PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nhello world"
            .as_slice();
        let info = ProxyProtocolV1Info::parse(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
        assert!(!info.is_tcp());
        assert!(!info.is_udp());
        assert!(info.is_unknown());
        assert!(!info.is_ipv4());
        assert!(!info.is_ipv6());
    }
}
