use super::*;

pub(super) fn parse_tcp_transport(
    transport: &[u8],
    declared_len: usize,
    source: IpAddr,
    destination: IpAddr,
    complete: bool,
) -> TcpFrame<'_> {
    if declared_len < 20 {
        return TcpFrame::Malformed("IP payload is shorter than a minimum TCP header");
    }
    let captured = &transport[..transport.len().min(declared_len)];
    if captured.len() < 20 {
        return TcpFrame::Malformed("captured TCP header is truncated");
    }
    let header_len = usize::from(captured[12] >> 4) * 4;
    if header_len < 20 {
        return TcpFrame::Malformed("TCP data offset is smaller than 20 bytes");
    }
    if header_len > declared_len {
        return TcpFrame::Malformed("TCP data offset exceeds the IP transport length");
    }

    let source = SocketAddr::new(source, u16_be_at(captured, 0));
    let destination = SocketAddr::new(destination, u16_be_at(captured, 2));
    let (endpoint_a, endpoint_b, from_a) = if source <= destination {
        (source, destination, true)
    } else {
        (destination, source, false)
    };
    TcpFrame::Segment(TcpSegment {
        key: TcpFlowKey { endpoint_a, endpoint_b },
        from_a,
        sequence: u32::from_be_bytes([captured[4], captured[5], captured[6], captured[7]]),
        acknowledgement: u32::from_be_bytes([captured[8], captured[9], captured[10], captured[11]]),
        flags: captured[13],
        complete: complete && captured.len() == declared_len,
        payload: &captured[header_len.min(captured.len())..],
    })
}
