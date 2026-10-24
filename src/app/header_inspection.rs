use super::*;

impl App {
    pub fn packet_header_fields(&self) -> Vec<PacketField> {
        self.active_investigation_packet()
            .map(packet_fields::extract_fields)
            .unwrap_or_default()
    }

    pub fn visible_packet_header_fields(&self) -> Vec<PacketField> {
        packet_fields::filter_fields(&self.packet_header_fields(), &self.header_search)
    }

    pub fn header_cursor_down(&mut self) {
        let count = self.visible_packet_header_fields().len();
        if count == 0 {
            self.header_cursor = 0;
        } else {
            self.header_cursor = (self.header_cursor + 1).min(count - 1);
        }
    }

    pub fn header_cursor_up(&mut self) {
        self.header_cursor = self.header_cursor.saturating_sub(1);
    }

    pub fn header_cursor_home(&mut self) {
        self.header_cursor = 0;
    }

    pub fn header_cursor_end(&mut self) {
        self.header_cursor = self.visible_packet_header_fields().len().saturating_sub(1);
    }

    pub fn start_header_search(&mut self) {
        self.header_searching = true;
        self.header_cursor = 0;
    }

    pub fn close_header_search(&mut self) {
        self.header_searching = false;
    }

    pub fn update_header_search(&mut self, c: char) {
        self.header_search.push(c);
        self.header_cursor = 0;
    }

    pub fn pop_header_search(&mut self) {
        self.header_search.pop();
        self.header_cursor = 0;
    }

    pub fn clear_header_search(&mut self) {
        self.header_search.clear();
        self.header_cursor = 0;
    }

    pub fn apply_selected_header_filter(&mut self) {
        let fields = self.visible_packet_header_fields();
        let Some(field) = fields.get(self.header_cursor).or_else(|| fields.first()) else {
            self.set_status("No packet header field selected");
            return;
        };
        let Some(expr) = packet_fields::filter_expression(field) else {
            self.set_status(format!("No display filter mapping for {}", field.path));
            return;
        };
        self.filter.input = expr.clone();
        self.filter.active = false;
        self.rebuild_filtered();
        self.active_tab = Tab::Packets;
        self.set_status(format!("Filter applied: {expr}"));
    }

    pub fn jump_selected_header_to_bytes(&mut self) {
        let fields = self.visible_packet_header_fields();
        let Some(field) = fields.get(self.header_cursor).or_else(|| fields.first()) else {
            self.set_status("No packet header field selected");
            return;
        };
        let Some(offset) = field.offset else {
            self.set_status(format!(
                "{} is derived metadata and has no byte offset",
                field.path
            ));
            return;
        };
        let path = field.path.clone();
        let packet_len = self
            .active_investigation_packet()
            .map(|packet| packet.bytes.len())
            .unwrap_or(0);
        self.byte_cursor = offset.min(packet_len.saturating_sub(1));
        self.investigation_scroll = self.byte_cursor / 16;
        self.investigation_view = InvestigationView::Bytes;
        self.set_status(format!("Byte inspector: {path} at offset 0x{offset:04x}"));
    }

    pub fn byte_cursor_left(&mut self) {
        self.byte_cursor = self.byte_cursor.saturating_sub(1);
    }

    pub fn byte_cursor_right(&mut self) {
        let packet_len = self
            .active_investigation_packet()
            .map(|packet| packet.bytes.len())
            .unwrap_or(0);
        self.byte_cursor = (self.byte_cursor + 1).min(packet_len.saturating_sub(1));
    }

    pub fn byte_cursor_up(&mut self) {
        self.byte_cursor = self.byte_cursor.saturating_sub(16);
    }

    pub fn byte_cursor_down(&mut self) {
        let packet_len = self
            .active_investigation_packet()
            .map(|packet| packet.bytes.len())
            .unwrap_or(0);
        self.byte_cursor = (self.byte_cursor + 16).min(packet_len.saturating_sub(1));
    }

    pub fn byte_cursor_home(&mut self) {
        self.byte_cursor = 0;
    }

    pub fn byte_cursor_end(&mut self) {
        self.byte_cursor = self
            .active_investigation_packet()
            .map(|packet| packet.bytes.len().saturating_sub(1))
            .unwrap_or(0);
    }

    pub(super) fn reset_header_focus(&mut self) {
        self.header_cursor = 0;
        self.byte_cursor = 0;
        self.header_searching = false;
    }
}
