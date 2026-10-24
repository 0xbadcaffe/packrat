use super::*;

impl App {
    pub fn iface_down(&mut self) {
        if self.iface_sel + 1 < self.iface_list.len() {
            self.iface_sel += 1;
        }
    }

    pub fn iface_up(&mut self) {
        self.iface_sel = self.iface_sel.saturating_sub(1);
    }

    pub fn confirm_iface(&mut self) {
        if self.iface_list.is_empty() {
            self.picking_iface = false;
            self.capturing = false;
            self.set_status("No capture interfaces found".to_string());
            return;
        }

        self.selected_iface = self.iface_list[self.iface_sel].clone();
        self.picking_iface = false;
        self.abort_capture();

        // Clear all analysis state so simulated data cannot bleed into real captures
        // and vice-versa. clear_packets() sets capturing=false; we restore it below.
        if let Err(error) = self.try_clear_packets() {
            self.picking_iface = true;
            self.set_status(format!("Interface switch postponed: {error}"));
            return;
        }

        if self.selected_iface == "simulated" {
            self.seed_scenario();
            self.capture_handle = Some(SimulatedCapture.run(self.packet_tx.clone()));
            self.capturing = true;
        } else {
            if let Some(program) = self.capture_helper_path.clone() {
                use crate::capture::helper::HelperCapture;
                let source = HelperCapture {
                    program,
                    iface: self.selected_iface.clone(),
                    filter: None,
                };
                self.capture_handle = Some(source.run(self.packet_tx.clone()));
                self.capturing = true;
                return;
            }
            #[cfg(feature = "real-capture")]
            {
                use crate::capture::live::LiveCapture;
                let source = LiveCapture {
                    iface: self.selected_iface.clone(),
                    filter: None,
                };
                self.capture_handle = Some(source.run(self.packet_tx.clone()));
                self.capturing = true;
            }
            #[cfg(not(feature = "real-capture"))]
            {
                self.capturing = false;
            }
        }
    }

    pub fn switch_interface(&mut self) {
        self.abort_capture();
        self.picking_iface = true;
        self.capturing = false;
    }

    pub(super) fn abort_capture(&mut self) {
        if let Some(handle) = self.capture_handle.take() {
            handle.abort();
        }
    }
}
