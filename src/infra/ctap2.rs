use std::fs::File;

use uhid_virt::{Bus, CreateParams};

use crate::utils::uhid::{UHIDDevice, UHIDErr};

pub async fn create_ctap2_device() -> Result<UHIDDevice<File>, UHIDErr> {
    let params = CreateParams {
        name: "Virtual CTAP2".to_string(),
        bus: Bus::USB,
        version: 0,
        country: 0,
        vendor: 0,
        phys: "".to_string(),
        uniq: "".to_string(),
        product: 0,
        rd_data: [0, 0, 0].into(),
    };
    UHIDDevice::create(params).await
}
