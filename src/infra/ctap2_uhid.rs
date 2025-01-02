use crate::prelude::*;
use std::fs::File;

use uhid_virt::{Bus, CreateParams};

use crate::uhid::UHIDDevice;

// HID Report Descriptor from http://www.usb.org/developers/hidpage/HUTRR48.pdf
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, /* Usage Page: FIDO Alliance Page (0xF1D0) */
    0x09, 0x01, /*       Usage: U2F Authenticator Device (0x01)  */
    0xa1, 0x01, /*       Collection: Application                 */
    0x09, 0x20, /*       - Usage: Input Report Data (0x20)       */
    0x15, 0x00, /*       - Logical Minimum (0)                   */
    0x26, 0xff, 0x00, /* - Logical Maximum (255)                 */
    0x75, 0x08, /*       - Report Size (8)                       */
    0x95, 0x40, /*       - Report Count (64)                     */
    0x81, 0x02, /*       - Input (Data, Absolute, Variable)      */
    0x09, 0x21, /*       - Usage: Input Report Data (0x21)       */
    0x15, 0x00, /*       - Logical Minimum (0)                  */
    0x26, 0xff, 0x00, /* - Logical Maximum (255)                 */
    0x75, 0x08, /*       - Report Size (8)                       */
    0x95, 0x40, /*       - Report Count (64)                     */
    0x91, 0x02, /*       - Output (Data, Absolute, Variable)     */
    0xc0, /*             End Collection                          */
];

pub async fn create_ctap2_uhid_device() -> Result<UHIDDevice<File>> {
    let params = CreateParams {
        name: "Virtual CTAP2".to_string(),
        bus: Bus::USB,
        version: 1,
        country: 0,
        vendor: 0,
        phys: "".to_string(),
        uniq: "".to_string(),
        product: 0,
        rd_data: REPORT_DESCRIPTOR.into(),
    };
    UHIDDevice::create(params).await
}
