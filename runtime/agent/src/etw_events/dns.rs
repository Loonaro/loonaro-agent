use crate::send_event_enqueue;
use one_collect::Guid;
use one_collect::ReadOnly;
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_dns(
    etw: &mut EtwSession,
    tx: mpsc::Sender<Vec<u8>>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-DNS-Client provider guid
    let dns_guid = Guid::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
    etw.enable_provider(dns_guid);

    // event id 3019 = Query
    let mut dns_event = Event::new(3019, "Dns::Query".into());
    *dns_event.extension_mut().provider_mut() = dns_guid;
    dns_event.set_no_callstack_flag();

    dns_event.add_callback(move |data: &EventData| {
        *counter.borrow_mut() += 1;
        send_event_enqueue(
            &tx,
            data,
            &ancillary,
            etw::EtwEvent::Dns(etw::DnsEvent::Query),
        )
        .into()
    });

    etw.add_event(dns_event, None);
}
