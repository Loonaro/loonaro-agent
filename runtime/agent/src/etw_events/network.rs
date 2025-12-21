use crate::send_event_enqueue;
use one_collect::Guid;
use one_collect::ReadOnly;
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_network(
    etw: &mut EtwSession,
    tx: mpsc::Sender<Vec<u8>>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // TcpIp provider guid
    let net_guid = Guid::from_u128(0x2f07e2ee_15db_40f1_90ef_9d7ba282188a);
    etw.enable_provider(net_guid);

    // event type 12 = Connect
    let mut net_event = Event::new(12, "TcpIp::Connect".into());
    *net_event.extension_mut().provider_mut() = net_guid;
    net_event.set_no_callstack_flag();

    net_event.add_callback(move |data: &EventData| {
        *counter.borrow_mut() += 1;
        send_event_enqueue(
            &tx,
            data,
            &ancillary,
            etw::EtwEvent::Network(etw::NetworkEvent::Connect),
        )
        .into()
    });

    etw.add_event(net_event, None);
}
