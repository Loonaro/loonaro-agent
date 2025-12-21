use crate::send_event_enqueue;
use one_collect::Guid;
use one_collect::ReadOnly;
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_registry(
    etw: &mut EtwSession,
    tx: mpsc::Sender<Vec<u8>>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Registry provider guid
    let reg_guid = Guid::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);
    etw.enable_provider(reg_guid);

    // event type 65 = SetValue
    let mut reg_event = Event::new(65, "Registry::SetValue".into());
    *reg_event.extension_mut().provider_mut() = reg_guid;
    reg_event.set_no_callstack_flag();

    reg_event.add_callback(move |data: &EventData| {
        *counter.borrow_mut() += 1;
        send_event_enqueue(
            &tx,
            data,
            &ancillary,
            etw::EtwEvent::Registry(etw::RegistryEvent::SetValue),
        )
        .into()
    });

    etw.add_event(reg_event, None);
}
