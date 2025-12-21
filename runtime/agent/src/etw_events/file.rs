use crate::send_event_enqueue;
use one_collect::Guid;
use one_collect::ReadOnly;
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_file_create(
    etw: &mut EtwSession,
    tx: mpsc::Sender<Vec<u8>>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // FileIo provider guid
    let file_guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
    etw.enable_provider(file_guid);

    // event type 64 = FileIo_Create
    let mut file_event = Event::new(64, "FileIo::Create".into());
    *file_event.extension_mut().provider_mut() = file_guid;
    file_event.set_no_callstack_flag();

    file_event.add_callback(move |data: &EventData| {
        *counter.borrow_mut() += 1;
        send_event_enqueue(
            &tx,
            data,
            &ancillary,
            etw::EtwEvent::File(etw::FileEvent::Create),
        )
        .into()
    });

    etw.add_event(file_event, None);
}
