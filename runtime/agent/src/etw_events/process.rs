use crate::send_event_enqueue;
use etw::ProcessEvent;
use one_collect::ReadOnly;
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::EventData;
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_process(
    etw: &mut EtwSession,
    tx: mpsc::Sender<Vec<u8>>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    let ancillary_create = ancillary.clone();
    let tx_create = tx.clone();
    let counter_create = counter.clone();
    etw.comm_start_event()
        .add_callback(move |data: &EventData| {
            *counter_create.borrow_mut() += 1;
            send_event_enqueue(
                &tx_create,
                data,
                &ancillary_create,
                etw::EtwEvent::SystemProcess(ProcessEvent::ProcessCreate),
            )
            .into()
        });

    let ancillary_term = ancillary.clone();
    let tx_term = tx.clone();
    let counter_term = counter.clone();
    etw.comm_end_event().add_callback(move |data: &EventData| {
        *counter_term.borrow_mut() += 1;
        send_event_enqueue(
            &tx_term,
            data,
            &ancillary_term,
            etw::EtwEvent::SystemProcess(ProcessEvent::ProcessTerminate),
        )
        .into()
    });
}
