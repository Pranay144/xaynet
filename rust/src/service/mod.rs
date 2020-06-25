use crate::{
    coordinator::Coordinator,
    settings::{MaskSettings, PetSettings},
    InitError,
};
use futures::ready;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::stream::Stream;

pub mod data;
mod handle;

pub use data::Data;
pub use handle::{
    Event,
    EventStream,
    Handle,
    LengthRequest,
    Message,
    RoundParametersRequest,
    ScalarRequest,
    SeedDictRequest,
    SumDictRequest,
};

/// The `Service` is the task that drives the PET protocol. It reacts
/// to the various messages from the participants and drives the
/// protocol.
pub struct Service {
    /// The coordinator holds the protocol state: crypto material, sum
    /// and update dictionaries, configuration, etc.
    coordinator: Coordinator,

    /// Events to handle
    events: EventStream,

    /// Data the service currently holds.
    data: Data,
}

impl Service {
    /// Instantiate a new [`Service`] and return it along with the
    /// corresponding [`Handle`].
    pub fn new(pet: PetSettings, mask: MaskSettings) -> Result<(Self, Handle), InitError> {
        let (handle, events) = Handle::new();
        let service = Self {
            events,
            coordinator: Coordinator::new_with_config(pet, mask)?,
            data: Data::new(),
        };
        Ok((service, handle))
    }

    /// Dispatch the given event to the appropriate handler
    fn dispatch_event(&mut self, event: Event) {
        match event {
            Event::Message(Message { buffer }) => self.handle_message(buffer),
            Event::RoundParameters(req) => self.handle_round_parameters_request(req),
            Event::SumDict(req) => self.handle_sum_dict_request(req),
            Event::Scalar(req) => self.handle_scalar_request(req),
            Event::SeedDict(req) => self.handle_seed_dict_request(req),
            Event::Length(req) => self.handle_length_request(req),
        }
        self.process_protocol_events();
    }

    /// Handler for round parameters requests
    fn handle_round_parameters_request(&mut self, req: RoundParametersRequest) {
        self.coordinator.try_phase_transition(); // HACK get coordinator out of IDLE
        let RoundParametersRequest { response_tx } = req;
        let _ = response_tx.send(self.data.round_parameters());
    }

    /// Handler for sum dict requests
    fn handle_sum_dict_request(&self, req: SumDictRequest) {
        let SumDictRequest { response_tx } = req;
        let _ = response_tx.send(self.data.sum_dict());
    }

    /// Handler for model scalar requests
    fn handle_scalar_request(&self, req: ScalarRequest) {
        let ScalarRequest { response_tx } = req;
        let _ = response_tx.send(self.data.scalar());
    }

    /// Handler for seed dict requests
    fn handle_seed_dict_request(&mut self, req: SeedDictRequest) {
        let SeedDictRequest {
            public_key,
            response_tx,
        } = req;
        let resp = self.data.seed_dict(public_key).unwrap();
        let _ = response_tx.send(resp);
    }

    /// Handler for model/mask length requests.
    fn handle_length_request(&self, req: LengthRequest) {
        let LengthRequest { response_tx } = req;
        let _ = response_tx.send(self.data.length());
    }

    /// Dequeue all the events produced by the coordinator, and handle
    /// them
    fn process_protocol_events(&mut self) {
        while let Some(event) = self.coordinator.next_event() {
            if let Err(e) = self.data.update(event) {
                error!(error = %e, "failed to update the service state, cancelling current round");
                self.coordinator.reset();
            }
        }
    }

    /// Handle a message
    fn handle_message(&mut self, buffer: Vec<u8>) {
        let _ = self.coordinator.handle_message(&buffer[..]);
    }

    /// Handle the incoming requests.
    fn poll_events(&mut self, cx: &mut Context) -> Poll<()> {
        trace!("polling requests");
        loop {
            match ready!(Pin::new(&mut self.events).poll_next(cx)) {
                Some(event) => self.dispatch_event(event),
                None => {
                    trace!("no more events to handle");
                    return Poll::Ready(());
                }
            }
        }
    }
}

impl Future for Service {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        trace!("polling Service");
        let pin = self.get_mut();

        if let Poll::Ready(_) = pin.poll_events(cx) {
            return Poll::Ready(());
        }

        Poll::Pending
    }
}