// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use bitcoin::Txid;
use lightning::ln::channelmanager::PaymentId;
use lightning::{impl_writeable_tlv_based, impl_writeable_tlv_based_enum};

use crate::data_store::{StorableObject, StorableObjectUpdate, UpdatableObject};
use crate::payment::payjoin::{unix_now, PayjoinSessionStatus};

/// Represents a payjoin session with persisted events
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayjoinSession {
	/// Session identifier (uses PaymentId from PaymentDetails)
	pub session_id: PaymentId,

	/// The kind of session.
	pub kind: PayjoinSessionKind,

	/// Serialized session events.
	///
	/// Only ever appended to by the [`KVStorePayjoinReceiverPersister`] through
	/// [`DataStore::mutate`], and left out of [`PayjoinSessionUpdate`], so a write of a copy read
	/// before an event was appended can't drop it.
	///
	/// [`KVStorePayjoinReceiverPersister`]: crate::payment::payjoin::persist::KVStorePayjoinReceiverPersister
	/// [`DataStore::mutate`]: crate::data_store::DataStore::mutate
	pub events: Vec<SerializedSessionEvent>,

	/// Unix timestamp of when the session ended, or `None` while it's open, including while its
	/// fallback is pending.
	pub completed_at: Option<u64>,

	/// The timestamp, in seconds since start of the UNIX epoch, when this entry was last updated.
	pub latest_update_timestamp: u64,

	/// Whether the user asked to cancel the session. The resume task applies the request.
	///
	/// Only ever set through [`DataStore::mutate`], and left out of [`PayjoinSessionUpdate`], so a
	/// write of a copy read before the request can't undo it.
	///
	/// [`DataStore::mutate`]: crate::data_store::DataStore::mutate
	pub cancel_requested: bool,

	/// The transaction spending the sender's inputs that wallet sync saw, if any. `None` for a
	/// session that ended without one, e.g. because it expired before the sender sent its
	/// original, or its fallback was given up on.
	///
	/// Only ever set through [`DataStore::mutate`], and left out of [`PayjoinSessionUpdate`], for
	/// the same reason as [`Self::cancel_requested`].
	///
	/// [`DataStore::mutate`]: crate::data_store::DataStore::mutate
	pub resolution: Option<SessionResolution>,
}

/// A transaction spending the sender's inputs of a [`PayjoinSession`], and how far it got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionResolution {
	/// The latest such transaction wallet sync saw, until it's confirmed through
	/// `ANTI_REORG_DELAY`. Meanwhile the session isn't advanced any further and can't be
	/// cancelled, and its fallback isn't broadcast. Cleared if the transaction drops out.
	Pending(SessionSpend),
	/// The transaction was confirmed through `ANTI_REORG_DELAY`, which settled the session. Set
	/// just before the session's log is closed, which sets [`PayjoinSession::completed_at`], and
	/// never changed after.
	Settled(SessionSpend),
}

impl_writeable_tlv_based_enum!(SessionResolution,
	{0, Pending} => (),
	{2, Settled} => ()
);

/// A transaction spending the sender's inputs, as classified against a [`PayjoinSession`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSpend {
	/// The transaction.
	pub txid: Txid,
	/// What it is to the session.
	pub kind: SpendKind,
}

impl_writeable_tlv_based!(SessionSpend, {
	(0, txid, required),
	(2, kind, required),
});

/// What a transaction spending the sender's inputs is to a session, as payjoin's `ResolvedBy`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpendKind {
	/// The payjoin proposal.
	Payjoin,
	/// The sender's fallback transaction.
	Fallback,
	/// Neither, e.g. a fee bump or a double-spend by the sender.
	Unrecognized,
}

impl_writeable_tlv_based_enum!(SpendKind,
	(0, Payjoin) => {},
	(2, Fallback) => {},
	(4, Unrecognized) => {}
);

impl PayjoinSession {
	pub fn new(session_id: PaymentId, kind: PayjoinSessionKind) -> Self {
		Self {
			session_id,
			kind,
			events: Vec::new(),
			completed_at: None,
			latest_update_timestamp: unix_now(),
			cancel_requested: false,
			resolution: None,
		}
	}

	/// Whether the session is still running: it's open, and no spend settled it.
	///
	/// A settled session is open only until its log is closed, which the resume task retries if it
	/// failed.
	pub(crate) fn is_running(&self) -> bool {
		self.completed_at.is_none() && self.settled_spend().is_none()
	}

	/// Whether the session is running but paused, waiting for wallet sync to see the spend of the
	/// sender's inputs it recorded buried.
	pub(crate) fn is_awaiting_settlement(&self) -> bool {
		self.is_running() && self.pending_spend().is_some()
	}

	/// Whether the session can still be cancelled, as far as its record tells: it's running, and
	/// wallet sync saw no spend of the sender's inputs, which the session settles on instead.
	pub(crate) fn is_cancellable(&self) -> bool {
		self.is_running() && !self.is_awaiting_settlement()
	}

	/// Whether the session's pending spend is one of `txids`.
	pub(crate) fn is_pending_on_any(&self, txids: &[Txid]) -> bool {
		self.pending_spend().is_some_and(|spend| txids.contains(&spend.txid))
	}

	/// When the last event was appended to the session's log, or when the record was last
	/// updated if it has none.
	pub(crate) fn last_event_at(&self) -> u64 {
		self.events.last().map_or(self.latest_update_timestamp, |e| e.created_at)
	}

	/// The spend waiting to be buried, if any.
	pub(crate) fn pending_spend(&self) -> Option<&SessionSpend> {
		match &self.resolution {
			Some(SessionResolution::Pending(spend)) => Some(spend),
			_ => None,
		}
	}

	/// The spend that settled the session, if any.
	pub(crate) fn settled_spend(&self) -> Option<&SessionSpend> {
		match &self.resolution {
			Some(SessionResolution::Settled(spend)) => Some(spend),
			_ => None,
		}
	}

	/// The session's status as reported to the user by [`PayjoinPayment::status`].
	///
	/// `fallback_txid` is the txid of the session's fallback transaction: for a running session,
	/// only if the fallback is pending, and for an ended one, if the session had one. Only a
	/// cancelled session that ended reports it.
	///
	/// [`PayjoinPayment::status`]: crate::payment::PayjoinPayment::status
	pub(crate) fn user_status(&self, fallback_txid: Option<Txid>) -> PayjoinSessionStatus {
		if let Some(SessionSpend { txid, kind: SpendKind::Payjoin }) = self.settled_spend() {
			return PayjoinSessionStatus::Completed { txid: *txid };
		}
		match fallback_txid {
			_ if !self.is_running() && self.cancel_requested => {
				PayjoinSessionStatus::Cancelled { fallback_txid }
			},
			_ if !self.is_running() => {
				PayjoinSessionStatus::Failed { txid: self.settled_spend().map(|s| s.txid) }
			},
			Some(fallback_txid) if self.cancel_requested => {
				PayjoinSessionStatus::Cancelled { fallback_txid: Some(fallback_txid) }
			},
			Some(fallback_txid) => PayjoinSessionStatus::FallbackPending { fallback_txid },
			None => PayjoinSessionStatus::Active,
		}
	}
}

impl_writeable_tlv_based!(PayjoinSession, {
	(0, session_id, required),
	(2, kind, required),
	(4, events, required_vec),
	(6, completed_at, option),
	(8, latest_update_timestamp, (default_value, 0u64)),
	(10, cancel_requested, (default_value, false)),
	(12, resolution, option),
});

/// The direction-specific data of a [`PayjoinSession`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayjoinSessionKind {
	/// We are receiving a payjoin.
	Receive,
}

impl_writeable_tlv_based_enum!(PayjoinSessionKind,
	(0, Receive) => {}
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializedSessionEvent {
	/// Serialized event bytes.
	pub event_bytes: Vec<u8>,
	/// Unix timestamp of when the event occurred
	pub created_at: u64,
}

impl_writeable_tlv_based!(SerializedSessionEvent, {
	(0, event_bytes, required),
	(2, created_at, required),
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PayjoinSessionUpdate {
	pub session_id: PaymentId,
	pub completed_at: Option<Option<u64>>,
}

impl From<&PayjoinSession> for PayjoinSessionUpdate {
	fn from(value: &PayjoinSession) -> Self {
		Self { session_id: value.session_id, completed_at: Some(value.completed_at) }
	}
}

impl StorableObject for PayjoinSession {
	type Id = PaymentId;

	fn id(&self) -> Self::Id {
		self.session_id
	}
}

impl UpdatableObject for PayjoinSession {
	type Update = PayjoinSessionUpdate;

	fn update(&mut self, update: Self::Update) -> bool {
		debug_assert_eq!(
			self.session_id, update.session_id,
			"We should only ever override data for the same id"
		);

		let mut updated = false;

		macro_rules! update_if_necessary {
			($val:expr, $update:expr) => {
				if $val != $update {
					$val = $update;
					updated = true;
				}
			};
		}

		if let Some(completed_at_opt) = update.completed_at {
			update_if_necessary!(self.completed_at, completed_at_opt);
		}

		if updated {
			self.latest_update_timestamp = unix_now();
		}

		updated
	}

	fn to_update(&self) -> Self::Update {
		self.into()
	}
}

impl StorableObjectUpdate<PayjoinSession> for PayjoinSessionUpdate {
	fn id(&self) -> <PayjoinSession as StorableObject>::Id {
		self.session_id
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::Hash;
	use lightning::util::ser::{Readable, Writeable};

	use super::*;

	fn txid(byte: u8) -> Txid {
		Txid::from_byte_array([byte; 32])
	}

	#[test]
	fn receive_session_round_trips() {
		let mut session = PayjoinSession::new(PaymentId([7; 32]), PayjoinSessionKind::Receive);
		session.events.push(SerializedSessionEvent { event_bytes: vec![1, 2, 3], created_at: 42 });
		session.completed_at = Some(43);
		session.cancel_requested = true;
		let spend = SessionSpend { txid: txid(1), kind: SpendKind::Payjoin };
		session.resolution = Some(SessionResolution::Pending(spend.clone()));
		let decoded = PayjoinSession::read(&mut &session.encode()[..]).unwrap();
		assert_eq!(decoded, session);

		session.resolution = Some(SessionResolution::Settled(spend));
		let decoded = PayjoinSession::read(&mut &session.encode()[..]).unwrap();
		assert_eq!(decoded, session);
	}

	#[test]
	fn stale_write_keeps_what_only_mutate_sets() {
		let stale = PayjoinSession::new(PaymentId([10; 32]), PayjoinSessionKind::Receive);
		let mut current = stale.clone();
		current.cancel_requested = true;
		let resolution = Some(SessionResolution::Pending(SessionSpend {
			txid: txid(2),
			kind: SpendKind::Fallback,
		}));
		current.resolution = resolution.clone();
		current.events.push(SerializedSessionEvent { event_bytes: vec![1], created_at: 1 });

		// What `insert_or_update` of a copy read before those writes applies.
		current.update(stale.to_update());
		assert!(current.cancel_requested);
		assert_eq!(current.resolution, resolution);
		assert_eq!(current.events.len(), 1);
	}

	#[test]
	fn user_status_reports_outcome_and_cancellation() {
		let fallback_txid = txid(3);
		let other_txid = txid(4);
		let settled =
			|kind| Some(SessionResolution::Settled(SessionSpend { txid: other_txid, kind }));
		let status = |resolution, completed: bool, cancel_requested, fallback: bool| {
			let mut session = PayjoinSession::new(PaymentId([12; 32]), PayjoinSessionKind::Receive);
			session.resolution = resolution;
			session.completed_at = completed.then_some(5);
			session.cancel_requested = cancel_requested;
			session.user_status(fallback.then_some(fallback_txid))
		};

		// A requested cancellation isn't reported until it's applied.
		assert_eq!(status(None, false, true, false), PayjoinSessionStatus::Active);
		assert_eq!(
			status(None, false, false, true),
			PayjoinSessionStatus::FallbackPending { fallback_txid }
		);
		assert_eq!(
			status(None, false, true, true),
			PayjoinSessionStatus::Cancelled { fallback_txid: Some(fallback_txid) }
		);
		assert_eq!(
			status(settled(SpendKind::Payjoin), true, false, true),
			PayjoinSessionStatus::Completed { txid: other_txid }
		);
		// Cancelling can't undo a payjoin that completed before it was applied.
		assert_eq!(
			status(settled(SpendKind::Payjoin), true, true, true),
			PayjoinSessionStatus::Completed { txid: other_txid }
		);
		assert_eq!(
			status(settled(SpendKind::Fallback), true, false, true),
			PayjoinSessionStatus::Failed { txid: Some(other_txid) }
		);
		// A spend waiting to be buried doesn't change it.
		let pending = Some(SessionResolution::Pending(SessionSpend {
			txid: other_txid,
			kind: SpendKind::Payjoin,
		}));
		assert_eq!(status(pending, false, false, false), PayjoinSessionStatus::Active);
		// Settled, though its log isn't closed yet.
		assert_eq!(
			status(settled(SpendKind::Fallback), false, false, true),
			PayjoinSessionStatus::Failed { txid: Some(other_txid) }
		);
		assert_eq!(
			status(settled(SpendKind::Unrecognized), true, true, true),
			PayjoinSessionStatus::Cancelled { fallback_txid: Some(fallback_txid) }
		);
		assert_eq!(status(None, true, false, false), PayjoinSessionStatus::Failed { txid: None });
		assert_eq!(
			status(None, true, true, false),
			PayjoinSessionStatus::Cancelled { fallback_txid: None }
		);
	}
}
