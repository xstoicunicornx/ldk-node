// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::Txid;
use lightning::ln::channelmanager::PaymentId;
use lightning::{impl_writeable_tlv_based, impl_writeable_tlv_based_enum};

use crate::data_store::{StorableObject, StorableObjectUpdate, UpdatableObject};
use crate::payment::payjoin::PayjoinSessionStatus;

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

	/// Current status of the session
	pub status: PayjoinStatus,

	/// Unix timestamp of session completion (if completed)
	pub completed_at: Option<u64>,

	/// The timestamp, in seconds since start of the UNIX epoch, when this entry was last updated.
	pub latest_update_timestamp: u64,

	/// Whether the user asked to cancel the session. The resume task applies the request, so it
	/// alone writes the session's event log.
	///
	/// Only ever set through [`DataStore::mutate`], and left out of [`PayjoinSessionUpdate`], so a
	/// write of a copy read before the request can't undo it.
	///
	/// [`DataStore::mutate`]: crate::data_store::DataStore::mutate
	pub cancel_requested: bool,

	/// The transaction that settled the session, once known: the payjoin, the fallback, or another
	/// spend of the sender's inputs.
	pub resolution_txid: Option<Txid>,

	/// The latest transaction wallet sync saw spending the sender's inputs, as classified against
	/// the session, until it's confirmed through `ANTI_REORG_DELAY` and settles the session. While
	/// there is one, the session isn't advanced any further and can't be cancelled.
	///
	/// Only ever set through [`DataStore::mutate`], and left out of [`PayjoinSessionUpdate`], for
	/// the same reason as [`Self::cancel_requested`].
	///
	/// [`DataStore::mutate`]: crate::data_store::DataStore::mutate
	pub spend: Option<SessionSpend>,
}

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
		let latest_update_timestamp = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(Duration::from_secs(0))
			.as_secs();
		Self {
			session_id,
			kind,
			events: Vec::new(),
			status: PayjoinStatus::Active,
			completed_at: None,
			latest_update_timestamp,
			cancel_requested: false,
			resolution_txid: None,
			spend: None,
		}
	}

	/// The session's status as reported to the user by [`PayjoinPayment::status`], given the
	/// txid of the session's fallback transaction, if it has one.
	///
	/// [`PayjoinPayment::status`]: crate::payment::PayjoinPayment::status
	pub(crate) fn user_status(&self, fallback_txid: Option<Txid>) -> PayjoinSessionStatus {
		match self.status {
			PayjoinStatus::Active => PayjoinSessionStatus::Active,
			PayjoinStatus::Completed => {
				PayjoinSessionStatus::Completed { txid: self.resolution_txid }
			},
			PayjoinStatus::FallbackPending | PayjoinStatus::Failed if self.cancel_requested => {
				PayjoinSessionStatus::Cancelled { fallback_txid }
			},
			// A session only becomes pending a fallback it has.
			PayjoinStatus::FallbackPending => match fallback_txid {
				Some(fallback_txid) => PayjoinSessionStatus::FallbackPending { fallback_txid },
				None => PayjoinSessionStatus::Failed { txid: None },
			},
			PayjoinStatus::Failed => PayjoinSessionStatus::Failed { txid: self.resolution_txid },
		}
	}
}

impl_writeable_tlv_based!(PayjoinSession, {
	(0, session_id, required),
	(2, kind, required),
	(6, events, required_vec),
	(8, status, required),
	(10, completed_at, option),
	(12, latest_update_timestamp, (default_value, 0u64)),
	(14, cancel_requested, (default_value, false)),
	(16, resolution_txid, option),
	(18, spend, option),
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PayjoinStatus {
	/// The session is active
	Active,
	/// The session has completed successfully
	Completed,
	/// The session has failed
	Failed,
	/// The payjoin didn't complete and the sender's fallback transaction is rebroadcast until it,
	/// or a transaction double-spending it, confirms
	FallbackPending,
}

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

impl_writeable_tlv_based_enum!(PayjoinStatus,
	(0, Active) => {},
	(2, Completed) => {},
	(4, Failed) => {},
	(6, FallbackPending) => {}
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PayjoinSessionUpdate {
	pub session_id: PaymentId,
	pub status: Option<PayjoinStatus>,
	pub completed_at: Option<Option<u64>>,
	pub resolution_txid: Option<Option<Txid>>,
}

impl From<&PayjoinSession> for PayjoinSessionUpdate {
	fn from(value: &PayjoinSession) -> Self {
		Self {
			session_id: value.session_id,
			status: Some(value.status),
			completed_at: Some(value.completed_at),
			resolution_txid: Some(value.resolution_txid),
		}
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

		if let Some(status_opt) = update.status {
			update_if_necessary!(self.status, status_opt);
		}
		if let Some(completed_at_opt) = update.completed_at {
			update_if_necessary!(self.completed_at, completed_at_opt);
		}
		if let Some(resolution_txid_opt) = update.resolution_txid {
			update_if_necessary!(self.resolution_txid, resolution_txid_opt);
		}

		if updated {
			self.latest_update_timestamp = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap_or(Duration::from_secs(0))
				.as_secs();
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
		session.status = PayjoinStatus::Completed;
		session.completed_at = Some(43);
		session.cancel_requested = true;
		session.resolution_txid = Some(txid(1));
		session.spend = Some(SessionSpend { txid: txid(1), kind: SpendKind::Payjoin });

		let decoded = PayjoinSession::read(&mut &session.encode()[..]).unwrap();
		assert_eq!(decoded, session);
	}

	#[test]
	fn stale_write_keeps_what_only_mutate_sets() {
		let stale = PayjoinSession::new(PaymentId([10; 32]), PayjoinSessionKind::Receive);
		let mut current = stale.clone();
		current.cancel_requested = true;
		current.spend = Some(SessionSpend { txid: txid(2), kind: SpendKind::Fallback });
		current.events.push(SerializedSessionEvent { event_bytes: vec![1], created_at: 1 });

		// What `insert_or_update` of a copy read before those writes applies.
		current.update(stale.to_update());
		assert!(current.cancel_requested);
		assert_eq!(current.spend, Some(SessionSpend { txid: txid(2), kind: SpendKind::Fallback }));
		assert_eq!(current.events.len(), 1);
	}

	#[test]
	fn user_status_reports_outcome_and_cancellation() {
		let fallback_txid = txid(3);
		let other_txid = txid(4);
		let status = |status, cancel_requested, fallback: bool, resolution_txid| {
			let mut session = PayjoinSession::new(PaymentId([12; 32]), PayjoinSessionKind::Receive);
			session.status = status;
			session.cancel_requested = cancel_requested;
			session.resolution_txid = resolution_txid;
			session.user_status(fallback.then_some(fallback_txid))
		};

		// A requested cancellation isn't reported until it's applied.
		assert_eq!(status(PayjoinStatus::Active, true, true, None), PayjoinSessionStatus::Active);
		assert_eq!(
			status(PayjoinStatus::Completed, false, true, Some(other_txid)),
			PayjoinSessionStatus::Completed { txid: Some(other_txid) }
		);
		// Cancelling can't undo a payjoin that completed before it was applied.
		assert_eq!(
			status(PayjoinStatus::Completed, true, true, Some(other_txid)),
			PayjoinSessionStatus::Completed { txid: Some(other_txid) }
		);
		assert_eq!(
			status(PayjoinStatus::FallbackPending, false, true, None),
			PayjoinSessionStatus::FallbackPending { fallback_txid }
		);
		assert_eq!(
			status(PayjoinStatus::Failed, false, true, Some(fallback_txid)),
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		assert_eq!(
			status(PayjoinStatus::FallbackPending, true, true, None),
			PayjoinSessionStatus::Cancelled { fallback_txid: Some(fallback_txid) }
		);
		assert_eq!(
			status(PayjoinStatus::Failed, true, false, None),
			PayjoinSessionStatus::Cancelled { fallback_txid: None }
		);
	}
}
