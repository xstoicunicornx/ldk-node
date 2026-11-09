// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{Transaction, Txid};
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

	/// The transaction to broadcast if the payjoin session fails or is aborted.
	pub fallback_tx: Option<Transaction>,

	/// Serialized session events
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
}

impl PayjoinSession {
	pub fn new(session_id: PaymentId, kind: PayjoinSessionKind) -> Self {
		let latest_update_timestamp = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(Duration::from_secs(0))
			.as_secs();
		Self {
			session_id,
			kind,
			fallback_tx: None,
			events: Vec::new(),
			status: PayjoinStatus::Active,
			completed_at: None,
			latest_update_timestamp,
			cancel_requested: false,
			resolution_txid: None,
		}
	}

	/// Returns the fallback transaction to broadcast if the payjoin doesn't complete, if known.
	pub(crate) fn fallback_tx(&self) -> Option<&Transaction> {
		self.fallback_tx.as_ref()
	}

	/// Records the fallback transaction to broadcast if the payjoin doesn't complete.
	pub(crate) fn set_fallback_tx(&mut self, tx: Transaction) {
		self.fallback_tx = Some(tx);
	}

	/// The session's status as reported to the user by [`PayjoinPayment::status`].
	///
	/// [`PayjoinPayment::status`]: crate::payment::PayjoinPayment::status
	pub(crate) fn user_status(&self) -> PayjoinSessionStatus {
		let fallback_txid = self.fallback_tx().map(|tx| tx.compute_txid());
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
	(4, fallback_tx, option),
	(6, events, required_vec),
	(8, status, required),
	(10, completed_at, option),
	(12, latest_update_timestamp, (default_value, 0u64)),
	(14, cancel_requested, (default_value, false)),
	(16, resolution_txid, option),
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
	pub fallback_tx: Option<Option<Transaction>>,
	pub events: Option<Vec<SerializedSessionEvent>>,
	pub status: Option<PayjoinStatus>,
	pub completed_at: Option<Option<u64>>,
	pub resolution_txid: Option<Option<Txid>>,
}

impl From<&PayjoinSession> for PayjoinSessionUpdate {
	fn from(value: &PayjoinSession) -> Self {
		Self {
			session_id: value.session_id,
			fallback_tx: Some(value.fallback_tx.clone()),
			events: Some(value.events.clone()),
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

		if let Some(fallback_tx_opt) = update.fallback_tx {
			update_if_necessary!(self.fallback_tx, fallback_tx_opt);
		}
		if let Some(events_opt) = &update.events {
			update_if_necessary!(self.events, events_opt.clone());
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
	use bitcoin::absolute::LockTime;
	use bitcoin::hashes::Hash;
	use bitcoin::transaction::Version;
	use bitcoin::{Amount, ScriptBuf, TxIn, TxOut};
	use lightning::util::ser::{Readable, Writeable};

	use super::*;

	fn dummy_tx() -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn::default()],
			output: vec![TxOut {
				value: Amount::from_sat(10_000),
				script_pubkey: ScriptBuf::new(),
			}],
		}
	}

	#[test]
	fn receive_session_round_trips() {
		let mut session = PayjoinSession::new(PaymentId([7; 32]), PayjoinSessionKind::Receive);
		assert_eq!(session.fallback_tx(), None);

		session.set_fallback_tx(dummy_tx());
		session.events.push(SerializedSessionEvent { event_bytes: vec![1, 2, 3], created_at: 42 });
		session.status = PayjoinStatus::Completed;
		session.completed_at = Some(43);

		let decoded = PayjoinSession::read(&mut &session.encode()[..]).unwrap();
		assert_eq!(decoded, session);
		assert_eq!(decoded.fallback_tx(), Some(&dummy_tx()));
	}

	#[test]
	fn fallback_pending_session_round_trips() {
		let mut session = PayjoinSession::new(PaymentId([8; 32]), PayjoinSessionKind::Receive);
		session.set_fallback_tx(dummy_tx());
		session.status = PayjoinStatus::FallbackPending;
		session.completed_at = Some(44);

		let decoded = PayjoinSession::read(&mut &session.encode()[..]).unwrap();
		assert_eq!(decoded.status, PayjoinStatus::FallbackPending);
		assert_eq!(decoded.fallback_tx(), Some(&dummy_tx()));
	}

	#[test]
	fn cancel_and_resolution_round_trip() {
		let mut session = PayjoinSession::new(PaymentId([9; 32]), PayjoinSessionKind::Receive);
		session.cancel_requested = true;
		session.resolution_txid = Some(dummy_tx().compute_txid());

		let decoded = PayjoinSession::read(&mut &session.encode()[..]).unwrap();
		assert_eq!(decoded, session);
	}

	#[test]
	fn stale_write_keeps_cancel_request() {
		let stale = PayjoinSession::new(PaymentId([10; 32]), PayjoinSessionKind::Receive);
		let mut current = stale.clone();
		current.cancel_requested = true;

		// What `insert_or_update` of a copy read before the request applies.
		current.update(stale.to_update());
		assert!(current.cancel_requested);
	}

	#[test]
	fn user_status_reports_outcome_and_cancellation() {
		let fallback_txid = dummy_tx().compute_txid();
		let other_txid = Txid::from_byte_array([11; 32]);
		let session = |status, cancel_requested, fallback: bool, resolution_txid| {
			let mut session = PayjoinSession::new(PaymentId([12; 32]), PayjoinSessionKind::Receive);
			session.status = status;
			session.cancel_requested = cancel_requested;
			if fallback {
				session.set_fallback_tx(dummy_tx());
			}
			session.resolution_txid = resolution_txid;
			session.user_status()
		};

		// A requested cancellation isn't reported until it's applied.
		assert_eq!(session(PayjoinStatus::Active, true, true, None), PayjoinSessionStatus::Active);
		assert_eq!(
			session(PayjoinStatus::Completed, false, true, Some(other_txid)),
			PayjoinSessionStatus::Completed { txid: Some(other_txid) }
		);
		// Cancelling can't undo a payjoin that completed before it was applied.
		assert_eq!(
			session(PayjoinStatus::Completed, true, true, Some(other_txid)),
			PayjoinSessionStatus::Completed { txid: Some(other_txid) }
		);
		assert_eq!(
			session(PayjoinStatus::FallbackPending, false, true, None),
			PayjoinSessionStatus::FallbackPending { fallback_txid }
		);
		assert_eq!(
			session(PayjoinStatus::Failed, false, true, Some(fallback_txid)),
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		assert_eq!(
			session(PayjoinStatus::FallbackPending, true, true, None),
			PayjoinSessionStatus::Cancelled { fallback_txid: Some(fallback_txid) }
		);
		assert_eq!(
			session(PayjoinStatus::Failed, true, false, None),
			PayjoinSessionStatus::Cancelled { fallback_txid: None }
		);
	}
}
