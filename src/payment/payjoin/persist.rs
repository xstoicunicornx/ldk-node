// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::sync::Arc;

use bitcoin::{Transaction, Txid};
use lightning::ln::channelmanager::PaymentId;
use payjoin::persist::AsyncSessionPersister;
use payjoin::receive::v2::{
	replay_event_log_async as replay_receiver_event_log_async, SessionEvent as ReceiverSessionEvent,
};

use crate::logger::{log_error, LdkLogger, Logger};
use crate::payment::payjoin::payjoin_session::{
	PayjoinSession, PayjoinSessionKind, SerializedSessionEvent, SessionResolution, SessionSpend,
};
use crate::payment::payjoin::replay::Replayed;
use crate::payment::payjoin::{unix_now, PayjoinSessionStatus};
use crate::types::PayjoinSessionStore;
use crate::Error;

/// Reads and writes the record and event log of one payjoin receive session.
pub(crate) struct KVStorePayjoinReceiverPersister {
	session_id: PaymentId,
	payjoin_session_store: Arc<PayjoinSessionStore>,
	/// For a new session. `None` for a session that already exists.
	new_session: Option<PayjoinSession>,
	logger: Arc<Logger>,
}

impl KVStorePayjoinReceiverPersister {
	pub fn new(
		session_id: PaymentId, payjoin_session_store: Arc<PayjoinSessionStore>, logger: Arc<Logger>,
	) -> Self {
		let new_session = PayjoinSession::new(session_id, PayjoinSessionKind::Receive);

		Self { session_id, payjoin_session_store, new_session: Some(new_session), logger }
	}

	pub fn session_id(&self) -> PaymentId {
		self.session_id
	}

	/// The session's record, or [`Error::InvalidPaymentId`] if there is none.
	pub async fn get_session(&self) -> Result<PayjoinSession, Error> {
		self.payjoin_session_store.get(&self.session_id).await?.ok_or(Error::InvalidPaymentId)
	}

	/// For a session that already exists. Reading or writing the session's log fails with
	/// [`Error::InvalidPaymentId`] if its record is gone.
	pub fn for_existing(
		session_id: PaymentId, payjoin_session_store: Arc<PayjoinSessionStore>, logger: Arc<Logger>,
	) -> Self {
		Self { session_id, payjoin_session_store, new_session: None, logger }
	}

	/// The session's status as reported to the user, or `None` if there is no such session.
	pub async fn status(&self) -> Result<Option<PayjoinSessionStatus>, Error> {
		let session = match self.get_session().await {
			Ok(session) => session,
			Err(Error::InvalidPaymentId) => return Ok(None),
			Err(e) => return Err(e),
		};
		// Only a running session pending its fallback, or a cancelled one, reports the fallback,
		// which takes replaying the session.
		let fallback_txid = if session.is_running() || session.cancel_requested {
			let replayed = self.replay().await;
			let fallback = if session.is_running() {
				replayed.pending_fallback()
			} else {
				replayed.fallback()
			};
			fallback.map(Transaction::compute_txid)
		} else {
			None
		};
		Ok(Some(session.user_status(fallback_txid)))
	}

	/// Replays the session's event log, along with the session's fallback transaction, if it
	/// received the sender's original.
	pub async fn replay(&self) -> Replayed {
		match replay_receiver_event_log_async(self).await {
			Ok((state, history)) => Replayed::Open(state, history.fallback_tx()),
			Err(e) if e.is_expired() => Replayed::Expired(e.expiry_fallback_tx().cloned()),
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to replay payjoin session {}: {:?}",
					self.session_id,
					e
				);
				Replayed::Unreadable
			},
		}
	}

	/// Flags the session for cancellation, unless it was already. Fails with
	/// [`Error::PayjoinSessionNotCancellable`] if the session isn't running or wallet sync saw a
	/// spend of the sender's inputs, which the session settles on instead.
	///
	/// Set atomically, so a session ending meanwhile isn't flagged.
	pub async fn request_cancel(&self) -> Result<(), Error> {
		let mut outcome = Err(Error::InvalidPaymentId);
		self.payjoin_session_store
			.mutate(&self.session_id, |existing| {
				let existing = existing?;
				if existing.cancel_requested {
					outcome = Ok(());
					return None;
				}
				if !existing.is_cancellable() {
					outcome = Err(Error::PayjoinSessionNotCancellable);
					return None;
				}
				outcome = Ok(());
				let mut session = existing.clone();
				session.cancel_requested = true;
				Some(session)
			})
			.await?;
		outcome
	}

	/// Records a spend of the sender's inputs that the session waits on to be buried, in place of
	/// any other pending one, unless the session isn't running. Returns whether it was recorded,
	/// which it isn't if it was already.
	pub async fn record_pending(&self, spend: SessionSpend) -> Result<bool, Error> {
		let pending = Some(SessionResolution::Pending(spend));
		let recorded = self
			.payjoin_session_store
			.mutate(&self.session_id, |existing| {
				let existing = existing?;
				(existing.is_running() && existing.resolution != pending).then(|| {
					let mut session = existing.clone();
					session.resolution = pending.clone();
					session
				})
			})
			.await?;
		Ok(recorded.is_some())
	}

	/// Clears the session's pending spend if it's one of `txids`. A settled spend stays, even if a
	/// deep reorg drops it. Returns whether it was cleared.
	pub async fn clear_pending(&self, txids: &[Txid]) -> Result<bool, Error> {
		let cleared = self
			.payjoin_session_store
			.mutate(&self.session_id, |existing| {
				let existing = existing?;
				existing.is_pending_on_any(txids).then(|| {
					let mut session = existing.clone();
					session.resolution = None;
					session
				})
			})
			.await?;
		Ok(cleared.is_some())
	}

	/// Records the spend that settled the session, in place of any pending one, unless the
	/// session isn't running. Returns whether it was.
	pub async fn settle(&self, spend: SessionSpend) -> Result<bool, Error> {
		let mut recorded = false;
		self.payjoin_session_store
			.mutate(&self.session_id, |existing| {
				let existing = existing?;
				if !existing.is_running() {
					return None;
				}
				recorded = true;
				let mut session = existing.clone();
				session.resolution = Some(SessionResolution::Settled(spend.clone()));
				Some(session)
			})
			.await?;
		Ok(recorded)
	}
}

impl AsyncSessionPersister for KVStorePayjoinReceiverPersister {
	type SessionEvent = ReceiverSessionEvent;
	type InternalStorageError = Error;

	fn save_event(
		&self, event: Self::SessionEvent,
	) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
		async move {
			let event_bytes = serde_json::to_vec(&event).map_err(|_| Error::PersistenceFailed)?;

			let event = SerializedSessionEvent { event_bytes, created_at: unix_now() };

			let new_session = self.new_session.clone();
			let mut closed = false;
			self.payjoin_session_store
				.mutate(&self.session_id, |existing| {
					// Create the record with its first event if it doesn't exist yet
					let mut session = existing.cloned().or(new_session)?;
					// Nothing follows a session's close, or its log would no longer replay. Both
					// the resume task and wallet sync can close a session, so the second to try
					// is refused here.
					closed = session.events.last().is_some_and(|last| {
						matches!(
							serde_json::from_slice(&last.event_bytes),
							Ok(ReceiverSessionEvent::Closed(_))
						)
					});
					if closed {
						return None;
					}
					session.events.push(event);
					Some(session)
				})
				.await?
				.ok_or(if closed {
					Error::PayjoinSessionFailed
				} else {
					Error::InvalidPaymentId
				})?;

			Ok(())
		}
	}

	fn load(
		&self,
	) -> impl std::future::Future<
		Output = Result<
			Box<dyn Iterator<Item = Self::SessionEvent> + Send>,
			Self::InternalStorageError,
		>,
	> + Send {
		async move {
			let session = self.get_session().await?;

			let events: Vec<ReceiverSessionEvent> = session
				.events
				.iter()
				.map(|e| serde_json::from_slice(&e.event_bytes))
				.collect::<Result<Vec<_>, _>>()
				.map_err(|_| Error::PersistenceFailed)?;

			Ok(Box::new(events.into_iter()) as Box<dyn Iterator<Item = Self::SessionEvent> + Send>)
		}
	}

	/// Records when the session ended, unless an earlier close already did. Until then, the
	/// session is open.
	///
	/// Only `completed_at` is set, atomically, so a write of the record meanwhile isn't undone.
	fn close(
		&self,
	) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
		async move {
			let now = unix_now();
			let mut found = false;
			self.payjoin_session_store
				.mutate(&self.session_id, |existing| {
					let existing = existing?;
					found = true;
					existing.completed_at.is_none().then(|| {
						let mut session = existing.clone();
						session.completed_at = Some(now);
						session
					})
				})
				.await?;
			if !found {
				return Err(Error::InvalidPaymentId);
			}
			Ok(())
		}
	}
}
