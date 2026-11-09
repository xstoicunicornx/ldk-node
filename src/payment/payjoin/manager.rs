// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{psbt::Input, Amount, BlockHash, FeeRate, Transaction, TxIn, Txid};

use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
use lightning::ln::channelmanager::PaymentId;
use lightning::log_warn;

use payjoin::io::fetch_ohttp_keys;
use payjoin::persist::{OptionalTransitionOutcome, PersistedError};
use payjoin::receive::v2::{
	replay_event_log_async as replay_receiver_event_log_async, CreateRequestError,
	HasReplyableError, Initialized, MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown,
	PayjoinProposal, ProvisionalProposal, ReceiveSession, Receiver, ReceiverBuilder, Resolution,
	ResolvedBy, SessionOutcome as ReceiverSessionOutcome, UncheckedOriginalPayload, WantsFeeRange,
	WantsInputs, WantsOutputs,
};
use payjoin::receive::InputPair;

use crate::chain::ChainSource;
use crate::config::{
	Config, PayjoinConfig, PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS, PAYJOIN_MAX_RESPONSE_BYTES,
	PAYJOIN_RELAY_TIMEOUT_SECS, PAYJOIN_RETRY_DELAY, PAYJOIN_SEEN_INPUT_RETENTION_SECS,
	PAYJOIN_SESSION_CLEANUP_AGE_SECS,
};
use crate::fee_estimator::{ConfirmationTarget, FeeEstimator, OnchainFeeEstimator};
use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::payment::payjoin::payjoin_session::{
	PayjoinSessionKind, PayjoinStatus, SessionSpend, SpendKind,
};
use crate::payment::payjoin::persist::KVStorePayjoinReceiverPersister;
use crate::payment::payjoin::seen_inputs::{
	check_and_record_seen_input, forget_seen_inputs, prune_seen_inputs,
};
use crate::payment::payjoin::PayjoinSessionStatus;
use crate::payment::store::TransactionType;

use crate::types::{Broadcaster, PayjoinSeenInputsStore, PayjoinSessionStore};
use crate::wallet::Wallet;
use crate::Error;

/// The result of opening a Payjoin receive session.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PayjoinReceiveSession {
	/// The BIP 21 URI to share with the sender.
	pub uri: String,
	/// Identifier for this session
	pub session_id: PaymentId,
}

#[derive(Clone)]
pub(crate) struct PayjoinManager {
	payjoin_session_store: Arc<PayjoinSessionStore>,
	payjoin_seen_inputs_store: Arc<PayjoinSeenInputsStore>,
	logger: Arc<Logger>,
	config: Arc<Config>,
	wallet: Arc<Wallet>,
	fee_estimator: Arc<OnchainFeeEstimator>,
	chain_source: Arc<ChainSource>,
	broadcaster: Arc<Broadcaster>,
	session_retry_at: Arc<Mutex<HashMap<PaymentId, Instant>>>,
	/// The wallet's chain tip when pending fallbacks were last rebroadcast. `None` until the
	/// first pass after startup, which rebroadcasts what a restart dropped from the queue.
	fallback_rebroadcast_tip: Arc<Mutex<Option<BlockHash>>>,
}

impl PayjoinManager {
	pub(crate) fn new(
		payjoin_session_store: Arc<PayjoinSessionStore>,
		payjoin_seen_inputs_store: Arc<PayjoinSeenInputsStore>, logger: Arc<Logger>,
		config: Arc<Config>, wallet: Arc<Wallet>, fee_estimator: Arc<OnchainFeeEstimator>,
		chain_source: Arc<ChainSource>, broadcaster: Arc<Broadcaster>,
	) -> Self {
		Self {
			payjoin_session_store,
			payjoin_seen_inputs_store,
			logger,
			config,
			wallet,
			fee_estimator,
			chain_source,
			broadcaster,
			session_retry_at: Arc::new(Mutex::new(HashMap::new())),
			fallback_rebroadcast_tip: Arc::new(Mutex::new(None)),
		}
	}

	pub(crate) async fn receive_payjoin(
		&self, amount_sats: u64, fee_rate: Option<FeeRate>,
	) -> Result<PayjoinReceiveSession, Error> {
		let payjoin_config =
			self.config.payjoin_config.as_ref().ok_or(Error::PayjoinNotConfigured)?;

		// Generate a new session ID
		let mut random_bytes = [0u8; 32];
		getrandom::fill(&mut random_bytes).map_err(|e| {
			log_error!(self.logger, "Failed to generate random session ID: {}", e);
			Error::PayjoinSessionCreationFailed
		})?;
		let session_id = PaymentId(random_bytes);

		let confirmation_target = ConfirmationTarget::OnchainPayment;
		let fee_rate =
			fee_rate.unwrap_or_else(|| self.fee_estimator.estimate_fee_rate(confirmation_target));

		let ohttp_keys = {
			let mut result = Err(Error::ConnectionFailed);
			for relay in self.relay_order(payjoin_config)? {
				match fetch_ohttp_keys(relay, payjoin_config.payjoin_directory.as_str()).await {
					Ok(keys) => {
						result = Ok(keys);
						break;
					},
					Err(e) => {
						log_error!(
							self.logger,
							"Failed to fetch OHTTP keys via {}: {}. Trying next relay.",
							relay,
							e
						);
					},
				}
			}
			result
		}?;
		log_debug!(self.logger, "Fetched OHTTP keys: {:?}", ohttp_keys);

		let amount = Amount::from_sat(amount_sats);

		// Revealed only once the OHTTP keys are in hand, so a failed fetch doesn't use up an address.
		let address = self.wallet.get_new_address().await?;

		// Create a new persister for this session
		let persister = KVStorePayjoinReceiverPersister::new(
			session_id,
			Arc::clone(&self.payjoin_session_store),
		);

		let session =
			ReceiverBuilder::new(address, payjoin_config.payjoin_directory.as_str(), ohttp_keys)
				.map_err(|e| {
					log_error!(self.logger, "Failed to create receiver builder: {}", e);
					Error::PayjoinSessionCreationFailed
				})?
				.with_amount(amount)
				.with_max_fee_rate(fee_rate)
				.build()
				.save_async(&persister)
				.await
				.map_err(|e| {
					log_error!(self.logger, "Failed to persist the new payjoin session: {:?}", e);
					Error::PersistenceFailed
				})?;

		log_info!(self.logger, "Receive session established");
		let pj_uri = session.pj_uri();

		Ok(PayjoinReceiveSession { uri: pj_uri.to_string(), session_id })
	}

	fn relay_order<'a>(&self, payjoin_config: &'a PayjoinConfig) -> Result<Vec<&'a str>, Error> {
		let count = payjoin_config.ohttp_relays.len();
		let start = if count > 0 {
			let mut bytes = [0u8; 8];
			getrandom::fill(&mut bytes).map_err(|e| {
				log_error!(self.logger, "Failed to generate random relay index: {}", e);
				Error::PayjoinSessionFailed
			})?;
			u64::from_ne_bytes(bytes) as usize % count
		} else {
			0
		};
		Ok((0..count).map(|i| payjoin_config.ohttp_relays[(start + i) % count].as_str()).collect())
	}

	async fn process_receiver_session(
		&self, mut session: ReceiveSession, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<(), Error> {
		if persister.get_session().await?.cancel_requested {
			let Some(next) = self.apply_cancel(session, persister).await? else {
				return Ok(());
			};
			session = next;
		}
		loop {
			session = match session {
				ReceiveSession::Initialized(proposal) => {
					match self.read_from_directory(proposal, persister).await? {
						// No sender yet. Yield so the resume task can service other sessions;
						// the next tick re-enters this session where it left off.
						ReceiveSession::Initialized(_) => return Ok(()),
						next => next,
					}
				},
				ReceiveSession::UncheckedOriginalPayload(proposal) => {
					self.check_original_payload(proposal, persister).await?
				},
				ReceiveSession::MaybeInputsOwned(proposal) => {
					self.check_inputs_not_owned(proposal, persister).await?
				},
				ReceiveSession::MaybeInputsSeen(proposal) => {
					self.check_no_inputs_seen_before(proposal, persister).await?
				},
				ReceiveSession::OutputsUnknown(proposal) => {
					self.identify_receiver_outputs(proposal, persister).await?
				},
				ReceiveSession::WantsOutputs(proposal) => {
					self.commit_outputs(proposal, persister).await?
				},
				ReceiveSession::WantsInputs(proposal) => {
					self.contribute_inputs(proposal, persister).await?
				},
				ReceiveSession::WantsFeeRange(proposal) => {
					self.apply_fee_range(proposal, persister).await?
				},
				ReceiveSession::ProvisionalProposal(proposal) => {
					self.finalize_proposal(proposal, persister).await?
				},
				ReceiveSession::PayjoinProposal(proposal) => {
					self.send_payjoin_proposal(proposal, persister).await?
				},
				ReceiveSession::HasReplyableError(error) => {
					self.handle_error(error, persister).await?
				},
				ReceiveSession::Monitor(_) => {
					// Wallet sync settles the session once it sees a transaction spending the
					// sender's inputs buried, so there is nothing to do until then.
					log_debug!(
						self.logger,
						"Payjoin session {} is waiting for the sender to broadcast.",
						persister.session_id()
					);
					return Ok(());
				},
				ReceiveSession::PendingFallback(pending) => {
					let fallback_tx = pending.fallback_tx().clone();
					self.close_session_with_fallback(persister.session_id(), Some(fallback_tx))
						.await;

					pending.close().save_async(persister).await?;
					return Ok(());
				},
				ReceiveSession::Closed(outcome) => {
					return self.handle_closed_session(outcome, persister).await;
				},
			}
		}
	}

	/// Applies a cancellation requested through [`Self::cancel_session`].
	///
	/// Only runs for a session that wallet sync saw no spend of the sender's inputs for, since
	/// such a session isn't resumed. Returns the session to keep processing: [`ReceiveSession::PendingFallback`]
	/// if the session had the sender's fallback, so it is broadcast like that of a failed payjoin,
	/// or the session unchanged if it is ending already. Returns `None` if the session closed.
	async fn apply_cancel(
		&self, session: ReceiveSession, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ReceiveSession>, Error> {
		let pending = match session {
			ReceiveSession::Initialized(r) => {
				self.close_cancelled_session(persister).await?;
				r.cancel().save_async(persister).await?;
				return Ok(None);
			},
			ReceiveSession::UncheckedOriginalPayload(r) => {
				self.close_cancelled_session(persister).await?;
				r.cancel().save_async(persister).await?;
				return Ok(None);
			},
			// Whether there's a fallback to broadcast is only known from the transition.
			ReceiveSession::HasReplyableError(r) => match r.cancel().save_async(persister).await? {
				Some(pending) => pending,
				None => {
					self.close_cancelled_session(persister).await?;
					return Ok(None);
				},
			},
			ReceiveSession::MaybeInputsOwned(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::MaybeInputsSeen(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::OutputsUnknown(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::WantsOutputs(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::WantsInputs(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::WantsFeeRange(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::ProvisionalProposal(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::PayjoinProposal(r) => r.cancel().save_async(persister).await?,
			ReceiveSession::Monitor(r) => r.cancel().save_async(persister).await?,
			session @ (ReceiveSession::PendingFallback(_) | ReceiveSession::Closed(_)) => {
				return Ok(Some(session));
			},
		};
		log_info!(
			self.logger,
			"Cancelled payjoin session {}. Broadcasting the sender's fallback transaction.",
			persister.session_id()
		);
		Ok(Some(ReceiveSession::PendingFallback(pending)))
	}

	/// Marks a cancelled session that has no fallback to broadcast as [`PayjoinStatus::Failed`].
	///
	/// Our record goes first, as in [`Self::settle_session`]: a session that isn't active is never
	/// replayed, so it doesn't matter if persisting the close event fails afterwards.
	async fn close_cancelled_session(
		&self, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<(), Error> {
		let mut session = persister.get_session().await?;
		session.status = PayjoinStatus::Failed;
		session.completed_at.get_or_insert_with(|| {
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
		});
		self.payjoin_session_store.insert_or_update(session).await?;
		log_info!(self.logger, "Cancelled payjoin session {}.", persister.session_id());
		Ok(())
	}

	/// Returns the status of the session `session_id`, or `None` if there is no such session.
	pub(crate) async fn session_status(
		&self, session_id: PaymentId,
	) -> Result<Option<PayjoinSessionStatus>, Error> {
		let Some(session) = self.payjoin_session_store.get(&session_id).await? else {
			return Ok(None);
		};
		// Only these report the fallback, which takes replaying the session.
		let reports_fallback = session.status == PayjoinStatus::FallbackPending
			|| (session.status == PayjoinStatus::Failed && session.cancel_requested);
		let fallback_txid = match self.persister(session_id).await {
			Some(persister) if reports_fallback => {
				self.session_fallback(&persister).await.map(|tx| tx.compute_txid())
			},
			_ => None,
		};
		Ok(Some(session.user_status(fallback_txid)))
	}

	/// Requests the cancellation of the session `session_id`, which the resume task applies.
	///
	/// See [`PayjoinPayment::cancel`].
	///
	/// [`PayjoinPayment::cancel`]: crate::payment::PayjoinPayment::cancel
	pub(crate) async fn cancel_session(&self, session_id: PaymentId) -> Result<(), Error> {
		let session =
			self.payjoin_session_store.get(&session_id).await?.ok_or(Error::InvalidPaymentId)?;
		if session.cancel_requested {
			return Ok(());
		}
		// Once wallet sync saw something spend the sender's inputs, the session settles on that,
		// so cancelling would change nothing.
		if session.status != PayjoinStatus::Active || session.spend.is_some() {
			return Err(Error::PayjoinSessionNotCancellable);
		}

		// Set atomically, so a session ending meanwhile isn't flagged.
		let mut outcome = Err(Error::InvalidPaymentId);
		self.payjoin_session_store
			.mutate(&session_id, |existing| {
				let existing = existing?;
				if existing.cancel_requested {
					outcome = Ok(());
					return None;
				}
				if existing.status != PayjoinStatus::Active || existing.spend.is_some() {
					outcome = Err(Error::PayjoinSessionNotCancellable);
					return None;
				}
				outcome = Ok(());
				let mut session = existing.clone();
				session.cancel_requested = true;
				Some(session)
			})
			.await?;
		outcome?;

		// Apply it on the next resume rather than after a backoff.
		self.session_retry_at.lock().expect("lock").remove(&session_id);
		log_info!(self.logger, "Requested the cancellation of payjoin session {}.", session_id);
		Ok(())
	}

	/// Reports transactions wallet sync saw, new or newly confirmed, to the active sessions.
	///
	/// Each is classified against each session. One spending the sender's inputs is recorded as
	/// the session's [`spend`], which pauses the session, and a payjoin is tagged as such on its
	/// payment. The session settles once that spend is buried, which [`Self::on_tx_buried`]
	/// reports.
	///
	/// [`spend`]: crate::payment::payjoin::payjoin_session::PayjoinSession::spend
	pub(crate) async fn on_txs_seen(&self, txs: &[Arc<Transaction>]) -> Result<(), Error> {
		if txs.is_empty() {
			return Ok(());
		}
		let sessions =
			self.payjoin_session_store.list_filter(|s| s.status == PayjoinStatus::Active).await;
		for session in sessions {
			let session_id = session.session_id;
			let Some(persister) = self.persister(session_id).await else {
				continue;
			};
			// An expired or unreadable session is closed by the resume task, not settled here.
			let Replayed::Open(state, _) = self.replay(&persister).await else {
				continue;
			};
			for tx in txs {
				let Some(resolution) = state.classify_tx(tx) else {
					continue;
				};
				let txid = tx.compute_txid();
				let kind = spend_kind(resolution.resolved_by());
				if kind == SpendKind::Payjoin {
					self.wallet.classify_payjoin(txid, Some(tx)).await?;
				}
				let recorded =
					self.payjoin_session_store
						.mutate(&session_id, |existing| {
							let existing = existing?;
							let spend = Some(SessionSpend { txid, kind });
							(existing.status == PayjoinStatus::Active && existing.spend != spend)
								.then(|| {
									let mut session = existing.clone();
									session.spend = spend;
									session
								})
						})
						.await?;
				if recorded.is_none() {
					continue;
				}
				log_info!(
					self.logger,
					"Payjoin session {} saw {:?} transaction {} spend the sender's inputs. It settles once that's buried.",
					session_id,
					kind,
					txid
				);
			}
		}
		Ok(())
	}

	/// Reports transactions wallet sync saw dropped or replaced, which unpauses the sessions that
	/// were waiting on them to be buried.
	pub(crate) async fn on_txs_gone(&self, txids: &[Txid]) -> Result<(), Error> {
		if txids.is_empty() {
			return Ok(());
		}
		let waiting = self
			.payjoin_session_store
			.list_filter(|s| s.spend.as_ref().is_some_and(|spend| txids.contains(&spend.txid)))
			.await;
		for session in waiting {
			self.payjoin_session_store
				.mutate(&session.session_id, |existing| {
					let existing = existing?;
					existing.spend.as_ref().is_some_and(|spend| txids.contains(&spend.txid)).then(
						|| {
							let mut session = existing.clone();
							session.spend = None;
							session
						},
					)
				})
				.await?;
			log_info!(
				self.logger,
				"The transaction payjoin session {} was waiting on is gone. Resuming the session.",
				session.session_id
			);
		}
		Ok(())
	}

	/// Reports a transaction wallet sync saw confirmed through [`ANTI_REORG_DELAY`], which settles
	/// the sessions whose sender inputs it spends.
	///
	/// An active session classifies it, and its log is closed with the result. A session that
	/// can't classify it, because its log is closed already pending the fallback, or it expired,
	/// settles on the fallback's inputs being spent instead.
	pub(crate) async fn on_tx_buried(&self, txid: Txid) -> Result<(), Error> {
		let sessions = self
			.payjoin_session_store
			.list_filter(|s| {
				s.status == PayjoinStatus::Active || s.status == PayjoinStatus::FallbackPending
			})
			.await;
		if sessions.is_empty() {
			return Ok(());
		}
		// Checked here rather than taken from the caller, which reports it from a snapshot.
		let Some((tx, confirmations)) = self.wallet.tx_with_confirmations(txid) else {
			return Ok(());
		};
		if confirmations < ANTI_REORG_DELAY {
			return Ok(());
		}

		for session in sessions {
			let Some(persister) = self.persister(session.session_id).await else {
				continue;
			};
			match self.replay(&persister).await {
				Replayed::Open(state, fallback) if session.status == PayjoinStatus::Active => {
					match state.classify_tx(&tx) {
						Some(resolution) => {
							self.settle_session(&persister, state, fallback, &tx, resolution)
								.await?
						},
						// The session can't classify in its current state, e.g. pending the
						// fallback because the resume task hasn't broadcast it yet.
						None => {
							if let Some(fallback) = fallback {
								self.settle_on_fallback_inputs(session.session_id, &tx, &fallback)
									.await?
							}
						},
					}
				},
				Replayed::Open(_, Some(fallback)) | Replayed::Expired(Some(fallback)) => {
					self.settle_on_fallback_inputs(session.session_id, &tx, &fallback).await?
				},
				_ => {},
			}
		}
		Ok(())
	}

	/// Settles an active session on `tx`, which spends the sender's inputs and is confirmed
	/// through [`ANTI_REORG_DELAY`], as classified against the session.
	async fn settle_session(
		&self, persister: &KVStorePayjoinReceiverPersister, state: ReceiveSession,
		fallback: Option<Transaction>, tx: &Transaction, resolution: Resolution,
	) -> Result<(), Error> {
		let session_id = persister.session_id();
		let txid = tx.compute_txid();
		let kind = spend_kind(resolution.resolved_by());
		// Wallet sync records a replacement in the record of what it replaced, so the record
		// holding `tx` may carry the tag of a payjoin it replaced.
		if kind == SpendKind::Payjoin {
			self.wallet.classify_payjoin(txid, Some(tx)).await?;
		} else {
			self.wallet.untag_payjoin(txid).await?;
		}

		// A spend that lost to this one can no longer confirm, but wallet sync leaves its payment
		// pending if it dropped the loser before seeing the winner, rather than recording the
		// winner as its replacement.
		for lost in self.wallet.lost_conflicts_of(tx) {
			let Some(lost_resolution) = state.classify_tx(&lost) else {
				// Lost on one of our own inputs, not the sender's.
				continue;
			};
			let tx_type = (lost_resolution.resolved_by() == ResolvedBy::Payjoin)
				.then_some(TransactionType::Payjoin);
			self.wallet.fail_payment_lost_to_conflict(lost.compute_txid(), tx_type).await?;
		}
		if let Some(fallback) = &fallback {
			self.forget_spent_sender_inputs(tx, fallback).await;
		}

		let status = match kind {
			SpendKind::Payjoin => PayjoinStatus::Completed,
			SpendKind::Fallback | SpendKind::Unrecognized => PayjoinStatus::Failed,
		};
		// Our record goes first: resumption only picks up active sessions, so if persisting the
		// close event fails afterwards, the session is still never replayed.
		if !self.settle_record(session_id, &[PayjoinStatus::Active], status, Some(txid)).await? {
			return Ok(());
		}
		log_info!(
			self.logger,
			"Payjoin session {} settled as {:?}: {:?} transaction {} is buried.",
			session_id,
			status,
			kind,
			txid
		);

		if let Err(e) = state.close(resolution).save_async(persister).await {
			log_error!(
				self.logger,
				"Failed to record the close of payjoin session {}: {:?}",
				session_id,
				e
			);
		}
		Ok(())
	}

	/// Settles a session that can't classify `tx`, which is confirmed through
	/// [`ANTI_REORG_DELAY`], on whether it spends the inputs of the session's `fallback`.
	async fn settle_on_fallback_inputs(
		&self, session_id: PaymentId, tx: &Transaction, fallback: &Transaction,
	) -> Result<(), Error> {
		if !spends_any_input_of(tx, fallback) {
			return Ok(());
		}
		let txid = tx.compute_txid();
		// Only the fallback can be told apart from the payjoin without classifying.
		if txid == fallback.compute_txid() {
			self.wallet.untag_payjoin(txid).await?;
		}
		self.fail_lost_spends(tx, fallback).await?;
		self.forget_spent_sender_inputs(tx, fallback).await;
		let settled = self
			.settle_record(
				session_id,
				&[PayjoinStatus::Active, PayjoinStatus::FallbackPending],
				PayjoinStatus::Failed,
				Some(txid),
			)
			.await?;
		if settled {
			log_info!(
				self.logger,
				"Payjoin session {} failed: transaction {} spending the sender's inputs is buried.",
				session_id,
				txid
			);
		}
		Ok(())
	}

	/// Moves session `session_id` to the terminal `status`, recording `resolution_txid` as what
	/// settled it, if it's still in one of `from`. Returns whether it was.
	async fn settle_record(
		&self, session_id: PaymentId, from: &[PayjoinStatus], status: PayjoinStatus,
		resolution_txid: Option<Txid>,
	) -> Result<bool, Error> {
		let now = unix_now();
		let mut settled = false;
		self.payjoin_session_store
			.mutate(&session_id, |existing| {
				let existing = existing?;
				if !from.contains(&existing.status) {
					return None;
				}
				settled = true;
				let mut session = existing.clone();
				session.status = status;
				session.resolution_txid = resolution_txid;
				session.completed_at.get_or_insert(now);
				Some(session)
			})
			.await?;
		Ok(settled)
	}

	async fn persister(&self, session_id: PaymentId) -> Option<KVStorePayjoinReceiverPersister> {
		KVStorePayjoinReceiverPersister::from_session(
			session_id,
			Arc::clone(&self.payjoin_session_store),
		)
		.await
		.ok()
	}

	/// Replays a session's event log, along with the session's fallback transaction, if it
	/// received the sender's original.
	async fn replay(&self, persister: &KVStorePayjoinReceiverPersister) -> Replayed {
		match replay_receiver_event_log_async(persister).await {
			Ok((state, history)) => Replayed::Open(state, history.fallback_tx()),
			Err(e) if e.is_expired() => Replayed::Expired(e.expiry_fallback_tx().cloned()),
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to replay payjoin session {}: {:?}",
					persister.session_id(),
					e
				);
				Replayed::Unreadable
			},
		}
	}

	/// The fallback transaction of the session `persister` is for, if it received the sender's
	/// original and its log can be replayed.
	async fn session_fallback(
		&self, persister: &KVStorePayjoinReceiverPersister,
	) -> Option<Transaction> {
		match self.replay(persister).await {
			Replayed::Open(_, fallback) | Replayed::Expired(fallback) => fallback,
			Replayed::Unreadable => None,
		}
	}

	async fn read_from_directory(
		&self, session: Receiver<Initialized>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let Some((ohttp_response, context)) =
			self.post_via_relay(|relay| session.create_poll_request(relay)).await?
		else {
			log_info!(self.logger, "Payjoin session {} expired.", persister.session_id());
			return Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted));
		};

		let state_transition = session
			.process_response(ohttp_response.as_bytes(), context)
			.save_async(persister)
			.await;

		match state_transition {
			Ok(OptionalTransitionOutcome::Progress(next_state)) => {
				log_info!(
					self.logger,
					"Got a request from the sender. Responding with a Payjoin proposal."
				);
				Ok(ReceiveSession::UncheckedOriginalPayload(next_state))
			},
			Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
				Ok(ReceiveSession::Initialized(current_state))
			},
			Err(e) if e.is_transient() => {
				log_debug!(self.logger, "Transient error polling for request, retrying: {e:?}");
				let session = e.transient_state().expect("transient error carries current state");
				Ok(ReceiveSession::Initialized(session))
			},
			// The directory's response was fatal, so payjoin closed the session's log.
			Err(e) if e.is_fatal() => {
				log_error!(self.logger, "Payjoin directory rejected the session: {:?}", e);
				Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted))
			},
			Err(e) => Err(self.step_error("process the sender's directory response", &e)),
		}
	}

	async fn post_request(&self, req: payjoin::Request) -> Result<bitreq::Response, Error> {
		let response = bitreq::post(req.url)
			.with_header("Content-Type", req.content_type)
			.with_body(req.body)
			.with_timeout(PAYJOIN_RELAY_TIMEOUT_SECS)
			.with_max_body_size(PAYJOIN_MAX_RESPONSE_BYTES)
			.send_async()
			.await
			.map_err(|e| {
				log_error!(self.logger, "HTTP request failed: {}", e);
				Error::ConnectionFailed
			})?;

		if !(200..300).contains(&response.status_code) {
			log_error!(
				self.logger,
				"Relay returned status {} for payjoin request.",
				response.status_code
			);
			return Err(Error::ConnectionFailed);
		}

		Ok(response)
	}

	/// Handles a validation step whose transition failed. A rejection of the sender's proposal
	/// was saved as [`ReceiveSession::HasReplyableError`], so the session goes on from there to
	/// tell the sender. Any other failure is returned as [`Self::step_error`] maps it.
	fn validation_failed<ApiErr: std::error::Error, CurrentState: fmt::Debug>(
		&self, step: &str,
		e: PersistedError<ApiErr, Error, Receiver<HasReplyableError>, CurrentState>,
	) -> Result<ReceiveSession, Error> {
		if e.storage_error_ref().is_some() || !e.is_fatal() {
			return Err(self.step_error(step, &e));
		}
		if let Some(api_error) = e.api_error_ref() {
			log_info!(
				self.logger,
				"Rejected the sender's proposal. Failed to {}: {}",
				step,
				api_error
			);
		}
		e.fatal_state().map(ReceiveSession::HasReplyableError).ok_or(Error::PayjoinSessionFailed)
	}

	/// The error to return for a step whose transition failed: the persister's error if saving
	/// it failed, or [`Error::PayjoinSessionFailed`] if payjoin rejected it.
	fn step_error<ApiErr: std::error::Error, ErrorState: fmt::Debug, CurrentState: fmt::Debug>(
		&self, step: &str, e: &PersistedError<ApiErr, Error, ErrorState, CurrentState>,
	) -> Error {
		log_error!(self.logger, "Failed to {}: {:?}", step, e);
		match e.storage_error_ref() {
			Some(storage_error) => *storage_error,
			None => Error::PayjoinSessionFailed,
		}
	}

	async fn check_original_payload(
		&self, proposal: Receiver<UncheckedOriginalPayload>,
		persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let transaction = proposal.extract_tx_to_check_broadcast_suitability();
		let is_broadcast_suitable =
			self.chain_source.can_broadcast_transaction(&transaction).await.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to check broadcast suitability of the sender's original transaction: {:?}",
					e
				);
				Error::PayjoinSessionFailed
			})?;

		let proposal = match proposal
			.apply_broadcast_suitability(None, is_broadcast_suitable)
			.save_async(persister)
			.await
		{
			Ok(proposal) => proposal,
			Err(e) => {
				return self.validation_failed(
					"check the sender's original transaction for broadcast suitability",
					e,
				)
			},
		};

		// The sender's original transaction is the fallback, which the session keeps: if the
		// payjoin fails or times out, it's broadcast to ensure the receiver still gets paid.
		log_info!(
			self.logger,
			"Fallback transaction received. This will be broadcast if the Payjoin fails"
		);

		Ok(ReceiveSession::MaybeInputsOwned(proposal))
	}

	async fn check_inputs_not_owned(
		&self, proposal: Receiver<MaybeInputsOwned>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let mut marked_checklist = Vec::new();
		for item in proposal.inputs_owned_checklist() {
			let owned = self.wallet.is_my_outpoint(item.value()).map_err(|e| {
				log_error!(self.logger, "Failed to check whether a sender input is ours: {}", e);
				e
			})?;
			marked_checklist.push(item.mark(owned));
		}

		let proposal = match proposal
			.apply_inputs_owned_checklist(marked_checklist)
			.save_async(persister)
			.await
		{
			Ok(proposal) => proposal,
			Err(e) => {
				return self.validation_failed("check whether the sender's inputs belong to us", e)
			},
		};

		Ok(ReceiveSession::MaybeInputsSeen(proposal))
	}

	async fn check_no_inputs_seen_before(
		&self, proposal: Receiver<MaybeInputsSeen>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let session_id = persister.session_id();

		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(Duration::from_secs(0))
			.as_secs();

		let mut marked_checklist = Vec::new();
		for item in proposal.inputs_seen_checklist() {
			let seen = check_and_record_seen_input(
				&self.payjoin_seen_inputs_store,
				*item.value(),
				session_id,
				now,
			)
			.await?;
			marked_checklist.push(item.mark(seen));
		}

		let transition = proposal.apply_inputs_seen_checklist(marked_checklist);
		let proposal = match transition.save_async(persister).await {
			Ok(proposal) => proposal,
			Err(e) => return self.validation_failed("check the sender's inputs for reuse", e),
		};

		Ok(ReceiveSession::OutputsUnknown(proposal))
	}

	async fn identify_receiver_outputs(
		&self, proposal: Receiver<OutputsUnknown>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let mut marked_checklist = Vec::new();
		for item in proposal.outputs_owned_checklist() {
			let owned = self.wallet.is_mine(item.value().clone()).map_err(|e| {
				log_error!(self.logger, "Failed to check whether a proposal output is ours: {}", e);
				e
			})?;
			marked_checklist.push(item.mark(owned));
		}

		let proposal = match proposal
			.apply_outputs_owned_checklist(marked_checklist)
			.save_async(persister)
			.await
		{
			Ok(proposal) => proposal,
			Err(e) => {
				return self.validation_failed("identify our outputs in the sender's proposal", e)
			},
		};
		Ok(ReceiveSession::WantsOutputs(proposal))
	}

	async fn commit_outputs(
		&self, proposal: Receiver<WantsOutputs>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let proposal = proposal.commit_outputs().save_async(persister).await.map_err(|e| {
			log_error!(self.logger, "Failed to commit the payjoin outputs: {:?}", e);
			Error::PersistenceFailed
		})?;
		Ok(ReceiveSession::WantsInputs(proposal))
	}

	async fn contribute_inputs(
		&self, proposal: Receiver<WantsInputs>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let candidate_inputs = self.list_input_pairs()?;

		if candidate_inputs.is_empty() {
			log_error!(
				self.logger,
				"No spendable UTXOs available in wallet. Cannot contribute inputs to payjoin."
			);
			return Err(Error::InsufficientFunds);
		}

		let selected_input = proposal.try_preserving_privacy(candidate_inputs).map_err(|e| {
			log_error!(self.logger, "Failed to select input for payjoin contribution: {}", e);
			Error::PayjoinSessionFailed
		})?;
		let proposal = proposal
			.contribute_inputs(vec![selected_input])
			.map_err(|e| {
				log_error!(self.logger, "Failed to contribute inputs to payjoin: {}", e);
				Error::PayjoinSessionFailed
			})?
			.commit_inputs()
			.save_async(persister)
			.await
			.map_err(|e| {
				log_error!(self.logger, "Failed to commit our contributed payjoin inputs: {:?}", e);
				Error::PersistenceFailed
			})?;
		Ok(ReceiveSession::WantsFeeRange(proposal))
	}

	fn list_input_pairs(&self) -> Result<Vec<InputPair>, Error> {
		let unspent = self.wallet.list_unspent_confirmed_utxos()?;

		let mut input_pairs = Vec::with_capacity(unspent.len());

		for u in unspent {
			let txin = TxIn { previous_output: u.outpoint, ..Default::default() };
			let psbtin = Input { witness_utxo: Some(u.output.clone()), ..Default::default() };

			let input_pair = InputPair::new(txin, psbtin, None).map_err(|e| {
				log_error!(self.logger, "Failed to create InputPair: {}", e);
				Error::PayjoinSessionFailed
			})?;

			input_pairs.push(input_pair);
		}

		Ok(input_pairs)
	}

	async fn apply_fee_range(
		&self, proposal: Receiver<WantsFeeRange>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let proposal = proposal
			.apply_fee_range(None, None)
			.save_async(persister)
			.await
			.map_err(|e| self.step_error("apply the payjoin fee range", &e))?;

		Ok(ReceiveSession::ProvisionalProposal(proposal))
	}

	async fn finalize_proposal(
		&self, proposal: Receiver<ProvisionalProposal>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let signed_psbt = self.wallet.process_psbt(proposal.psbt_to_sign())?;

		let proposal = proposal
			.finalize_signed_proposal(&signed_psbt)
			.save_async(persister)
			.await
			.map_err(|e| self.step_error("finalize the payjoin proposal", &e))?;
		Ok(ReceiveSession::PayjoinProposal(proposal))
	}

	async fn send_payjoin_proposal(
		&self, proposal: Receiver<PayjoinProposal>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let Some((ohttp_response, context)) =
			self.post_via_relay(|relay| proposal.create_post_request(relay)).await?
		else {
			log_info!(self.logger, "Payjoin session {} expired.", persister.session_id());
			return Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted));
		};

		let payjoin_psbt = proposal.psbt().clone();

		match proposal
			.process_response(ohttp_response.as_bytes(), context)
			.save_async(persister)
			.await
		{
			Ok(session) => {
				// At this point we will persist the fee and txid to the session store
				let payjoin_tx = payjoin_psbt.extract_tx_unchecked_fee_rate();
				let txid = payjoin_tx.compute_txid();

				log_info!(
					self.logger,
					"Payjoin proposal sent. Waiting for the sender to broadcast it. TXID, unless the sender's signatures change it: {}",
					txid
				);
				Ok(ReceiveSession::Monitor(session))
			},
			Err(e) if e.is_transient() => {
				// The directory failed the post, e.g. with a 5xx. Nothing was persisted, so like a
				// failed relay this backs the session off and the proposal is posted again on a
				// later resume, rather than at once.
				log_warn!(
					self.logger,
					"Transient error sending payjoin proposal, retrying after backoff: {e:?}"
				);
				Err(Error::ConnectionFailed)
			},
			// The directory's response was fatal, so payjoin saved the session as pending its
			// fallback, which goes out now.
			Err(e) if e.is_fatal() => {
				log_error!(self.logger, "Payjoin directory rejected our proposal: {:?}", e);
				e.fatal_state()
					.map(ReceiveSession::PendingFallback)
					.ok_or(Error::PayjoinSessionFailed)
			},
			Err(e) => Err(self.step_error("process the directory's response to our proposal", &e)),
		}
	}

	async fn post_via_relay<F>(
		&self, mut build: F,
	) -> Result<Option<(bitreq::Response, payjoin::OhttpResponse)>, Error>
	where
		F: FnMut(&str) -> Result<(payjoin::Request, payjoin::OhttpResponse), CreateRequestError>,
	{
		let payjoin_config =
			self.config.payjoin_config.as_ref().ok_or(Error::PayjoinNotConfigured)?;

		for relay in self.relay_order(payjoin_config)? {
			let (req, ctx) = match build(relay) {
				Ok(r) => r,
				Err(e) if e.is_expired() => return Ok(None),
				Err(e) => {
					// Building the request doesn't depend on the relay, so this would fail
					// the same way for every remaining relay.
					log_error!(self.logger, "Failed to build payjoin request: {}", e);
					return Err(Error::PayjoinSessionFailed);
				},
			};

			match self.post_request(req).await {
				Ok(resp) => return Ok(Some((resp, ctx))),
				Err(e) => {
					log_debug!(
						self.logger,
						"Request via relay {} failed, trying next: {:?}",
						relay,
						e
					);
				},
			}
		}

		log_error!(self.logger, "All configured OHTTP relays failed.");
		Err(Error::ConnectionFailed)
	}

	async fn handle_error(
		&self, session: Receiver<HasReplyableError>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let Some((err_response, err_ctx)) =
			self.post_via_relay(|relay| session.create_error_request(relay)).await?
		else {
			log_info!(self.logger, "Payjoin session {} expired.", persister.session_id());
			return Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted));
		};

		let err_bytes = err_response.as_bytes();

		match session.process_error_response(err_bytes, err_ctx).save_async(persister).await {
			Ok(Some(pending)) => {
				log_info!(
					self.logger,
					"Session delivered error reply. Broadcast the fallback transaction."
				);
				Ok(ReceiveSession::PendingFallback(pending))
			},
			Ok(None) => Ok(ReceiveSession::Closed(ReceiverSessionOutcome::Aborted)),
			Err(e) if e.is_transient() => {
				// As with the proposal, nothing was persisted, so this backs the session off like a
				// failed relay and the error reply is posted again on a later resume.
				log_warn!(
					self.logger,
					"Transient error posting error response, retrying after backoff: {e:?}"
				);
				Err(Error::ConnectionFailed)
			},
			Err(e) => {
				if let Some(api_err) = e.api_error_ref() {
					log_warn!(self.logger, "Failed to confirm error response delivery: {api_err}");
				}
				match e.fatal_state() {
					Some(pending) => {
						log_error!(self.logger, "Session failed to deliver error reply. Broadcast the fallback transaction");
						Ok(ReceiveSession::PendingFallback(pending))
					},
					None => Err(Error::PayjoinSessionFailed),
				}
			},
		}
	}

	async fn handle_closed_session(
		&self, outcome: ReceiverSessionOutcome, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<(), Error> {
		let session_id = persister.session_id();
		let mut session = persister.get_session().await?;
		session.completed_at.get_or_insert_with(|| {
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
		});

		// `settle_session` updates our record before it closes a session, which then isn't replayed,
		// so its closes don't come through here. `Success` and `FallbackBroadcasted` are only
		// recorded by the deprecated `check_for_transaction`, which we don't call.
		match outcome {
			ReceiverSessionOutcome::Success(txid) => {
				log_info!(self.logger, "Payjoin session completed with transaction {}.", txid);
				// Wallet sync fills in the payment's amount and fee.
				self.wallet.classify_payjoin(txid, None).await?;

				session.status = PayjoinStatus::Completed;
				session.resolution_txid = Some(txid);

				self.payjoin_session_store.insert_or_update(session).await?;
			},
			ReceiverSessionOutcome::PayjoinProposalSent => {
				log_info!(self.logger, "Payjoin session closed after its proposal was sent.");
				session.status = PayjoinStatus::Completed;

				self.payjoin_session_store.insert_or_update(session).await?;
			},
			ReceiverSessionOutcome::FallbackBroadcasted => {
				log_info!(self.logger, "Payjoin failed. Fallback transaction was broadcasted.");
				session.status = PayjoinStatus::Failed;
				session.resolution_txid =
					self.session_fallback(persister).await.map(|tx| tx.compute_txid());

				self.payjoin_session_store.insert_or_update(session).await?;
			},
			ReceiverSessionOutcome::Aborted => {
				log_info!(self.logger, "Payjoin session was aborted.");
				let fallback_tx = self.session_fallback(persister).await;
				self.close_session_with_fallback(session_id, fallback_tx).await;
			},
			ReceiverSessionOutcome::Unrecognized(txid) => {
				log_error!(
					self.logger,
					"Payjoin session {} was settled by an unrecognized transaction {}.",
					session_id,
					txid
				);
				session.status = PayjoinStatus::Failed;
				session.resolution_txid = Some(txid);

				self.payjoin_session_store.insert_or_update(session).await?;
			},
		}
		Ok(())
	}

	pub(crate) async fn resume_payjoin_sessions(
		&self, mut stop_receiver: tokio::sync::watch::Receiver<()>,
	) -> Result<(), Error> {
		let now = Instant::now();
		let backing_off: HashSet<PaymentId> = {
			let retry_at = self.session_retry_at.lock().expect("lock");
			retry_at.iter().filter(|(_, at)| now < **at).map(|(id, _)| *id).collect()
		};

		let recv_session_ids = self
			.payjoin_session_store
			.list_filter(|p| {
				matches!(p.kind, PayjoinSessionKind::Receive)
					&& p.status == PayjoinStatus::Active
					// Waiting for wallet sync to see its spend buried, so not advanced.
					&& p.spend.is_none()
					&& !backing_off.contains(&p.session_id)
			})
			.await
			.into_iter()
			.map(|s| s.session_id)
			.collect::<Vec<PaymentId>>();

		if recv_session_ids.is_empty() {
			log_debug!(self.logger, "No sessions to resume.");
			return Ok(());
		}

		let mut join_set: tokio::task::JoinSet<Result<(), Error>> = tokio::task::JoinSet::new();

		// Process receiver sessions
		for session_id in recv_session_ids {
			let self_clone = self.clone();
			// Create a persister for this session
			let recv_persister = match KVStorePayjoinReceiverPersister::from_session(
				session_id,
				Arc::clone(&self.payjoin_session_store),
			)
			.await
			{
				Ok(p) => p,
				Err(e) => {
					log_error!(
						self.logger,
						"Failed to create persister for session {:?}: {:?}",
						session_id,
						e
					);
					self.session_retry_at
						.lock()
						.expect("lock")
						.insert(session_id, Instant::now() + PAYJOIN_RETRY_DELAY);
					continue;
				},
			};

			match replay_receiver_event_log_async(&recv_persister).await {
				Ok((receiver_state, _)) => {
					join_set.spawn(async move {
						let res = self_clone
							.process_receiver_session(receiver_state, &recv_persister)
							.await;
						{
							let mut retry_at = self_clone.session_retry_at.lock().expect("lock");
							if res.is_err() {
								retry_at.insert(session_id, Instant::now() + PAYJOIN_RETRY_DELAY);
							} else {
								retry_at.remove(&session_id);
							}
						}
						res
					});
				},
				Err(e) if e.is_expired() => {
					self.close_session_with_fallback(session_id, e.expiry_fallback_tx().cloned())
						.await
				},
				Err(e) => {
					log_error!(
						self.logger,
						"An error {:?} occurred while replaying receiver session",
						e
					);
					// The fallback is only in the log, so there's nothing to broadcast.
					self.close_session_with_fallback(session_id, None).await;
				},
			}
		}

		tokio::select! {
			_ = async {
				while let Some(result) = join_set.join_next().await {
					match result {
						Ok(Ok(())) => log_debug!(self.logger, "A payjoin session task finished."),
						Ok(Err(e)) => log_error!(self.logger, "A payjoin session failed: {:?}", e),
						Err(e) => log_error!(self.logger, "A payjoin session task panicked: {:?}", e),
					}
				}
			} => {
				log_debug!(self.logger, "All payjoin resumed sessions completed.");
			}
			_ = stop_receiver.changed() => {
				join_set.abort_all();
				log_info!(self.logger, "Resumed payjoin sessions were interrupted.");
			}
		}
		Ok(())
	}

	/// Closes an active session whose payjoin didn't complete and broadcasts its fallback
	/// transaction, if it has one.
	///
	/// The broadcast queue doesn't survive a restart, so the session is persisted as
	/// [`PayjoinStatus::FallbackPending`] before the fallback is queued, and
	/// [`Self::rebroadcast_pending_fallbacks`] keeps broadcasting it until wallet sync sees it, or
	/// another spend of the sender's inputs, buried. A session no longer active, e.g. because
	/// wallet sync settled it meanwhile, is left alone.
	async fn close_session_with_fallback(
		&self, session_id: PaymentId, fallback_tx: Option<Transaction>,
	) {
		let status = if fallback_tx.is_some() {
			PayjoinStatus::FallbackPending
		} else {
			log_warn!(
				self.logger,
				"Payjoin session {} has no fallback transaction; closing as Failed without broadcast.",
				session_id
			);
			PayjoinStatus::Failed
		};
		match self.settle_record(session_id, &[PayjoinStatus::Active], status, None).await {
			Ok(true) => log_info!(self.logger, "Closed failed receiver session: {}", session_id),
			Ok(false) => return,
			Err(e) => {
				log_error!(self.logger, "Failed to close receiver session {}: {:?}", session_id, e)
			},
		}

		// Broadcast even if persisting failed: a broadcast that may not be retried beats none.
		if let Some(fallback_tx) = fallback_tx {
			self.broadcaster.broadcast(fallback_tx);
		}
	}

	/// Rebroadcasts the fallback transaction of every [`PayjoinStatus::FallbackPending`] session
	/// once per chain tip, until wallet sync sees it, or another spend of the sender's inputs,
	/// buried, which [`Self::on_tx_buried`] settles, or until it's given up on.
	///
	/// Like the wallet's rebroadcast of its own unconfirmed transactions, this runs on chain tip
	/// changes, and its first pass after startup rebroadcasts what a restart dropped from the
	/// broadcast queue.
	pub(crate) async fn rebroadcast_pending_fallbacks(&self) {
		// Compared by hash, so a reorg replacing the tip at the same height counts as a change.
		let tip = self.wallet.best_block_hash();
		{
			let mut last_tip = self.fallback_rebroadcast_tip.lock().expect("lock");
			if *last_tip == Some(tip) {
				return;
			}
			*last_tip = Some(tip);
		}

		let pending_sessions = self
			.payjoin_session_store
			.list_filter(|s| s.status == PayjoinStatus::FallbackPending)
			.await;

		let now = unix_now();
		for session in pending_sessions {
			let session_id = session.session_id;
			let fallback_tx = match self.persister(session_id).await {
				Some(persister) => self.session_fallback(&persister).await,
				None => None,
			};
			let Some(fallback_tx) = fallback_tx else {
				log_warn!(
					self.logger,
					"Payjoin session {} is pending a fallback it can't recover; marking it Failed.",
					session_id
				);
				self.resolve_pending_fallback(session_id, None).await;
				continue;
			};
			let fallback_txid = fallback_tx.compute_txid();

			let closed_at = session.completed_at.unwrap_or(session.latest_update_timestamp);
			if now.saturating_sub(closed_at) > PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS {
				log_warn!(
					self.logger,
					"Giving up on fallback transaction {} of payjoin session {}: not confirmed after {}s.",
					fallback_txid,
					session_id,
					PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS
				);
				self.resolve_pending_fallback(session_id, None).await;
			} else {
				log_debug!(
					self.logger,
					"Rebroadcasting fallback transaction {} of payjoin session {}.",
					fallback_txid,
					session_id
				);
				self.broadcaster.broadcast(fallback_tx);
			}
		}
	}

	/// Fails the payments of the spends that lost to `winner`, which spends the inputs of a
	/// session's `fallback_tx` and is confirmed through [`ANTI_REORG_DELAY`], and which wallet sync
	/// would leave pending: the fallback we broadcast when the sender's payjoin won anyway, or the
	/// payjoin when the fallback won.
	///
	/// Used for a session that can't classify the losers. Only those spending one of the sender's
	/// inputs, which `fallback_tx` spends, are failed, not ones that lost on an input of ours a
	/// payjoin spent. A payjoin keeps the tag it got when wallet sync saw it.
	async fn fail_lost_spends(
		&self, winner: &Transaction, fallback_tx: &Transaction,
	) -> Result<(), Error> {
		for lost in self.wallet.lost_conflicts_of(winner) {
			if spends_any_input_of(&lost, fallback_tx) {
				self.wallet.fail_payment_lost_to_conflict(lost.compute_txid(), None).await?;
			}
		}
		Ok(())
	}

	/// Forgets the seen sender inputs, which `fallback_tx` spends, that `winner` spends, now that
	/// it's confirmed through [`ANTI_REORG_DELAY`]. An unrecognized `winner` may spend only some of
	/// them, and the rest can still be reused to probe us.
	///
	/// Best effort: [`Self::cleanup_old_sessions`] forgets what this misses after
	/// [`PAYJOIN_SEEN_INPUT_RETENTION_SECS`].
	async fn forget_spent_sender_inputs(&self, winner: &Transaction, fallback_tx: &Transaction) {
		let spent = fallback_tx
			.input
			.iter()
			.map(|txin| txin.previous_output)
			.filter(|sender| winner.input.iter().any(|txin| txin.previous_output == *sender))
			.collect::<Vec<_>>();
		if let Err(e) = forget_seen_inputs(&self.payjoin_seen_inputs_store, spent).await {
			log_warn!(
				self.logger,
				"Failed to forget the payjoin sender inputs spent by {}: {:?}",
				winner.compute_txid(),
				e
			);
		}
	}

	/// Marks a [`PayjoinStatus::FallbackPending`] session [`PayjoinStatus::Failed`], ending the
	/// rebroadcast of its fallback, and records `resolution_txid` as what settled it.
	async fn resolve_pending_fallback(&self, session_id: PaymentId, resolution_txid: Option<Txid>) {
		let res = self
			.settle_record(
				session_id,
				&[PayjoinStatus::FallbackPending],
				PayjoinStatus::Failed,
				resolution_txid,
			)
			.await;
		if let Err(e) = res {
			log_error!(
				self.logger,
				"Failed to mark payjoin session {} as Failed: {:?}. Will retry on the next chain tip.",
				session_id,
				e
			);
		}
	}

	/// Cleans up old payjoin sessions that are completed or failed.
	/// Sessions older than `PAYJOIN_SESSION_CLEANUP_AGE_SECS` will be removed.
	pub(crate) async fn cleanup_old_sessions(&self) -> Result<(), Error> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or(std::time::Duration::from_secs(0))
			.as_secs();

		match prune_seen_inputs(
			&self.payjoin_seen_inputs_store,
			now,
			PAYJOIN_SEEN_INPUT_RETENTION_SECS,
		)
		.await
		{
			Ok(0) => {},
			Ok(pruned) => log_info!(self.logger, "Forgot {} old payjoin sender inputs", pruned),
			Err(e) => {
				log_error!(self.logger, "Failed to forget old payjoin sender inputs: {:?}", e)
			},
		}

		let sessions_to_remove: Vec<PaymentId> = self
			.payjoin_session_store
			.list_filter(|s| {
				let is_terminal =
					s.status == PayjoinStatus::Completed || s.status == PayjoinStatus::Failed;
				let completed_at = s.completed_at.unwrap_or(s.latest_update_timestamp);
				is_terminal && now.saturating_sub(completed_at) > PAYJOIN_SESSION_CLEANUP_AGE_SECS
			})
			.await
			.into_iter()
			.map(|s| s.session_id)
			.collect();

		if sessions_to_remove.is_empty() {
			return Ok(());
		}

		log_info!(self.logger, "Cleaning up {} old payjoin sessions", sessions_to_remove.len());

		for session_id in sessions_to_remove {
			if let Err(e) = self.payjoin_session_store.remove(&session_id).await {
				log_error!(
					self.logger,
					"Failed to remove old payjoin session {:?}: {:?}",
					session_id,
					e
				);
			}
			self.session_retry_at.lock().expect("lock").remove(&session_id);
		}

		Ok(())
	}
}

/// A session's event log, replayed.
enum Replayed {
	/// The session in its current state, with its fallback transaction if it has one.
	Open(ReceiveSession, Option<Transaction>),
	/// The session expired, with its fallback transaction if it has one.
	Expired(Option<Transaction>),
	/// The log couldn't be replayed.
	Unreadable,
}

fn spend_kind(resolved_by: ResolvedBy) -> SpendKind {
	match resolved_by {
		ResolvedBy::Payjoin => SpendKind::Payjoin,
		ResolvedBy::Fallback => SpendKind::Fallback,
		_ => SpendKind::Unrecognized,
	}
}

/// Whether `tx` spends any of the inputs of `fallback_tx`, i.e. any of the sender's.
fn spends_any_input_of(tx: &Transaction, fallback_tx: &Transaction) -> bool {
	tx.input.iter().any(|txin| {
		fallback_tx.input.iter().any(|sender| sender.previous_output == txin.previous_output)
	})
}

fn unix_now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
}

#[cfg(all(test, feature = "chain-esplora"))]
mod tests {
	use std::collections::HashMap;
	use std::sync::atomic::{AtomicU8, Ordering};

	use bitcoin::absolute::LockTime;
	use bitcoin::hashes::Hash;
	use bitcoin::transaction::Version;
	use bitcoin::{
		Address, Network, OutPoint, Psbt, ScriptBuf, Sequence, TxOut, WPubkeyHash, Witness,
	};
	use payjoin::persist::AsyncSessionPersister;
	use payjoin::receive::v2::SessionEvent;
	use serde_json::json;

	use super::*;
	use crate::config::EsploraSyncConfig;
	use crate::data_store::KeepAllEntries;
	use crate::io::test_utils::InMemoryStore;
	use crate::payment::PaymentStatus;
	use crate::payment::{PaymentDetails, PaymentKind};
	use crate::types::{DynStore, DynStoreWrapper};
	use crate::wallet::tests::{
		chain_tip_changed, insert_confirmed_tx, new_test_wallet, observe_confirmed,
		observe_dropped, observe_replaced, observe_unconfirmed, recorded_payment, set_chain_tip,
		tx_spending,
	};
	use crate::{NodeMetrics, PersistedNodeMetrics};

	// Keys of a payjoin receiver session, from rust-payjoin's fuzzing seeds. Nothing in these tests
	// encrypts with them.
	const OHTTP_KEYS: [u8; 74] = [
		1, 0, 22, 4, 49, 201, 65, 129, 251, 247, 128, 36, 159, 34, 170, 43, 131, 131, 10, 85, 25,
		245, 236, 35, 252, 37, 128, 98, 22, 235, 48, 68, 122, 8, 134, 133, 12, 23, 164, 215, 191,
		143, 99, 200, 11, 214, 16, 10, 31, 15, 91, 223, 101, 248, 218, 98, 90, 235, 190, 123, 14,
		75, 237, 98, 32, 13, 77, 94, 0, 4, 0, 1, 0, 3,
	];
	const RECEIVER_SECRET_KEY: [u8; 32] = [
		55, 181, 82, 181, 118, 112, 72, 22, 165, 165, 27, 49, 174, 138, 173, 154, 94, 222, 82, 73,
		223, 101, 59, 62, 77, 184, 180, 205, 246, 246, 71, 92,
	];
	const RECEIVER_PUBLIC_KEY: [u8; 65] = [
		4, 169, 112, 179, 223, 102, 152, 248, 70, 179, 203, 202, 47, 218, 92, 121, 173, 239, 35,
		126, 66, 223, 96, 202, 36, 252, 93, 204, 223, 174, 107, 245, 243, 121, 135, 94, 243, 11,
		133, 76, 46, 112, 47, 231, 239, 225, 227, 244, 123, 81, 171, 166, 150, 132, 192, 70, 169,
		147, 114, 34, 202, 177, 177, 11, 236,
	];
	const SENDER_REPLY_KEY: [u8; 65] = [
		4, 194, 221, 118, 65, 156, 207, 82, 35, 217, 201, 43, 116, 24, 169, 42, 61, 39, 244, 255,
		112, 83, 209, 162, 36, 150, 230, 77, 40, 133, 173, 247, 186, 16, 202, 172, 58, 122, 210,
		166, 77, 90, 183, 98, 94, 37, 82, 127, 92, 242, 127, 14, 208, 130, 137, 57, 186, 17, 229,
		87, 40, 223, 13, 196, 243,
	];

	/// An expiration far enough out that sessions never expire mid-test (2100-01-01).
	const NEVER_EXPIRES: u64 = 4_102_444_800;

	/// What the sender pays us, out of each 200 000 sat input of theirs.
	const PAYMENT_SATS: u64 = 100_000;
	const SENDER_INPUT_SATS: u64 = 200_000;

	struct Harness {
		manager: Arc<PayjoinManager>,
		wallet: Arc<Wallet>,
		broadcaster: Arc<Broadcaster>,
		session_store: Arc<PayjoinSessionStore>,
	}

	/// A manager over a test wallet holding one confirmed UTXO, at chain tip 10, to contribute.
	async fn harness() -> Harness {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let wallet = new_test_wallet(Arc::clone(&store), false).await;
		let funding = tx_spending(&wallet, outpoint(0xf0, 0));
		insert_confirmed_tx(&wallet, funding, 1);
		set_chain_tip(&wallet, 10);

		let logger = Arc::new(Logger::new_log_facade());
		let mut config = Config::default();
		config.network = Network::Regtest;
		// Nothing listens on the relay, so a session that gets to posting fails to.
		config.payjoin_config = Some(PayjoinConfig {
			payjoin_directory: "https://example.com".to_string(),
			ohttp_relays: vec!["http://127.0.0.1:1".to_string()],
		});
		let config = Arc::new(config);
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let broadcaster = Arc::new(Broadcaster::new(Arc::clone(&logger)));
		// Only consulted for the broadcast suitability check, which these tests record directly.
		let (chain_source, _) = ChainSource::new_esplora(
			"http://localhost:1".to_string(),
			HashMap::new(),
			EsploraSyncConfig::default(),
			Arc::clone(&fee_estimator),
			Arc::clone(&broadcaster),
			Arc::clone(&store),
			Arc::clone(&config),
			Arc::clone(&logger),
			Arc::new(PersistedNodeMetrics::new(NodeMetrics::default())),
		)
		.unwrap();
		let session_store = Arc::new(PayjoinSessionStore::new(
			Vec::new(),
			KeepAllEntries,
			"payjoin_sessions".to_string(),
			String::new(),
			Arc::clone(&store),
			Arc::clone(&logger),
		));
		let seen_inputs_store = Arc::new(PayjoinSeenInputsStore::new(
			Vec::new(),
			KeepAllEntries,
			"payjoin_seen_inputs".to_string(),
			String::new(),
			Arc::clone(&store),
			Arc::clone(&logger),
		));
		let manager = Arc::new(PayjoinManager::new(
			Arc::clone(&session_store),
			seen_inputs_store,
			logger,
			config,
			Arc::clone(&wallet),
			fee_estimator,
			Arc::new(chain_source),
			Arc::clone(&broadcaster),
		));
		wallet.set_payjoin_manager(Arc::downgrade(&manager));
		Harness { manager, wallet, broadcaster, session_store }
	}

	fn outpoint(byte: u8, vout: u32) -> OutPoint {
		OutPoint { txid: Txid::from_byte_array([byte; 32]), vout }
	}

	fn sender_script() -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7; 20]))
	}

	/// The sender's original transaction, paying us [`PAYMENT_SATS`] from `sender_inputs`, as a
	/// finalized PSBT. Its signatures are placeholders: the receiver doesn't verify them.
	fn original_psbt(address: &Address, sender_inputs: &[OutPoint]) -> Psbt {
		let input_sats = SENDER_INPUT_SATS * sender_inputs.len() as u64;
		let fee_sats = 1_000 * sender_inputs.len() as u64;
		let tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: sender_inputs
				.iter()
				.map(|previous_output| TxIn {
					previous_output: *previous_output,
					sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
					..Default::default()
				})
				.collect(),
			output: vec![
				TxOut {
					value: Amount::from_sat(PAYMENT_SATS),
					script_pubkey: address.script_pubkey(),
				},
				TxOut {
					value: Amount::from_sat(input_sats - PAYMENT_SATS - fee_sats),
					script_pubkey: sender_script(),
				},
			],
		};
		let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
		for input in psbt.inputs.iter_mut() {
			input.witness_utxo = Some(TxOut {
				value: Amount::from_sat(SENDER_INPUT_SATS),
				script_pubkey: sender_script(),
			});
			input.final_script_witness = Some(Witness::from_slice(&[vec![0x30; 72], vec![2; 33]]));
		}
		psbt
	}

	fn event(value: serde_json::Value) -> SessionEvent {
		serde_json::from_value(value).unwrap()
	}

	/// An event without data, e.g. `CheckedBroadcastSuitability()`.
	fn unit_event(name: &str) -> SessionEvent {
		serde_json::from_str(&format!("{{\"{}\":[]}}", name)).unwrap()
	}

	fn created_event(address: &Address, expiration: u64) -> SessionEvent {
		event(json!({ "Created": {
			"address": address.to_string(),
			"directory": "https://example.com/",
			"ohttp_keys": OHTTP_KEYS.to_vec(),
			"expiration": expiration,
			"amount": null,
			"receiver_key": [RECEIVER_SECRET_KEY.to_vec(), RECEIVER_PUBLIC_KEY.to_vec()],
			"reply_key": null,
			// 100 sat/vB, so the fee for the input we contribute is never capped.
			"max_fee_rate": 25_000,
		}}))
	}

	fn retrieved_original_event(original: &Psbt) -> SessionEvent {
		event(json!({ "RetrievedOriginalPayload": {
			"original": {
				"psbt": original,
				"params": {
					"v": 2,
					"output_substitution": "Enabled",
					"additional_fee_contribution": null,
					"min_fee_rate": 250,
				},
			},
			"reply_key": SENDER_REPLY_KEY.to_vec(),
		}}))
	}

	/// A receive session the sender sent its original transaction to.
	struct TestSession {
		session_id: PaymentId,
		persister: KVStorePayjoinReceiverPersister,
		fallback: Transaction,
	}

	fn new_session_id() -> PaymentId {
		static NEXT: AtomicU8 = AtomicU8::new(1);
		PaymentId([NEXT.fetch_add(1, Ordering::Relaxed); 32])
	}

	/// A session still waiting for the sender.
	async fn initialized_session(h: &Harness) -> (PaymentId, KVStorePayjoinReceiverPersister) {
		let session_id = new_session_id();
		let persister =
			KVStorePayjoinReceiverPersister::new(session_id, Arc::clone(&h.session_store));
		let address = h.wallet.get_new_address().await.unwrap();
		persister.save_event(created_event(&address, NEVER_EXPIRES)).await.unwrap();
		(session_id, persister)
	}

	/// A session that received an original spending `sender_inputs` and passed the broadcast
	/// suitability check, so it's in [`ReceiveSession::MaybeInputsOwned`].
	async fn session_with_original(
		h: &Harness, sender_inputs: &[OutPoint], expiration: u64,
	) -> TestSession {
		let session_id = new_session_id();
		let persister =
			KVStorePayjoinReceiverPersister::new(session_id, Arc::clone(&h.session_store));
		let address = h.wallet.get_new_address().await.unwrap();
		let original = original_psbt(&address, sender_inputs);
		for event in [
			created_event(&address, expiration),
			retrieved_original_event(&original),
			unit_event("CheckedBroadcastSuitability"),
		] {
			persister.save_event(event).await.unwrap();
		}
		let fallback = original.extract_tx_unchecked_fee_rate();
		TestSession { session_id, persister, fallback }
	}

	async fn replay(persister: &KVStorePayjoinReceiverPersister) -> ReceiveSession {
		replay_receiver_event_log_async(persister).await.unwrap().0
	}

	/// Takes a session from [`ReceiveSession::MaybeInputsOwned`] through the manager's steps to
	/// the proposal, then records it as posted, so it's in [`ReceiveSession::Monitor`]. Returns
	/// the payjoin transaction as the sender would broadcast it.
	async fn propose(h: &Harness, session: &TestSession) -> Transaction {
		let persister = &session.persister;
		let ReceiveSession::MaybeInputsOwned(proposal) = replay(persister).await else {
			panic!("expected a session that got the sender's original");
		};
		let mut state = ReceiveSession::MaybeInputsOwned(proposal);
		let payjoin_psbt = loop {
			state = match state {
				ReceiveSession::MaybeInputsOwned(p) => {
					h.manager.check_inputs_not_owned(p, persister).await.unwrap()
				},
				ReceiveSession::MaybeInputsSeen(p) => {
					h.manager.check_no_inputs_seen_before(p, persister).await.unwrap()
				},
				ReceiveSession::OutputsUnknown(p) => {
					h.manager.identify_receiver_outputs(p, persister).await.unwrap()
				},
				ReceiveSession::WantsOutputs(p) => {
					h.manager.commit_outputs(p, persister).await.unwrap()
				},
				ReceiveSession::WantsInputs(p) => {
					h.manager.contribute_inputs(p, persister).await.unwrap()
				},
				ReceiveSession::WantsFeeRange(p) => {
					h.manager.apply_fee_range(p, persister).await.unwrap()
				},
				ReceiveSession::ProvisionalProposal(p) => {
					h.manager.finalize_proposal(p, persister).await.unwrap()
				},
				ReceiveSession::PayjoinProposal(p) => break p.psbt().clone(),
				other => panic!("unexpected state {:?}", other),
			};
		};
		persister.save_event(unit_event("PostedPayjoinProposal")).await.unwrap();
		assert!(matches!(replay(persister).await, ReceiveSession::Monitor(_)));
		payjoin_psbt.extract_tx_unchecked_fee_rate()
	}

	async fn status(h: &Harness, session_id: PaymentId) -> PayjoinSessionStatus {
		h.manager.session_status(session_id).await.unwrap().unwrap()
	}

	/// Resumes the session as the resume task does.
	async fn resume(h: &Harness, persister: &KVStorePayjoinReceiverPersister) -> Result<(), Error> {
		let state = replay(persister).await;
		h.manager.process_receiver_session(state, persister).await
	}

	/// The transactions queued for broadcast.
	async fn broadcast_txs(h: &Harness) -> Vec<Transaction> {
		let mut txs = Vec::new();
		while let Ok(package) =
			tokio::time::timeout(Duration::from_millis(10), h.broadcaster.next_package()).await
		{
			txs.extend(package.into_sorted_transactions().into_inner());
		}
		txs
	}

	fn tx_type(payment: &PaymentDetails) -> Option<TransactionType> {
		match &payment.kind {
			PaymentKind::Onchain { tx_type, .. } => tx_type.clone(),
			kind => panic!("unexpected kind {:?}", kind),
		}
	}

	fn payment_id(txid: Txid) -> PaymentId {
		PaymentId(txid.to_byte_array())
	}

	/// Resumes every session the resume task would.
	async fn resume_all(h: &Harness) {
		let (_stop_sender, stop_receiver) = tokio::sync::watch::channel(());
		h.manager.resume_payjoin_sessions(stop_receiver).await.unwrap();
	}

	/// Moves the chain tip to where a transaction confirmed at `height` is buried.
	async fn bury(h: &Harness, height: u32) {
		chain_tip_changed(&h.wallet, height + ANTI_REORG_DELAY - 1).await;
	}

	async fn spend(h: &Harness, session_id: PaymentId) -> Option<SessionSpend> {
		h.session_store.get(&session_id).await.unwrap().unwrap().spend
	}

	#[tokio::test]
	async fn payjoin_settles_once_buried() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		let payjoin_txid = payjoin.compute_txid();
		// We contributed an input of ours.
		assert_eq!(payjoin.input.len(), 2);

		// Seen unconfirmed: tagged and recorded, but the session stays open.
		observe_unconfirmed(&h.wallet, &payjoin).await;
		assert_eq!(
			spend(&h, session.session_id).await,
			Some(SessionSpend { txid: payjoin_txid, kind: SpendKind::Payjoin })
		);
		let payment = recorded_payment(&h.wallet, &payment_id(payjoin_txid)).await.unwrap();
		assert_eq!(tx_type(&payment), Some(TransactionType::Payjoin));

		observe_confirmed(&h.wallet, &payjoin, 11).await;
		chain_tip_changed(&h.wallet, 11 + ANTI_REORG_DELAY - 2).await;
		assert_eq!(status(&h, session.session_id).await, PayjoinSessionStatus::Active);

		bury(&h, 11).await;
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Completed { txid: Some(payjoin_txid) }
		);
		assert!(matches!(
			replay(&session.persister).await,
			ReceiveSession::Closed(ReceiverSessionOutcome::PayjoinProposalSent)
		));
		// Nothing can follow the close.
		assert!(session.persister.save_event(unit_event("PostedPayjoinProposal")).await.is_err());
		// The sender's input is spent past the reorg bar, so it's forgotten.
		assert!(h.manager.payjoin_seen_inputs_store.get(&outpoint(1, 0)).await.unwrap().is_none());
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn spend_first_seen_buried_settles_at_once() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;

		// Wallet sync only catches up once the payjoin is buried already, e.g. after downtime.
		set_chain_tip(&h.wallet, 30);
		observe_confirmed(&h.wallet, &payjoin, 11).await;
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Completed { txid: Some(payjoin.compute_txid()) }
		);
	}

	#[tokio::test]
	async fn session_backs_off_when_the_proposal_cant_be_posted() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;

		// The relay is unreachable, so the session fails at posting the proposal it got to.
		assert!(resume(&h, &session.persister).await.is_err());
		assert!(matches!(replay(&session.persister).await, ReceiveSession::PayjoinProposal(_)));
		assert_eq!(status(&h, session.session_id).await, PayjoinSessionStatus::Active);
		assert!(h.manager.payjoin_seen_inputs_store.get(&outpoint(1, 0)).await.unwrap().is_some());
	}

	#[tokio::test]
	async fn original_spending_our_own_input_is_rejected() {
		let h = harness().await;
		let ours = h.wallet.list_unspent_confirmed_utxos().unwrap()[0].outpoint;
		let session = session_with_original(&h, &[ours], NEVER_EXPIRES).await;
		let ReceiveSession::MaybeInputsOwned(proposal) = replay(&session.persister).await else {
			panic!("expected a session that got the sender's original");
		};

		// The rejection is saved, and the session goes on to reply to the sender with it.
		let next = h.manager.check_inputs_not_owned(proposal, &session.persister).await.unwrap();
		assert!(matches!(next, ReceiveSession::HasReplyableError(_)));
		assert!(matches!(replay(&session.persister).await, ReceiveSession::HasReplyableError(_)));
	}

	#[tokio::test]
	async fn session_pauses_while_a_spend_waits_to_be_buried() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		// The sender gave up on the payjoin and broadcast its original.
		observe_unconfirmed(&h.wallet, &session.fallback).await;
		assert_eq!(
			spend(&h, session.session_id).await,
			Some(SessionSpend { txid: session.fallback.compute_txid(), kind: SpendKind::Fallback })
		);

		// Nothing advances: a proposal could no longer confirm.
		resume_all(&h).await;
		assert!(matches!(replay(&session.persister).await, ReceiveSession::MaybeInputsOwned(_)));

		// The original dropped out of the mempool, so the session goes on.
		observe_dropped(&h.wallet, &session.fallback).await;
		assert_eq!(spend(&h, session.session_id).await, None);
		resume_all(&h).await;
		assert!(matches!(replay(&session.persister).await, ReceiveSession::PayjoinProposal(_)));
	}

	#[tokio::test]
	async fn buried_fallback_fails_the_session() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		propose(&h, &session).await;
		let fallback_txid = session.fallback.compute_txid();

		observe_confirmed(&h.wallet, &session.fallback, 11).await;
		bury(&h, 11).await;

		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		assert!(matches!(replay(&session.persister).await, ReceiveSession::Closed(_)));
		let payment = recorded_payment(&h.wallet, &payment_id(fallback_txid)).await.unwrap();
		assert_eq!(tx_type(&payment), None);
		assert!(h.manager.payjoin_seen_inputs_store.get(&outpoint(1, 0)).await.unwrap().is_none());
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn unrecognized_spend_forgets_only_the_inputs_it_spends() {
		let h = harness().await;
		let (spent, unspent) = (outpoint(1, 0), outpoint(2, 0));
		let session = session_with_original(&h, &[spent, unspent], NEVER_EXPIRES).await;
		propose(&h, &session).await;

		// The sender double-spent one of its inputs to us in some other transaction.
		let double_spend = tx_spending(&h.wallet, spent);
		observe_confirmed(&h.wallet, &double_spend, 11).await;
		assert_eq!(
			spend(&h, session.session_id).await.map(|spend| spend.kind),
			Some(SpendKind::Unrecognized)
		);
		bury(&h, 11).await;

		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(double_spend.compute_txid()) }
		);
		assert!(h.manager.payjoin_seen_inputs_store.get(&spent).await.unwrap().is_none());
		assert!(h.manager.payjoin_seen_inputs_store.get(&unspent).await.unwrap().is_some());
	}

	#[tokio::test]
	async fn payjoin_replaced_by_the_fallback_loses_its_tag() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		let payjoin_id = payment_id(payjoin.compute_txid());
		let fallback_txid = session.fallback.compute_txid();

		observe_unconfirmed(&h.wallet, &payjoin).await;
		let payment = recorded_payment(&h.wallet, &payjoin_id).await.unwrap();
		assert_eq!(tx_type(&payment), Some(TransactionType::Payjoin));
		assert_eq!(payment.status, PaymentStatus::Pending);

		// The fallback confirms instead, e.g. after a reorg, and the payjoin can't any more.
		observe_replaced(&h.wallet, &payjoin, &session.fallback, 11).await;
		assert_eq!(
			spend(&h, session.session_id).await,
			Some(SessionSpend { txid: fallback_txid, kind: SpendKind::Fallback })
		);
		bury(&h, 11).await;

		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		// Wallet sync recorded the fallback as the payjoin's replacement, in the payjoin's record,
		// which no longer holds a payjoin.
		let payment = recorded_payment(&h.wallet, &payjoin_id).await.unwrap();
		assert!(matches!(payment.kind, PaymentKind::Onchain { txid, .. } if txid == fallback_txid));
		assert_eq!(payment.status, PaymentStatus::Succeeded);
		assert_eq!(tx_type(&payment), None);
	}

	#[tokio::test]
	async fn payjoin_dropped_before_the_fallback_confirms_has_its_payment_failed() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		let payjoin_id = payment_id(payjoin.compute_txid());
		let fallback_txid = session.fallback.compute_txid();

		observe_unconfirmed(&h.wallet, &payjoin).await;
		// Dropped from the mempool, so the fallback confirming later isn't its replacement to
		// wallet sync, and its payment stays pending.
		observe_dropped(&h.wallet, &payjoin).await;
		observe_confirmed(&h.wallet, &session.fallback, 11).await;
		assert_eq!(
			recorded_payment(&h.wallet, &payjoin_id).await.unwrap().status,
			PaymentStatus::Pending
		);
		bury(&h, 11).await;

		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		let payment = recorded_payment(&h.wallet, &payjoin_id).await.unwrap();
		assert_eq!(payment.status, PaymentStatus::Failed);
		assert_eq!(tx_type(&payment), Some(TransactionType::Payjoin));
		let fallback = recorded_payment(&h.wallet, &payment_id(fallback_txid)).await.unwrap();
		assert_eq!(fallback.status, PaymentStatus::Succeeded);
	}

	#[tokio::test]
	async fn cancelled_session_without_original_closes_without_broadcast() {
		let h = harness().await;
		let (session_id, persister) = initialized_session(&h).await;

		h.manager.cancel_session(session_id).await.unwrap();
		// Applied by the resume task, not by the request.
		assert_eq!(status(&h, session_id).await, PayjoinSessionStatus::Active);

		resume(&h, &persister).await.unwrap();
		assert_eq!(
			status(&h, session_id).await,
			PayjoinSessionStatus::Cancelled { fallback_txid: None }
		);
		assert!(matches!(
			replay(&persister).await,
			ReceiveSession::Closed(ReceiverSessionOutcome::Aborted)
		));
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn cancelled_session_after_proposal_broadcasts_the_fallback() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		propose(&h, &session).await;

		h.manager.cancel_session(session.session_id).await.unwrap();
		// Cancelling again is a no-op.
		h.manager.cancel_session(session.session_id).await.unwrap();
		resume(&h, &session.persister).await.unwrap();

		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Cancelled {
				fallback_txid: Some(session.fallback.compute_txid())
			}
		);
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);
		assert!(matches!(replay(&session.persister).await, ReceiveSession::Closed(_)));
	}

	#[tokio::test]
	async fn cancel_is_refused_once_it_cant_change_the_outcome() {
		let h = harness().await;
		assert!(matches!(
			h.manager.cancel_session(new_session_id()).await,
			Err(Error::InvalidPaymentId)
		));

		// Wallet sync saw a spend of the sender's inputs.
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		observe_unconfirmed(&h.wallet, &session.fallback).await;
		assert!(matches!(
			h.manager.cancel_session(session.session_id).await,
			Err(Error::PayjoinSessionNotCancellable)
		));

		// The session ended.
		let session = session_with_original(&h, &[outpoint(2, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		observe_confirmed(&h.wallet, &payjoin, 11).await;
		bury(&h, 11).await;
		assert!(matches!(
			h.manager.cancel_session(session.session_id).await,
			Err(Error::PayjoinSessionNotCancellable)
		));
	}

	#[tokio::test]
	async fn expired_session_rebroadcasts_its_fallback_until_buried() {
		let h = harness().await;
		// Expired in 2020.
		let session = session_with_original(&h, &[outpoint(1, 0)], 1_600_000_000).await;
		let fallback_txid = session.fallback.compute_txid();

		resume_all(&h).await;
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::FallbackPending { fallback_txid }
		);
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);

		// The first pass after startup rebroadcasts, and then once per chain tip.
		h.manager.rebroadcast_pending_fallbacks().await;
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);
		h.manager.rebroadcast_pending_fallbacks().await;
		assert!(broadcast_txs(&h).await.is_empty());

		observe_confirmed(&h.wallet, &session.fallback, 11).await;
		bury(&h, 11).await;
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		h.manager.rebroadcast_pending_fallbacks().await;
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn pending_fallback_beaten_by_the_payjoin_settles() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		let payjoin_txid = payjoin.compute_txid();
		let fallback_id = payment_id(session.fallback.compute_txid());

		// Cancelled, so we broadcast the fallback, which wallet sync records.
		h.manager.cancel_session(session.session_id).await.unwrap();
		resume(&h, &session.persister).await.unwrap();
		observe_unconfirmed(&h.wallet, &session.fallback).await;
		assert_eq!(
			recorded_payment(&h.wallet, &fallback_id).await.unwrap().status,
			PaymentStatus::Pending
		);

		// But the sender broadcast the payjoin it had, which confirms.
		observe_replaced(&h.wallet, &session.fallback, &payjoin, 11).await;
		bury(&h, 11).await;

		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert_eq!(recorded.status, PayjoinStatus::Failed);
		assert_eq!(recorded.resolution_txid, Some(payjoin_txid));
		// Wallet sync recorded the payjoin as the fallback's replacement, in the fallback's record.
		let payment = recorded_payment(&h.wallet, &fallback_id).await.unwrap();
		assert!(matches!(payment.kind, PaymentKind::Onchain { txid, .. } if txid == payjoin_txid));
		assert_eq!(payment.status, PaymentStatus::Succeeded);
		h.manager.rebroadcast_pending_fallbacks().await;
	}

	#[tokio::test]
	async fn cleanup_forgets_seen_inputs_past_retention() {
		let h = harness().await;
		let (old, recent) = (outpoint(1, 0), outpoint(2, 0));
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let store = &h.manager.payjoin_seen_inputs_store;
		let first_seen = now - PAYJOIN_SEEN_INPUT_RETENTION_SECS - 1;
		check_and_record_seen_input(store, old, new_session_id(), first_seen).await.unwrap();
		check_and_record_seen_input(store, recent, new_session_id(), now).await.unwrap();

		h.manager.cleanup_old_sessions().await.unwrap();
		assert!(store.get(&old).await.unwrap().is_none());
		assert!(store.get(&recent).await.unwrap().is_some());
	}
}
