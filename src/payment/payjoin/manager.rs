// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bitcoin::{psbt::Input, Amount, BlockHash, FeeRate, Transaction, TxIn, Txid};

use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
use lightning::ln::channelmanager::PaymentId;
use lightning::log_warn;

use payjoin::io::fetch_ohttp_keys;
use payjoin::persist::{AsyncSessionPersister, OptionalTransitionOutcome, PersistedError};
use payjoin::receive::v2::{
	CreateRequestError, HasReplyableError, Initialized, MaybeInputsOwned, MaybeInputsSeen,
	OutputsUnknown, PayjoinProposal, ProvisionalProposal, ReceiveSession, Receiver,
	ReceiverBuilder, Resolution, UncheckedOriginalPayload, WantsFeeRange, WantsInputs,
	WantsOutputs,
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
use crate::payment::payjoin::payjoin_session::{PayjoinSessionKind, SessionSpend, SpendKind};
use crate::payment::payjoin::persist::KVStorePayjoinReceiverPersister;
use crate::payment::payjoin::replay::{ClassifiedSpend, Replayed};
use crate::payment::payjoin::seen_inputs::{
	check_and_record_seen_input, forget_seen_inputs, prune_seen_inputs,
};
use crate::payment::payjoin::{unix_now, PayjoinSessionStatus};
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
	/// The wallet's chain tip when each pending fallback was last broadcast. Empty after startup,
	/// so the first resume rebroadcasts what a restart dropped from the broadcast queue.
	fallback_broadcast_tips: Arc<Mutex<HashMap<PaymentId, BlockHash>>>,
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
			fallback_broadcast_tips: Arc::new(Mutex::new(HashMap::new())),
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
			Arc::clone(&self.logger),
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
			let Some(next) = self.cancel(session, persister).await? else {
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
						Some(ReceiveSession::Initialized(_)) | None => return Ok(()),
						Some(next) => next,
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
					match self.send_payjoin_proposal(proposal, persister).await? {
						Some(next) => next,
						None => return Ok(()),
					}
				},
				ReceiveSession::HasReplyableError(error) => {
					match self.handle_error(error, persister).await? {
						Some(next) => next,
						None => return Ok(()),
					}
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
				// The session stays open until wallet sync sees a spend of the sender's inputs buried.
				// Until it sees one, each resume broadcasts the fallback as `Self::broadcast_fallback`
				// does.
				ReceiveSession::PendingFallback(pending) => {
					let fallback_tx = pending.fallback_tx().clone();
					let state = ReceiveSession::PendingFallback(pending);
					self.broadcast_fallback(persister, fallback_tx, Some(state)).await?;
					return Ok(());
				},
				// payjoin closed the log, but recording when failed, or the node stopped first. A close
				// event only follows once there's no fallback or payjoin left to check for, so this
				// just finishes the close. No step returns a closed session, so only a resumed one
				// gets here.
				ReceiveSession::Closed(_) => {
					persister.close().await?;
					return Ok(());
				},
			}
		}
	}

	/// Cancels a session that expired, or whose cancellation was requested through
	/// [`Self::cancel_session`].
	///
	/// Only runs for a session without a pending spend, since a session awaiting settlement isn't
	/// resumed. Returns the session to keep processing: [`ReceiveSession::PendingFallback`] if the
	/// session had the sender's fallback, so it is broadcast like that of a failed payjoin, or the
	/// session unchanged if it is ending already. Returns `None` if the session closed.
	async fn cancel(
		&self, session: ReceiveSession, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ReceiveSession>, Error> {
		let pending = match session {
			ReceiveSession::Initialized(r) => {
				r.cancel().save_async(persister).await?;
				return Ok(None);
			},
			ReceiveSession::UncheckedOriginalPayload(r) => {
				r.cancel().save_async(persister).await?;
				return Ok(None);
			},
			// Whether there's a fallback to broadcast is only known from the transition.
			ReceiveSession::HasReplyableError(r) => match r.cancel().save_async(persister).await? {
				Some(pending) => pending,
				None => return Ok(None),
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

	/// Returns the status of the session `session_id`, or `None` if there is no such session.
	pub(crate) async fn session_status(
		&self, session_id: PaymentId,
	) -> Result<Option<PayjoinSessionStatus>, Error> {
		self.persister(session_id).status().await
	}

	/// Requests the cancellation of the session `session_id`, which the resume task applies.
	///
	/// See [`PayjoinPayment::cancel`].
	///
	/// [`PayjoinPayment::cancel`]: crate::payment::PayjoinPayment::cancel
	pub(crate) async fn cancel_session(&self, session_id: PaymentId) -> Result<(), Error> {
		let persister = self.persister(session_id);
		let session = persister.get_session().await?;
		if session.cancel_requested {
			return Ok(());
		}
		// Once wallet sync saw something spend the sender's inputs, the session settles on that,
		// so cancelling would change nothing. Nor would it for a session pending its fallback.
		if !session.is_cancellable() || persister.replay().await.pending_fallback().is_some() {
			return Err(Error::PayjoinSessionNotCancellable);
		}
		persister.request_cancel().await?;

		// Apply it on the next resume rather than after a backoff.
		self.session_retry_at.lock().expect("lock").remove(&session_id);
		log_info!(self.logger, "Requested the cancellation of payjoin session {}.", session_id);
		Ok(())
	}

	/// Reports transactions wallet sync saw, new or newly confirmed, to the running sessions.
	///
	/// Each is classified against each session. One spending the sender's inputs is recorded as
	/// the session's pending spend, which pauses the session, and its payment is tagged as
	/// [`Self::tag_spend`] does. The session settles once that spend is buried, which [`Self::on_tx_buried`]
	/// reports.
	pub(crate) async fn on_txs_seen(&self, txs: &[Arc<Transaction>]) -> Result<(), Error> {
		if txs.is_empty() {
			return Ok(());
		}
		let sessions = self.payjoin_session_store.list_filter(|s| s.is_running()).await;
		for session in sessions {
			let session_id = session.session_id;
			let persister = self.persister(session_id);
			let replayed = persister.replay().await;
			for tx in txs {
				let Some(spend) = replayed.classify(tx) else {
					continue;
				};
				let txid = tx.compute_txid();
				let kind = spend.kind;
				self.tag_spend(tx, &spend).await?;
				if !persister.record_pending(SessionSpend { txid, kind }).await? {
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
		let waiting = self.payjoin_session_store.list_filter(|s| s.is_pending_on_any(txids)).await;
		for session in waiting {
			let persister = self.persister(session.session_id);
			if !persister.clear_pending(txids).await? {
				continue;
			}
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
	/// Only a session that got the sender's original, and so has its fallback, can be spent.
	pub(crate) async fn on_tx_buried(&self, txid: Txid) -> Result<(), Error> {
		let sessions = self.payjoin_session_store.list_filter(|s| s.is_running()).await;
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
			let persister = self.persister(session.session_id);
			let replayed = persister.replay().await;
			let Some(spend) = replayed.classify(&tx) else {
				continue;
			};
			self.settle_session(&persister, replayed, spend, &tx).await?;
		}
		Ok(())
	}

	/// Settles a session, `replayed`, on `tx`, which is confirmed through [`ANTI_REORG_DELAY`] and
	/// spends the sender's inputs. `spend` is what `tx` is to the session.
	async fn settle_session(
		&self, persister: &KVStorePayjoinReceiverPersister, replayed: Replayed,
		spend: ClassifiedSpend, tx: &Transaction,
	) -> Result<(), Error> {
		// Only a session that got the sender's original can be spent.
		let Some(fallback) = replayed.fallback() else {
			return Ok(());
		};
		let session_id = persister.session_id();
		let txid = tx.compute_txid();
		let kind = spend.kind;

		self.tag_spend(tx, &spend).await?;
		self.fail_lost_spends(tx, &replayed).await?;
		self.forget_spent_sender_inputs(tx, fallback).await;

		// Recorded first, so the session isn't resumed if persisting the close event fails
		// afterwards. The resume task then closes the log.
		if !persister.settle(SessionSpend { txid, kind }).await? {
			return Ok(());
		}
		log_info!(
			self.logger,
			"Payjoin session {} settled: {:?} transaction {} is buried.",
			session_id,
			kind,
			txid
		);
		let state = match replayed {
			Replayed::Open(state, _) => Some(state),
			_ => None,
		};
		self.close_session(persister, state, spend.resolution).await;
		Ok(())
	}

	/// Tags the payment of `tx`, a spend of the sender's inputs that `spend` classifies, as a
	/// payjoin if it is one, and untags it if it's known not to be.
	///
	/// Wallet sync records a replacement in the record of what it replaced, so the record holding
	/// `tx` may carry the tag of a payjoin it replaced. Only a session that classified `tx` knows an
	/// unrecognized spend isn't the payjoin.
	async fn tag_spend(&self, tx: &Transaction, spend: &ClassifiedSpend) -> Result<(), Error> {
		let txid = tx.compute_txid();
		match spend.kind {
			SpendKind::Payjoin => self.wallet.classify_payjoin(txid, Some(tx)).await,
			SpendKind::Fallback => self.wallet.untag_payjoin(txid).await,
			SpendKind::Unrecognized if spend.resolution.is_some() => {
				self.wallet.untag_payjoin(txid).await
			},
			SpendKind::Unrecognized => Ok(()),
		}
	}

	/// Closes the log of a session that ended by recording when it ended, without writing a close
	/// event. payjoin may have written one already, or none can be written, e.g. after expiry.
	async fn close_log(&self, persister: &KVStorePayjoinReceiverPersister) -> Result<(), Error> {
		persister.close().await?;
		log_info!(self.logger, "Payjoin session {} ended.", persister.session_id());
		Ok(())
	}

	/// Closes a session that ended, with a close event in its log if its `state` can write one:
	/// with the session's `resolution` if it classified the spend it settled on, or if it's
	/// pending its fallback. Otherwise this closes its log as [`Self::close_log`] does. Unlike
	/// that, this only logs a failure, which the next resume retries.
	async fn close_session(
		&self, persister: &KVStorePayjoinReceiverPersister, state: Option<ReceiveSession>,
		resolution: Option<Resolution>,
	) {
		self.fallback_broadcast_tips.lock().expect("lock").remove(&persister.session_id());
		let res = match (state, resolution) {
			(Some(state), Some(resolution)) => state
				.close(resolution)
				.save_async(persister)
				.await
				.map(|_| ())
				.map_err(|e| format!("{:?}", e)),
			(Some(ReceiveSession::PendingFallback(pending)), None) => {
				pending.close().save_async(persister).await.map_err(|e| format!("{:?}", e))
			},
			_ => self.close_log(persister).await.map_err(|e| format!("{:?}", e)),
		};
		if let Err(e) = res {
			log_error!(
				self.logger,
				"Failed to close payjoin session {}: {}",
				persister.session_id(),
				e
			);
		}
	}

	/// The persister of the existing session `session_id`.
	fn persister(&self, session_id: PaymentId) -> KVStorePayjoinReceiverPersister {
		KVStorePayjoinReceiverPersister::for_existing(
			session_id,
			Arc::clone(&self.payjoin_session_store),
			Arc::clone(&self.logger),
		)
	}

	/// Polls the directory for the sender's original. Returns `None` if the session ended.
	async fn read_from_directory(
		&self, session: Receiver<Initialized>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ReceiveSession>, Error> {
		let Some((ohttp_response, context)) =
			self.post_via_relay(|relay| session.create_poll_request(relay)).await?
		else {
			log_info!(self.logger, "Payjoin session {} expired.", persister.session_id());
			return self.cancel(ReceiveSession::Initialized(session), persister).await;
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
				Ok(Some(ReceiveSession::UncheckedOriginalPayload(next_state)))
			},
			Ok(OptionalTransitionOutcome::Stasis(current_state)) => {
				Ok(Some(ReceiveSession::Initialized(current_state)))
			},
			Err(e) if e.is_transient() => {
				log_debug!(self.logger, "Transient error polling for request, retrying: {e:?}");
				let session = e.transient_state().expect("transient error carries current state");
				Ok(Some(ReceiveSession::Initialized(session)))
			},
			// A fatal response closed the session's log.
			Err(e) => {
				self.fatal_rejection("process the sender's directory response", e, persister)
					.await?;
				Ok(None)
			},
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

	/// Handles a step whose transition payjoin rejected fatally, which it saved. Returns the state
	/// payjoin saved the session in, or `None` if it closed the session's log, which closes our
	/// record too. Any other failure is returned as [`Self::step_error`] maps it.
	async fn fatal_rejection<ApiErr, ErrorState, CurrentState>(
		&self, step: &str, e: PersistedError<ApiErr, Error, ErrorState, CurrentState>,
		persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ErrorState>, Error>
	where
		ApiErr: std::error::Error,
		ErrorState: fmt::Debug,
		CurrentState: fmt::Debug,
	{
		if !e.is_fatal() {
			return Err(self.step_error(step, &e));
		}
		if let Some(api_error) = e.api_error_ref() {
			log_warn!(
				self.logger,
				"Payjoin session {} failed to {}: {}",
				persister.session_id(),
				step,
				api_error
			);
		}
		// payjoin only closes the log on a fatal rejection for a session without a fallback: one
		// that never got the sender's original, or failed to reply to it without one.
		Ok(e.fatal_state())
	}

	/// Handles a validation step that payjoin rejected fatally: the session goes on from the
	/// [`ReceiveSession::HasReplyableError`] it was saved as, to tell the sender.
	async fn validation_failed<ApiErr: std::error::Error, CurrentState: fmt::Debug>(
		&self, step: &str,
		e: PersistedError<ApiErr, Error, Receiver<HasReplyableError>, CurrentState>,
		persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		// A validation step's rejection always has the error to reply with.
		self.fatal_rejection(step, e, persister)
			.await?
			.map(ReceiveSession::HasReplyableError)
			.ok_or(Error::PayjoinSessionFailed)
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
				return self
					.validation_failed(
						"check the sender's original transaction for broadcast suitability",
						e,
						persister,
					)
					.await
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
				return self
					.validation_failed(
						"check whether the sender's inputs belong to us",
						e,
						persister,
					)
					.await
			},
		};

		Ok(ReceiveSession::MaybeInputsSeen(proposal))
	}

	async fn check_no_inputs_seen_before(
		&self, proposal: Receiver<MaybeInputsSeen>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let session_id = persister.session_id();

		let now = unix_now();

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
			Err(e) => {
				return self
					.validation_failed("check the sender's inputs for reuse", e, persister)
					.await
			},
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
				return self
					.validation_failed(
						"identify our outputs in the sender's proposal",
						e,
						persister,
					)
					.await
			},
		};
		Ok(ReceiveSession::WantsOutputs(proposal))
	}

	async fn commit_outputs(
		&self, proposal: Receiver<WantsOutputs>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let proposal = proposal.commit_outputs().save_async(persister).await.map_err(|e| {
			log_error!(self.logger, "Failed to commit the payjoin outputs: {:?}", e);
			e
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
				e
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

	/// Posts our proposal to the directory. Returns `None` if the session ended.
	async fn send_payjoin_proposal(
		&self, proposal: Receiver<PayjoinProposal>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ReceiveSession>, Error> {
		let Some((ohttp_response, context)) =
			self.post_via_relay(|relay| proposal.create_post_request(relay)).await?
		else {
			log_info!(self.logger, "Payjoin session {} expired.", persister.session_id());
			return self.cancel(ReceiveSession::PayjoinProposal(proposal), persister).await;
		};

		let payjoin_psbt = proposal.psbt().clone();

		match proposal
			.process_response(ohttp_response.as_bytes(), context)
			.save_async(persister)
			.await
		{
			Ok(session) => {
				let payjoin_tx = payjoin_psbt.extract_tx_unchecked_fee_rate();
				let txid = payjoin_tx.compute_txid();

				log_info!(
					self.logger,
					"Payjoin proposal sent. Waiting for the sender to broadcast it. TXID, unless the sender's signatures change it: {}",
					txid
				);
				Ok(Some(ReceiveSession::Monitor(session)))
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
			// A fatal response saved the session as pending its fallback, which goes out now.
			Err(e) => Ok(self
				.fatal_rejection("process the directory's response to our proposal", e, persister)
				.await?
				.map(ReceiveSession::PendingFallback)),
		}
	}

	/// Posts the request `build` makes through the first relay that takes it. Returns `None` if
	/// the session expired.
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

	/// Posts the error reply to the directory for the sender. Returns `None` if the session ended.
	async fn handle_error(
		&self, session: Receiver<HasReplyableError>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ReceiveSession>, Error> {
		let Some((err_response, err_ctx)) =
			self.post_via_relay(|relay| session.create_error_request(relay)).await?
		else {
			log_info!(self.logger, "Payjoin session {} expired.", persister.session_id());
			return self.cancel(ReceiveSession::HasReplyableError(session), persister).await;
		};

		let err_bytes = err_response.as_bytes();

		match session.process_error_response(err_bytes, err_ctx).save_async(persister).await {
			Ok(Some(pending)) => {
				log_info!(
					self.logger,
					"Session delivered error reply. Broadcast the fallback transaction."
				);
				Ok(Some(ReceiveSession::PendingFallback(pending)))
			},
			// Without a fallback, payjoin closed the session's log.
			Ok(None) => Ok(None),
			Err(e) if e.is_transient() => {
				// As with the proposal, nothing was persisted, so this backs the session off like a
				// failed relay and the error reply is posted again on a later resume.
				log_warn!(
					self.logger,
					"Transient error posting error response, retrying after backoff: {e:?}"
				);
				Err(Error::ConnectionFailed)
			},
			// A fatal response saved the session as pending its fallback, or closed its log if it
			// had none.
			Err(e) => Ok(self
				.fatal_rejection("confirm the delivery of our error reply", e, persister)
				.await?
				.map(ReceiveSession::PendingFallback)),
		}
	}

	pub(crate) async fn resume_payjoin_sessions(
		&self, mut stop_receiver: tokio::sync::watch::Receiver<()>,
	) -> Result<(), Error> {
		self.close_settled_sessions().await;

		let now = Instant::now();
		let backing_off: HashSet<PaymentId> = {
			let retry_at = self.session_retry_at.lock().expect("lock");
			retry_at.iter().filter(|(_, at)| now < **at).map(|(id, _)| *id).collect()
		};

		let recv_sessions = self
			.payjoin_session_store
			.list_filter(|p| {
				matches!(p.kind, PayjoinSessionKind::Receive)
					&& p.is_running()
					// Waiting for wallet sync to see its spend buried, so not advanced.
					&& !p.is_awaiting_settlement()
					&& !backing_off.contains(&p.session_id)
			})
			.await
			.into_iter()
			.map(|s| s.session_id)
			.collect::<Vec<PaymentId>>();

		if recv_sessions.is_empty() {
			log_debug!(self.logger, "No sessions to resume.");
			return Ok(());
		}

		let mut join_set: tokio::task::JoinSet<Result<(), Error>> = tokio::task::JoinSet::new();

		// Process receiver sessions
		for session_id in recv_sessions {
			let self_clone = self.clone();
			let recv_persister = self.persister(session_id);

			match recv_persister.replay().await {
				// No state to process, but the fallback is pending.
				Replayed::Expired(Some(fallback_tx)) => {
					if let Err(e) =
						self.broadcast_fallback(&recv_persister, fallback_tx, None).await
					{
						log_error!(
							self.logger,
							"Failed to broadcast the fallback of payjoin session {}: {:?}",
							session_id,
							e
						);
					}
				},
				Replayed::Open(receiver_state, _) => {
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
				// Expired before the sender's original, so there's nothing to broadcast.
				Replayed::Expired(None) => {
					if let Err(e) = self.close_log(&recv_persister).await {
						log_error!(
							self.logger,
							"Failed to close the log of payjoin session {}: {:?}",
							session_id,
							e
						);
					}
				},
				// Retried after a delay rather than closed: the log may hold a fallback to broadcast,
				// and a read failure may pass.
				Replayed::Unreadable => {
					self.session_retry_at
						.lock()
						.expect("lock")
						.insert(session_id, Instant::now() + PAYJOIN_RETRY_DELAY);
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

	/// Closes the sessions that settled, but failed to close.
	async fn close_settled_sessions(&self) {
		let unclosed = self
			.payjoin_session_store
			.list_filter(|s| s.completed_at.is_none() && s.settled_spend().is_some())
			.await;
		for session in unclosed {
			let persister = self.persister(session.session_id);
			let state = match persister.replay().await {
				Replayed::Open(state, _) => Some(state),
				_ => None,
			};
			self.close_session(&persister, state, None).await;
		}
	}

	/// Broadcasts `fallback_tx`, the pending fallback of the session `persister` holds, once per
	/// chain tip, until wallet sync sees it or another spend of the sender's inputs, which
	/// [`Self::on_txs_seen`] records as the session's pending spend, or until it's given up on. If that
	/// spend drops out, [`Self::on_txs_gone`] clears it and the broadcasts resume. `state` is the
	/// session's, unless it expired.
	///
	/// Like the wallet's rebroadcast of its own unconfirmed transactions, this broadcasts again on
	/// chain tip changes, and the first resume after startup rebroadcasts what a restart dropped
	/// from the broadcast queue.
	async fn broadcast_fallback(
		&self, persister: &KVStorePayjoinReceiverPersister, fallback_tx: Transaction,
		state: Option<ReceiveSession>,
	) -> Result<(), Error> {
		let session = persister.get_session().await?;
		let session_id = session.session_id;

		// Pending since the session's last event, which made it so, or after which it expired.
		let pending_since = session.last_event_at();
		if unix_now().saturating_sub(pending_since) > PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS {
			log_warn!(
				self.logger,
				"Giving up on fallback transaction {} of payjoin session {}: not confirmed after {}s.",
				fallback_tx.compute_txid(),
				session_id,
				PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS
			);
			self.close_session(persister, state, None).await;
			return Ok(());
		}

		// Compared by hash, so a reorg replacing the tip at the same height counts as a change.
		let tip = self.wallet.best_block_hash();
		if self.fallback_broadcast_tips.lock().expect("lock").insert(session_id, tip) == Some(tip) {
			return Ok(());
		}
		log_info!(
			self.logger,
			"Broadcasting fallback transaction {} of payjoin session {}.",
			fallback_tx.compute_txid(),
			session_id
		);
		self.broadcaster.broadcast(fallback_tx);
		Ok(())
	}

	/// Fails the payments of the spends that lost to `winner`, which spends the sender's inputs of
	/// the session `replayed` and is confirmed through [`ANTI_REORG_DELAY`], and which wallet sync
	/// would leave pending if it dropped the loser before seeing the winner, rather than recording
	/// the winner as its replacement: the fallback we broadcast when the sender's payjoin won
	/// anyway, or the payjoin when the fallback won.
	///
	/// Only those spending one of the sender's inputs are failed, not ones that lost on an input of
	/// ours a payjoin spent. One the session classifies as its payjoin is tagged as such if it
	/// isn't yet.
	async fn fail_lost_spends(
		&self, winner: &Transaction, replayed: &Replayed,
	) -> Result<(), Error> {
		for lost in self.wallet.lost_conflicts_of(winner) {
			let Some(spend) = replayed.classify(&lost) else {
				continue;
			};
			let tx_type = (spend.kind == SpendKind::Payjoin).then_some(TransactionType::Payjoin);
			self.wallet.fail_payment_lost_to_conflict(lost.compute_txid(), tx_type).await?;
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

	/// Removes the sessions that ended more than [`PAYJOIN_SESSION_CLEANUP_AGE_SECS`] ago, and
	/// forgets the sender inputs seen more than [`PAYJOIN_SEEN_INPUT_RETENTION_SECS`] ago.
	pub(crate) async fn cleanup_old_sessions(&self) -> Result<(), Error> {
		let now = unix_now();

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
				s.completed_at.is_some_and(|completed_at| {
					now.saturating_sub(completed_at) > PAYJOIN_SESSION_CLEANUP_AGE_SECS
				})
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

#[cfg(all(test, feature = "chain-esplora"))]
mod tests {
	use std::collections::HashMap;
	use std::sync::atomic::{AtomicU8, Ordering};
	use std::time::Duration;

	use bitcoin::absolute::LockTime;
	use bitcoin::hashes::Hash;
	use bitcoin::transaction::Version;
	use bitcoin::{
		Address, Network, OutPoint, Psbt, ScriptBuf, Sequence, TxOut, WPubkeyHash, Witness,
	};
	use payjoin::persist::AsyncSessionPersister;
	use payjoin::receive::v2::{
		replay_event_log_async as replay_receiver_event_log_async, SessionEvent,
		SessionOutcome as ReceiverSessionOutcome,
	};
	use serde_json::json;

	use super::*;
	use crate::config::EsploraSyncConfig;
	use crate::data_store::KeepAllEntries;
	use crate::io::test_utils::InMemoryStore;
	use crate::payment::payjoin::payjoin_session::SessionResolution;
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
		let persister = KVStorePayjoinReceiverPersister::new(
			session_id,
			Arc::clone(&h.session_store),
			Arc::clone(&h.manager.logger),
		);
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
		let persister = KVStorePayjoinReceiverPersister::new(
			session_id,
			Arc::clone(&h.session_store),
			Arc::clone(&h.manager.logger),
		);
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
		let payjoin_psbt = proposal(h, session).await.psbt().clone();
		persister.save_event(unit_event("PostedPayjoinProposal")).await.unwrap();
		assert!(matches!(replay(persister).await, ReceiveSession::Monitor(_)));
		payjoin_psbt.extract_tx_unchecked_fee_rate()
	}

	/// Takes a session from [`ReceiveSession::MaybeInputsOwned`] through the manager's steps to
	/// the proposal, before it's posted.
	async fn proposal(h: &Harness, session: &TestSession) -> Receiver<PayjoinProposal> {
		let persister = &session.persister;
		let ReceiveSession::MaybeInputsOwned(proposal) = replay(persister).await else {
			panic!("expected a session that got the sender's original");
		};
		let mut state = ReceiveSession::MaybeInputsOwned(proposal);
		loop {
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
				ReceiveSession::PayjoinProposal(p) => return p,
				other => panic!("unexpected state {:?}", other),
			};
		}
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

	/// The session's spend waiting to be buried.
	async fn spend(h: &Harness, session_id: PaymentId) -> Option<SessionSpend> {
		h.session_store.get(&session_id).await.unwrap().unwrap().pending_spend().cloned()
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
			PayjoinSessionStatus::Completed { txid: payjoin_txid }
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
			PayjoinSessionStatus::Completed { txid: payjoin.compute_txid() }
		);
	}

	#[tokio::test]
	async fn session_backs_off_when_the_proposal_cant_be_posted() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;

		// The relay is unreachable, so the session fails at posting the proposal it got to.
		resume_all(&h).await;
		assert!(h.manager.session_retry_at.lock().unwrap().contains_key(&session.session_id));
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
	async fn classified_unrecognized_spend_loses_the_payjoin_tag() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		let payjoin_id = payment_id(payjoin.compute_txid());
		observe_unconfirmed(&h.wallet, &payjoin).await;
		assert_eq!(
			tx_type(&recorded_payment(&h.wallet, &payjoin_id).await.unwrap()),
			Some(TransactionType::Payjoin)
		);

		// The sender double-spent its input, which replaces the payjoin in the payjoin's record.
		let double_spend = tx_spending(&h.wallet, outpoint(1, 0));
		observe_replaced(&h.wallet, &payjoin, &double_spend, 11).await;
		bury(&h, 11).await;

		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(double_spend.compute_txid()) }
		);
		let payment = recorded_payment(&h.wallet, &payjoin_id).await.unwrap();
		let double_spend_txid = double_spend.compute_txid();
		assert!(
			matches!(payment.kind, PaymentKind::Onchain { txid, .. } if txid == double_spend_txid)
		);
		assert_eq!(tx_type(&payment), None);
	}

	#[tokio::test]
	async fn payjoin_settling_a_pending_fallback_keeps_its_tag() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let payjoin = propose(&h, &session).await;
		let payjoin_id = payment_id(payjoin.compute_txid());
		// Seen and tagged, then dropped, so the session can be cancelled.
		observe_unconfirmed(&h.wallet, &payjoin).await;
		observe_dropped(&h.wallet, &payjoin).await;
		h.manager.cancel_session(session.session_id).await.unwrap();
		resume(&h, &session.persister).await.unwrap();
		assert!(matches!(replay(&session.persister).await, ReceiveSession::PendingFallback(_)));

		// The sender broadcast the payjoin again, which confirms. Pending its fallback, the
		// session can't tell it from another spend.
		observe_confirmed(&h.wallet, &payjoin, 11).await;
		bury(&h, 11).await;

		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert_eq!(
			recorded.settled_spend(),
			Some(&SessionSpend { txid: payjoin.compute_txid(), kind: SpendKind::Unrecognized })
		);
		assert_eq!(
			tx_type(&recorded_payment(&h.wallet, &payjoin_id).await.unwrap()),
			Some(TransactionType::Payjoin)
		);
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
		// Untagged once seen, rather than only once buried.
		let payment = recorded_payment(&h.wallet, &payjoin_id).await.unwrap();
		assert!(matches!(payment.kind, PaymentKind::Onchain { txid, .. } if txid == fallback_txid));
		assert_eq!(tx_type(&payment), None);
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
	async fn proposal_expiring_before_its_post_broadcasts_the_fallback() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], unix_now() + 2).await;
		let proposal = proposal(&h, &session).await;
		// The session expires after it was replayed, before the proposal is posted.
		tokio::time::sleep(Duration::from_secs(3)).await;

		let next = h.manager.send_payjoin_proposal(proposal, &session.persister).await.unwrap();
		let Some(pending @ ReceiveSession::PendingFallback(_)) = next else {
			panic!("expected the session pending its fallback, got {:?}", next);
		};
		h.manager.process_receiver_session(pending, &session.persister).await.unwrap();
		let fallback_txid = session.fallback.compute_txid();
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::FallbackPending { fallback_txid }
		);
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);
	}

	#[tokio::test]
	async fn closing_a_log_again_keeps_when_it_ended() {
		let h = harness().await;
		let (session_id, persister) = initialized_session(&h).await;
		let record = || async { h.session_store.get(&session_id).await.unwrap().unwrap() };

		persister.close().await.unwrap();
		assert!(record().await.completed_at.is_some());

		// A record that ended already keeps when it ended.
		h.session_store
			.mutate(&session_id, |existing| {
				let mut session = existing?.clone();
				session.completed_at = Some(5);
				Some(session)
			})
			.await
			.unwrap();
		persister.close().await.unwrap();
		assert_eq!(record().await.completed_at, Some(5));
	}

	#[tokio::test]
	async fn closed_log_with_an_open_record_ends_the_session() {
		let h = harness().await;
		// The node stopped after payjoin closed the log, before our record followed.
		let (session_id, persister) = initialized_session(&h).await;
		persister.save_event(SessionEvent::Closed(ReceiverSessionOutcome::Aborted)).await.unwrap();

		resume_all(&h).await;
		assert_eq!(status(&h, session_id).await, PayjoinSessionStatus::Failed { txid: None });
		assert!(broadcast_txs(&h).await.is_empty());
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
		// Open until a spend of the sender's inputs is buried.
		assert!(matches!(replay(&session.persister).await, ReceiveSession::PendingFallback(_)));
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

		// The session expired after it got the sender's original, so its fallback is pending.
		let session = session_with_original(&h, &[outpoint(3, 0)], 1_600_000_000).await;
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

		// The first resume broadcasts it, and then once per chain tip.
		resume_all(&h).await;
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::FallbackPending { fallback_txid }
		);
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);
		resume_all(&h).await;
		assert!(broadcast_txs(&h).await.is_empty());
		set_chain_tip(&h.wallet, 11);
		resume_all(&h).await;
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);

		observe_confirmed(&h.wallet, &session.fallback, 11).await;
		bury(&h, 11).await;
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: Some(fallback_txid) }
		);
		resume_all(&h).await;
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn pending_fallback_is_rebroadcast_until_a_spend_is_seen() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		h.manager.cancel_session(session.session_id).await.unwrap();
		resume(&h, &session.persister).await.unwrap();
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);
		// Not again at the same tip.
		resume_all(&h).await;
		assert!(broadcast_txs(&h).await.is_empty());

		// Wallet sync sees the fallback, so it's not broadcast again at a new tip.
		observe_unconfirmed(&h.wallet, &session.fallback).await;
		assert_eq!(
			spend(&h, session.session_id).await,
			Some(SessionSpend { txid: session.fallback.compute_txid(), kind: SpendKind::Fallback })
		);
		set_chain_tip(&h.wallet, 11);
		resume_all(&h).await;
		assert!(broadcast_txs(&h).await.is_empty());

		// It dropped out of the mempool, so it's broadcast again.
		observe_dropped(&h.wallet, &session.fallback).await;
		assert_eq!(spend(&h, session.session_id).await, None);
		resume_all(&h).await;
		assert_eq!(broadcast_txs(&h).await, vec![session.fallback.clone()]);
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
		// Pending its fallback, the session can't tell the payjoin from another spend.
		assert_eq!(
			recorded.settled_spend(),
			Some(&SessionSpend { txid: payjoin_txid, kind: SpendKind::Unrecognized })
		);
		// Wallet sync recorded the payjoin as the fallback's replacement, in the fallback's record.
		let payment = recorded_payment(&h.wallet, &fallback_id).await.unwrap();
		assert!(matches!(payment.kind, PaymentKind::Onchain { txid, .. } if txid == payjoin_txid));
		assert_eq!(payment.status, PaymentStatus::Succeeded);
		assert!(matches!(replay(&session.persister).await, ReceiveSession::Closed(_)));
	}

	/// Backdates the last event of session `session_id` by `secs`.
	async fn backdate_last_event(h: &Harness, session_id: PaymentId, secs: u64) {
		h.session_store
			.mutate(&session_id, |existing| {
				let mut session = existing?.clone();
				let last = session.events.last_mut()?;
				last.created_at -= secs;
				Some(session)
			})
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn resume_closes_the_log_of_a_settled_session() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		// Settled, but the node stopped before the log was closed.
		let spend =
			SessionSpend { txid: session.fallback.compute_txid(), kind: SpendKind::Fallback };
		h.session_store
			.mutate(&session.session_id, |existing| {
				let mut session = existing?.clone();
				session.resolution = Some(SessionResolution::Settled(spend.clone()));
				Some(session)
			})
			.await
			.unwrap();

		let events = h.session_store.get(&session.session_id).await.unwrap().unwrap().events.len();

		resume_all(&h).await;
		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert!(recorded.completed_at.is_some());
		assert_eq!(recorded.settled_spend(), Some(&spend));
		// Not advanced: no event was added.
		assert_eq!(recorded.events.len(), events);
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn unknown_session_has_no_status() {
		let h = harness().await;
		assert_eq!(h.manager.session_status(new_session_id()).await.unwrap(), None);
	}

	#[tokio::test]
	async fn resume_backs_off_an_unreadable_log_rather_than_closing_it() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		h.session_store
			.mutate(&session.session_id, |existing| {
				let mut session = existing?.clone();
				session.events.last_mut()?.event_bytes = b"not an event".to_vec();
				Some(session)
			})
			.await
			.unwrap();

		resume_all(&h).await;

		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert!(recorded.completed_at.is_none());
		assert!(h.manager.session_retry_at.lock().unwrap().contains_key(&session.session_id));
		assert!(broadcast_txs(&h).await.is_empty());
	}

	#[tokio::test]
	async fn settled_spend_reported_gone_stays_settled() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		let settled = Some(SessionResolution::Settled(SessionSpend {
			txid: session.fallback.compute_txid(),
			kind: SpendKind::Fallback,
		}));
		// Settled, but its log isn't closed yet.
		h.session_store
			.mutate(&session.session_id, |existing| {
				let mut session = existing?.clone();
				session.resolution = settled.clone();
				Some(session)
			})
			.await
			.unwrap();

		// A reorg deeper than `ANTI_REORG_DELAY` drops it.
		h.manager.on_txs_gone(&[session.fallback.compute_txid()]).await.unwrap();
		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert_eq!(recorded.resolution, settled);
	}

	#[tokio::test]
	async fn pending_fallback_is_given_up_on() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], NEVER_EXPIRES).await;
		h.manager.cancel_session(session.session_id).await.unwrap();
		resume(&h, &session.persister).await.unwrap();
		broadcast_txs(&h).await;

		backdate_last_event(&h, session.session_id, PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS + 1)
			.await;
		resume_all(&h).await;
		assert!(broadcast_txs(&h).await.is_empty());
		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert_eq!(recorded.resolution, None);
		assert!(recorded.completed_at.is_some());
		assert!(matches!(replay(&session.persister).await, ReceiveSession::Closed(_)));
	}

	#[tokio::test]
	async fn expired_fallback_is_given_up_on() {
		let h = harness().await;
		let session = session_with_original(&h, &[outpoint(1, 0)], 1_600_000_000).await;
		backdate_last_event(&h, session.session_id, PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS + 1)
			.await;

		resume_all(&h).await;
		assert!(broadcast_txs(&h).await.is_empty());
		assert_eq!(
			status(&h, session.session_id).await,
			PayjoinSessionStatus::Failed { txid: None }
		);
		let recorded = h.session_store.get(&session.session_id).await.unwrap().unwrap();
		assert!(recorded.completed_at.is_some());
	}

	#[tokio::test]
	async fn cleanup_forgets_seen_inputs_past_retention() {
		let h = harness().await;
		let (old, recent) = (outpoint(1, 0), outpoint(2, 0));
		let now = unix_now();
		let store = &h.manager.payjoin_seen_inputs_store;
		let first_seen = now - PAYJOIN_SEEN_INPUT_RETENTION_SECS - 1;
		check_and_record_seen_input(store, old, new_session_id(), first_seen).await.unwrap();
		check_and_record_seen_input(store, recent, new_session_id(), now).await.unwrap();

		h.manager.cleanup_old_sessions().await.unwrap();
		assert!(store.get(&old).await.unwrap().is_none());
		assert!(store.get(&recent).await.unwrap().is_some());
	}
}
