// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{psbt::Input, Amount, BlockHash, FeeRate, Transaction, TxIn, Txid};

use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
use lightning::ln::channelmanager::PaymentId;
use lightning::log_warn;

use payjoin::io::fetch_ohttp_keys;
use payjoin::persist::OptionalTransitionOutcome;
use payjoin::receive::v2::{
	replay_event_log_async as replay_receiver_event_log_async, CreateRequestError,
	HasReplyableError, Initialized, MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown,
	PayjoinProposal, ProvisionalProposal, ReceiveSession, Receiver, ReceiverBuilder, ResolvedBy,
	SessionOutcome as ReceiverSessionOutcome, UncheckedOriginalPayload, WantsFeeRange, WantsInputs,
	WantsOutputs,
};
use payjoin::receive::InputPair;
use payjoin::ImplementationError;

use crate::chain::ChainSource;
use crate::config::{
	Config, PayjoinConfig, PAYJOIN_FALLBACK_REBROADCAST_TIMEOUT_SECS, PAYJOIN_MAX_RESPONSE_BYTES,
	PAYJOIN_RELAY_TIMEOUT_SECS, PAYJOIN_RETRY_DELAY, PAYJOIN_SEEN_INPUT_RETENTION_SECS,
	PAYJOIN_SESSION_CLEANUP_AGE_SECS,
};
use crate::fee_estimator::{ConfirmationTarget, FeeEstimator, OnchainFeeEstimator};
use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::payment::payjoin::payjoin_session::{PayjoinSession, PayjoinSessionKind, PayjoinStatus};
use crate::payment::payjoin::persist::KVStorePayjoinReceiverPersister;
use crate::payment::payjoin::seen_inputs::{
	check_and_record_seen_input, forget_seen_inputs, prune_seen_inputs,
};
use crate::payment::payjoin::PayjoinSessionStatus;
use crate::payment::store::TransactionType;

use crate::types::{Broadcaster, PayjoinSeenInputsStore, PayjoinSessionStore};
use crate::wallet::{PayjoinFallbackStatus, Wallet};
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

		if payjoin_config.ohttp_relays.is_empty() {
			log_error!(self.logger, "No OHTTP relays configured.");
			return Err(Error::PayjoinNotConfigured);
		}

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

		let address = self.wallet.get_new_address().await?;
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
		&self, session: ReceiveSession, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<(), Error> {
		let Some(mut session) = self.settle_session(session, persister).await? else {
			return Ok(());
		};
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
					// `settle_session` closes the session once wallet sync sees a transaction
					// spending the sender's inputs, so there is nothing to do until then.
					log_debug!(
						self.logger,
						"Payjoin session {} is waiting for the sender to broadcast.",
						persister.session_id()
					);
					return Ok(());
				},
				ReceiveSession::PendingFallback(pending) => {
					let fallback_tx = pending.fallback_tx().clone();
					let mut payjoin_session = persister.get_session().await?;
					self.close_session_with_fallback(&mut payjoin_session, Some(&fallback_tx))
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
	/// Runs after [`Self::settle_session`], so only for a session nothing spends the sender's
	/// inputs of yet. Returns the session to keep processing: [`ReceiveSession::PendingFallback`]
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
		Ok(Some(session.user_status()))
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
		if session.status != PayjoinStatus::Active {
			return Err(Error::PayjoinSessionNotCancellable);
		}
		// Once something spends the sender's inputs, the session settles on that, so cancelling
		// would change nothing.
		if let Some(fallback_tx) = session.fallback_tx() {
			let inputs = fallback_tx.input.iter().map(|txin| txin.previous_output);
			if !self.wallet.spends_of_outpoints(inputs).is_empty() {
				return Err(Error::PayjoinSessionNotCancellable);
			}
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
				if existing.status != PayjoinStatus::Active {
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

	/// Settles a session against the transactions wallet sync has seen spending the sender's
	/// inputs.
	///
	/// [`ReceiveSession::classify_tx`] tells whether such a spend is the payjoin, the sender's
	/// fallback, or neither. A payjoin is tagged as such on the payment as soon as it is seen. The
	/// session closes once the spend is confirmed through [`ANTI_REORG_DELAY`], and until then the
	/// protocol isn't advanced any further, as a proposal could no longer confirm.
	///
	/// Returns the session if nothing spends the sender's inputs yet, so the protocol should
	/// continue, or `None` if something does.
	async fn settle_session(
		&self, session: ReceiveSession, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<Option<ReceiveSession>, Error> {
		// Recorded once the sender's original transaction passed the broadcast suitability check,
		// which is the first state `classify_tx` supports.
		let Some(fallback_tx) = persister.get_session().await?.fallback_tx().cloned() else {
			return Ok(Some(session));
		};

		let spends = self
			.wallet
			.spends_of_outpoints(fallback_tx.input.iter().map(|txin| txin.previous_output));
		// Spends come most confirmed first, which is the one `classify_tx` asks to classify.
		let Some((tx, confirmations, resolution)) = spends.into_iter().find_map(|(tx, confs)| {
			session.classify_tx(&tx).map(|resolution| (tx, confs, resolution))
		}) else {
			return Ok(Some(session));
		};

		let session_id = persister.session_id();
		let txid = tx.compute_txid();
		let resolved_by = resolution.resolved_by();
		if resolved_by == ResolvedBy::Payjoin {
			self.wallet.classify_payjoin(txid, Some(&tx)).await?;
		}

		if confirmations < ANTI_REORG_DELAY {
			log_debug!(
				self.logger,
				"Payjoin session {} was resolved by {:?} transaction {} with {} confirmations. Closing it at {}.",
				session_id,
				resolved_by,
				txid,
				confirmations,
				ANTI_REORG_DELAY
			);
			return Ok(None);
		}

		// A spend that lost to this one can no longer confirm, but wallet sync leaves its payment
		// pending. For example, the payjoin after a reorg let the fallback win. Done before the
		// session is marked settled, so a failure is retried on the next tick.
		for lost in self.wallet.lost_conflicts_of(&tx) {
			let Some(lost_resolution) = session.classify_tx(&lost) else {
				// Lost on one of our own inputs, not the sender's.
				continue;
			};
			let tx_type = (lost_resolution.resolved_by() == ResolvedBy::Payjoin)
				.then_some(TransactionType::Payjoin);
			self.wallet.fail_payment_lost_to_conflict(lost.compute_txid(), tx_type).await?;
		}
		self.forget_spent_sender_inputs(&tx, &fallback_tx).await;

		// Our record goes first: resumption only picks up active sessions, so if persisting the
		// close event fails afterwards, the session is still never replayed.
		let mut payjoin_session = persister.get_session().await?;
		payjoin_session.status = match resolved_by {
			ResolvedBy::Payjoin => {
				log_info!(
					self.logger,
					"Payjoin session {} completed: payjoin transaction {} confirmed.",
					session_id,
					txid
				);
				PayjoinStatus::Completed
			},
			ResolvedBy::Fallback => {
				log_info!(
					self.logger,
					"Payjoin session {} failed: the sender's fallback transaction {} confirmed.",
					session_id,
					txid
				);
				PayjoinStatus::Failed
			},
			_ => {
				log_warn!(
					self.logger,
					"Payjoin session {} failed: the sender's inputs were spent by unrecognized transaction {}.",
					session_id,
					txid
				);
				PayjoinStatus::Failed
			},
		};
		payjoin_session.resolution_txid = Some(txid);
		payjoin_session.completed_at.get_or_insert_with(|| {
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
		});
		self.payjoin_session_store.insert_or_update(payjoin_session).await?;

		if let Err(e) = session.close(resolution).save_async(persister).await {
			log_error!(
				self.logger,
				"Failed to record the close of payjoin session {}: {:?}",
				session_id,
				e
			);
		}
		Ok(None)
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
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to process the sender's directory response: {:?}",
					e
				);
				Err(Error::PersistenceFailed)
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

		let proposal = proposal
			.apply_broadcast_suitability(None, is_broadcast_suitable)
			.save_async(persister)
			.await
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to check the sender's original transaction for broadcast suitability: {:?}",
					e
				);
				Error::PersistenceFailed
			})?;

		// The sender's original transaction is the fallback: if the payjoin fails or times out,
		// broadcast it to ensure the receiver still gets paid. Its inputs are also what
		// `settle_session` looks for spends of.
		let mut session = persister.get_session().await?;

		session.set_fallback_tx(transaction);
		self.payjoin_session_store.insert_or_update(session).await?;

		log_info!(
			self.logger,
			"Fallback transaction received. This will be broadcast if the Payjoin fails"
		);

		Ok(ReceiveSession::MaybeInputsOwned(proposal))
	}

	async fn check_inputs_not_owned(
		&self, proposal: Receiver<MaybeInputsOwned>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let proposal = proposal
			.check_inputs_not_owned(&mut |outpoint| {
				self.wallet
					.is_my_outpoint(&outpoint)
					.map_err(|e| ImplementationError::from(e.to_string().as_str()))
			})
			.save_async(persister)
			.await
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to check whether the sender's inputs belong to us: {:?}",
					e
				);
				Error::PersistenceFailed
			})?;

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
		let proposal = transition.save_async(persister).await.map_err(|e| {
			log_error!(self.logger, "Failed to check the sender's inputs for reuse: {:?}", e);
			Error::PersistenceFailed
		})?;

		Ok(ReceiveSession::OutputsUnknown(proposal))
	}

	async fn identify_receiver_outputs(
		&self, proposal: Receiver<OutputsUnknown>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let proposal = proposal
			.identify_receiver_outputs(&mut |output_script| {
				self.wallet
					.is_mine(output_script.to_owned())
					.map_err(|e| ImplementationError::from(e.to_string().as_str()))
			})
			.save_async(persister)
			.await
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to identify our outputs in the sender's proposal: {:?}",
					e
				);
				Error::PersistenceFailed
			})?;
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
		let proposal =
			proposal.apply_fee_range(None, None).save_async(persister).await.map_err(|e| {
				log_error!(self.logger, "Failed to apply the payjoin fee range: {:?}", e);
				Error::PersistenceFailed
			})?;

		Ok(ReceiveSession::ProvisionalProposal(proposal))
	}

	async fn finalize_proposal(
		&self, proposal: Receiver<ProvisionalProposal>, persister: &KVStorePayjoinReceiverPersister,
	) -> Result<ReceiveSession, Error> {
		let proposal = proposal
			.finalize_proposal(|psbt| {
				self.wallet
					.process_psbt(psbt.clone())
					.map_err(|e| ImplementationError::from(e.to_string().as_str()))
			})
			.save_async(persister)
			.await
			.map_err(|e| {
				log_error!(self.logger, "Failed to finalize the payjoin proposal: {:?}", e);
				Error::PersistenceFailed
			})?;
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
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to process the sender's response to our payjoin proposal: {:?}",
					e
				);
				Err(Error::PersistenceFailed)
			},
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
				session.resolution_txid = session.fallback_tx().map(|tx| tx.compute_txid());

				self.payjoin_session_store.insert_or_update(session).await?;
			},
			ReceiverSessionOutcome::Aborted => {
				log_info!(self.logger, "Payjoin session was aborted.");
				self.close_session_with_fallback(&mut session, None).await;
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
				Err(e) if e.is_expired() => match recv_persister.get_session().await {
					Ok(mut session) => {
						self.close_session_with_fallback(&mut session, e.expiry_fallback_tx()).await
					},
					Err(err) => log_error!(
						self.logger,
						"Failed to close expired receiver session {session_id}: {err:?}"
					),
				},
				Err(e) => {
					log_error!(
						self.logger,
						"An error {:?} occurred while replaying receiver session",
						e
					);
					match self.payjoin_session_store.get(&session_id).await {
						Ok(Some(mut session)) => {
							self.close_session_with_fallback(&mut session, None).await;
						},
						Ok(None) => {
							log_error!(
								self.logger,
								"Payjoin session {} disappeared before it could be closed.",
								session_id
							);
						},
						Err(e) => {
							log_error!(
								self.logger,
								"Failed to read payjoin session {} while closing it: {:?}",
								session_id,
								e
							);
						},
					}
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

	/// Closes a session whose payjoin didn't complete and broadcasts its fallback transaction.
	///
	/// The broadcast queue doesn't survive a restart, so the session is persisted as
	/// [`PayjoinStatus::FallbackPending`] with its fallback before the fallback is queued, and
	/// [`Self::rebroadcast_pending_fallbacks`] keeps broadcasting it until it resolves.
	async fn close_session_with_fallback(
		&self, session: &mut PayjoinSession, fallback_tx: Option<&Transaction>,
	) {
		// Keep an earlier timestamp if payjoin's `close()` already ran
		session.completed_at.get_or_insert_with(|| {
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
		});

		let fallback_tx = fallback_tx.cloned().or_else(|| session.fallback_tx().cloned());

		if let Some(fallback_tx) = &fallback_tx {
			session.set_fallback_tx(fallback_tx.clone());
			session.status = PayjoinStatus::FallbackPending;
		} else {
			log_warn!(
				self.logger,
				"Payjoin session {} missing fallback transaction; closing as Failed without broadcast.",
				session.session_id
			);
			session.status = PayjoinStatus::Failed;
		}

		if let Err(close_err) = self.payjoin_session_store.insert_or_update(session.clone()).await {
			log_error!(
				self.logger,
				"Failed to close receiver session {}: {:?}",
				session.session_id,
				close_err
			);
		} else {
			log_info!(self.logger, "Closed failed receiver session: {}", session.session_id);
		}

		// Broadcast even if persisting failed: a broadcast that may not be retried beats none.
		if let Some(fallback_tx) = fallback_tx {
			self.broadcaster.broadcast(fallback_tx);
		}
	}

	/// Rebroadcasts the fallback transaction of every [`PayjoinStatus::FallbackPending`] session
	/// once per chain tip, and marks a session [`PayjoinStatus::Failed`] once the wallet sees its
	/// fallback, or a transaction double-spending it, confirmed through `ANTI_REORG_DELAY`.
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

		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(Duration::from_secs(0))
			.as_secs();

		for session in pending_sessions {
			let session_id = session.session_id;
			let Some(fallback_tx) = session.fallback_tx() else {
				log_warn!(
					self.logger,
					"Payjoin session {} is pending a fallback it doesn't have; marking it Failed.",
					session_id
				);
				self.resolve_pending_fallback(session_id, None).await;
				continue;
			};
			let fallback_txid = fallback_tx.compute_txid();

			match self.wallet.payjoin_fallback_status(fallback_tx) {
				PayjoinFallbackStatus::Confirmed => {
					log_info!(
						self.logger,
						"Fallback transaction {} of payjoin session {} confirmed.",
						fallback_txid,
						session_id
					);
					self.forget_spent_sender_inputs(fallback_tx, fallback_tx).await;
					if self.fail_lost_spends(fallback_tx, fallback_tx).await {
						self.resolve_pending_fallback(session_id, Some(fallback_txid)).await;
					}
				},
				PayjoinFallbackStatus::Conflicted(winner) => {
					log_info!(
						self.logger,
						"Fallback transaction {} of payjoin session {} was double-spent by {}.",
						fallback_txid,
						session_id,
						winner.compute_txid()
					);
					self.forget_spent_sender_inputs(&winner, fallback_tx).await;
					if self.fail_lost_spends(&winner, fallback_tx).await {
						self.resolve_pending_fallback(session_id, Some(winner.compute_txid()))
							.await;
					}
				},
				PayjoinFallbackStatus::Unresolved => {
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
						self.broadcaster.broadcast(fallback_tx.clone());
					}
				},
			}
		}
	}

	/// Fails the payments of the spends that lost to `winner`, a spend of a pending fallback's
	/// inputs confirmed through [`ANTI_REORG_DELAY`], which wallet sync would leave pending: the
	/// fallback we broadcast when the sender's payjoin won anyway, or the payjoin when the
	/// fallback won.
	///
	/// The session is already closed, so the losers can't be classified against it. Only those
	/// spending one of the sender's inputs, which `fallback_tx` spends, are failed, not ones that
	/// lost on an input of ours a payjoin spent. A payjoin keeps the tag it got when
	/// `settle_session` saw it. Returns whether all of them were failed, so the session is only
	/// resolved once they were and a failure is retried on the next tip.
	async fn fail_lost_spends(&self, winner: &Transaction, fallback_tx: &Transaction) -> bool {
		let spends_sender_input = |tx: &Transaction| {
			tx.input.iter().any(|txin| {
				fallback_tx
					.input
					.iter()
					.any(|sender| sender.previous_output == txin.previous_output)
			})
		};
		for lost in self.wallet.lost_conflicts_of(winner).into_iter().filter(spends_sender_input) {
			let lost_txid = lost.compute_txid();
			if let Err(e) = self.wallet.fail_payment_lost_to_conflict(lost_txid, None).await {
				log_error!(
					self.logger,
					"Failed to fail the payment of transaction {}, which lost to {}: {:?}. Will retry on the next chain tip.",
					lost_txid,
					winner.compute_txid(),
					e
				);
				return false;
			}
		}
		true
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
			.payjoin_session_store
			.mutate(&session_id, |existing| {
				let mut session = existing?.clone();
				(session.status == PayjoinStatus::FallbackPending).then(|| {
					session.status = PayjoinStatus::Failed;
					session.resolution_txid = resolution_txid;
					session
				})
			})
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
