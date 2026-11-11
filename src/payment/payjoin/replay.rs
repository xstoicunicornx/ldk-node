// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A payjoin receive session's replayed event log, and what a spend of the sender's inputs is to
//! the session.

use bitcoin::Transaction;
use payjoin::receive::v2::{ReceiveSession, Resolution, ResolvedBy};

use crate::payment::payjoin::payjoin_session::SpendKind;

/// A session's event log, replayed.
pub(crate) enum Replayed {
	/// The session in its current state, with its fallback transaction if it has one.
	Open(ReceiveSession, Option<Transaction>),
	/// The session expired, with its fallback transaction if it has one.
	Expired(Option<Transaction>),
	/// The log couldn't be replayed.
	Unreadable,
}

impl Replayed {
	/// The session's fallback transaction, if it got the sender's original.
	pub(crate) fn fallback(&self) -> Option<&Transaction> {
		match self {
			Replayed::Open(_, fallback) | Replayed::Expired(fallback) => fallback.as_ref(),
			Replayed::Unreadable => None,
		}
	}

	/// The session's fallback transaction, if it's pending: the session moved to pending it, or
	/// expired after it got the sender's original.
	pub(crate) fn pending_fallback(&self) -> Option<&Transaction> {
		match self {
			Replayed::Open(ReceiveSession::PendingFallback(pending), _) => {
				Some(pending.fallback_tx())
			},
			Replayed::Expired(fallback) => fallback.as_ref(),
			_ => None,
		}
	}

	/// What `tx` is to the session, if it spends the sender's inputs, along with the session's
	/// resolution if it classified `tx`.
	///
	/// That's the session's classification, if it can classify in its current state, e.g. not
	/// while pending its fallback. Otherwise only the fallback itself can be told apart from the
	/// payjoin, by the fallback's inputs.
	pub(crate) fn classify(&self, tx: &Transaction) -> Option<ClassifiedSpend> {
		let (state, fallback) = match self {
			Replayed::Open(state, fallback) => (Some(state), fallback.as_ref()),
			Replayed::Expired(fallback) => (None, fallback.as_ref()),
			Replayed::Unreadable => return None,
		};
		match state.and_then(|state| state.classify_tx(tx)) {
			Some(resolution) => Some(ClassifiedSpend {
				kind: resolution.resolved_by().into(),
				resolution: Some(resolution),
			}),
			None => Some(ClassifiedSpend {
				kind: fallback_spend_kind(tx, fallback?)?,
				resolution: None,
			}),
		}
	}
}

/// What a spend of the sender's inputs is to a session, as [`Replayed::classify`] tells.
pub(crate) struct ClassifiedSpend {
	pub(crate) kind: SpendKind,
	/// The session's resolution, if it classified the spend.
	pub(crate) resolution: Option<Resolution>,
}

impl From<ResolvedBy> for SpendKind {
	fn from(resolved_by: ResolvedBy) -> Self {
		match resolved_by {
			ResolvedBy::Payjoin => SpendKind::Payjoin,
			ResolvedBy::Fallback => SpendKind::Fallback,
			_ => SpendKind::Unrecognized,
		}
	}
}

/// What `tx` is to a session that can't classify it, if it spends the inputs of the session's
/// `fallback_tx`: only the fallback itself can be told apart from the payjoin.
fn fallback_spend_kind(tx: &Transaction, fallback_tx: &Transaction) -> Option<SpendKind> {
	if !spends_any_input_of(tx, fallback_tx) {
		return None;
	}
	if tx.compute_txid() == fallback_tx.compute_txid() {
		Some(SpendKind::Fallback)
	} else {
		Some(SpendKind::Unrecognized)
	}
}

/// Whether `tx` spends any of the inputs of `fallback_tx`, i.e. any of the sender's.
fn spends_any_input_of(tx: &Transaction, fallback_tx: &Transaction) -> bool {
	tx.input.iter().any(|txin| {
		fallback_tx.input.iter().any(|sender| sender.previous_output == txin.previous_output)
	})
}
