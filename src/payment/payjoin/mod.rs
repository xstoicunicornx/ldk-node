// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Holds a payment handler for sending and receiving Payjoin payments.

pub(crate) mod manager;
pub(crate) mod payjoin_session;
pub(crate) mod persist;
pub(crate) mod replay;
pub(crate) mod seen_inputs;

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::Txid;
use lightning::ln::channelmanager::PaymentId;
pub use manager::PayjoinReceiveSession;

use crate::{error::Error, payment::payjoin::manager::PayjoinManager};

/// The status of a Payjoin receive session, as returned by [`PayjoinPayment::status`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PayjoinSessionStatus {
	/// The session is waiting on the sender, or on a transaction spending the sender's inputs to
	/// confirm. A session whose cancellation was requested stays active until it is applied.
	Active,
	/// The payjoin transaction confirmed and the session completed.
	Completed {
		/// The payjoin transaction.
		txid: Txid,
	},
	/// The payjoin didn't complete, so the sender's fallback transaction pays instead. It is
	/// rebroadcast until it, or another spend of the sender's inputs, is seen, and the session
	/// ends once that confirms.
	FallbackPending {
		/// The sender's fallback transaction.
		fallback_txid: Txid,
	},
	/// The payjoin didn't complete.
	Failed {
		/// The transaction that settled the session: the sender's fallback, or another spend of
		/// the sender's inputs. `None` if none was seen, e.g. because the session ended before
		/// the sender sent its original transaction, or the fallback was given up on.
		txid: Option<Txid>,
	},
	/// The session was cancelled through [`PayjoinPayment::cancel`] and didn't complete.
	Cancelled {
		/// The sender's fallback transaction, if the session had received it. It is then
		/// broadcast and rebroadcast until it, or another spend of the sender's inputs, is seen.
		fallback_txid: Option<Txid>,
	},
}

/// The current time, in seconds since the UNIX epoch.
pub(crate) fn unix_now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_secs()
}

#[cfg(not(feature = "uniffi"))]
type FeeRate = bitcoin::FeeRate;
#[cfg(feature = "uniffi")]
type FeeRate = Arc<bitcoin::FeeRate>;

macro_rules! maybe_map_fee_rate_opt {
	($fee_rate_opt:expr) => {{
		#[cfg(not(feature = "uniffi"))]
		{
			$fee_rate_opt
		}
		#[cfg(feature = "uniffi")]
		{
			$fee_rate_opt.map(|f| *f)
		}
	}};
}

/// A payment handler allowing to receive [Payjoin] payments.
///
/// Should be retrieved by calling [`Node::payjoin_payment`].
///
/// [Payjoin]: https://payjoin.org
/// [`Node::payjoin_payment`]: crate::Node::payjoin_payment
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PayjoinPayment {
	/// `None` if no [`PayjoinConfig`] was set, in which case all methods fail.
	///
	/// [`PayjoinConfig`]: crate::config::PayjoinConfig
	manager: Option<Arc<PayjoinManager>>,
	is_running: Arc<RwLock<bool>>,
}

impl PayjoinPayment {
	pub(crate) fn new(manager: Option<Arc<PayjoinManager>>, is_running: Arc<RwLock<bool>>) -> Self {
		Self { manager, is_running }
	}

	fn manager(&self) -> Result<&PayjoinManager, Error> {
		self.manager.as_deref().ok_or(Error::PayjoinNotConfigured)
	}
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PayjoinPayment {
	/// Opens a Payjoin receive session, returning the BIP 21 URI to share with the sender and
	/// the identifier of the session.
	///
	/// `fee_rate` caps what we are willing to pay for the input we contribute. It defaults to
	/// the current on-chain fee estimate. The cap is fixed when the URI is created and the
	/// session may last up to 24 hours, so if fees rise above it before the sender responds,
	/// the payjoin is declined and the sender's original transaction pays instead.
	///
	/// Returns [`Error::PayjoinNotConfigured`] if no [`PayjoinConfig`] was set.
	///
	/// [`PayjoinConfig`]: crate::config::PayjoinConfig
	pub async fn receive(
		&self, amount_sats: u64, fee_rate: Option<FeeRate>,
	) -> Result<PayjoinReceiveSession, Error> {
		let manager = self.manager()?;

		if !*self.is_running.read().expect("lock") {
			return Err(Error::NotRunning);
		}

		let fee_rate_opt = maybe_map_fee_rate_opt!(fee_rate);
		manager.receive_payjoin(amount_sats, fee_rate_opt).await
	}

	/// Returns the status of the receive session `session_id`, as returned by [`Self::receive`].
	///
	/// Returns `None` for an unknown session. A session that completed, failed or was cancelled
	/// is forgotten a day after it ended, while its payment stays in the payment store.
	///
	/// Returns [`Error::PayjoinNotConfigured`] if no [`PayjoinConfig`] was set.
	///
	/// [`PayjoinConfig`]: crate::config::PayjoinConfig
	pub async fn status(
		&self, session_id: PaymentId,
	) -> Result<Option<PayjoinSessionStatus>, Error> {
		let manager = self.manager()?;
		manager.session_status(session_id).await
	}

	/// Cancels the receive session `session_id`, as returned by [`Self::receive`].
	///
	/// The cancellation is applied in the background, so [`Self::status`] reports the session as
	/// active until it is, and as [`PayjoinSessionStatus::Cancelled`] afterwards. If the session
	/// already received the sender's original transaction, that transaction is broadcast so that
	/// we still get paid. Cancelling a session again has no further effect.
	///
	/// Returns [`Error::InvalidPaymentId`] for an unknown session, and
	/// [`Error::PayjoinSessionNotCancellable`] if the session already ended, its fallback is
	/// already pending, or a transaction spending the sender's inputs was already seen, so that
	/// cancelling can't change how it settles.
	///
	/// Returns [`Error::PayjoinNotConfigured`] if no [`PayjoinConfig`] was set.
	///
	/// [`PayjoinConfig`]: crate::config::PayjoinConfig
	pub async fn cancel(&self, session_id: PaymentId) -> Result<(), Error> {
		let manager = self.manager()?;
		manager.cancel_session(session_id).await
	}
}
