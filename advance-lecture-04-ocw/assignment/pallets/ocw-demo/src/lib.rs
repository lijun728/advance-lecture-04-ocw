//! A demonstration of an offchain worker that sends onchain callbacks

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use core::{convert::TryInto, fmt};
use frame_support::{
	debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult,
};
use parity_scale_codec::{Decode, Encode};

use frame_system::{
	self as system, ensure_none, ensure_signed,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		SignedPayload, SigningTypes, Signer, SubmitTransaction,
	},
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain as rt_offchain,
	offchain::{
		storage::StorageValueRef,
		storage_lock::{StorageLock, BlockAndTime},
	},
	transaction_validity::{
		InvalidTransaction, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
};
use sp_std::{
	prelude::*, str,
	collections::vec_deque::VecDeque,
};

use serde::{Deserialize, Deserializer};

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When an offchain worker is signing transactions it's going to request keys from type
/// `KeyTypeId` via the keystore to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
pub const NUM_VEC_LEN: usize = 10;
/// The type to sign and send transactions.
pub const UNSIGNED_TXS_PRIORITY: u64 = 100;

// We are fetching information from the github public API about organization`substrate-developer-hub`.
//----------- pub const HTTP_REMOTE_REQUEST: &str = "https://api.github.com/orgs/substrate-developer-hub";
pub const HTTP_REMOTE_REQUEST: &str = "https://api.coincap.io/v2/assets/polkadot";
// pub const HTTP_HEADER_USER_AGENT: &str = "jimmychu0807";

pub const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds
pub const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
pub const LOCK_BLOCK_EXPIRATION: u32 = 3; // in block number
//-----job add by lijun
pub  const PRICE: f32 = 1000.0; 


/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Payload<Public> {
	price: u32,
	public: Public
}

impl <T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

// ref: https://serde.rs/container-attrs.html#crate
//----job add BEGIN -----
#[allow(non_snake_case)]
#[derive(Deserialize, Encode, Decode, Clone, Default)]
struct PriceData {
	#[serde(deserialize_with = "de_string_to_bytes")]
	priceUsd: Vec<u8>,
}

#[allow(non_snake_case)]
#[derive(Deserialize, Encode, Decode, Clone, Default)]
struct PriceInfo {
	data: PriceData,
	timestamp: u64,
}
//--- job add  END-------

// -----job delete BEGIN----
// #[derive(Deserialize, Encode, Decode, Default)]
// struct GithubInfo {
	// Specify our own deserializing function to convert JSON string to vector of bytes
	// #[serde(deserialize_with = "de_string_to_bytes")]
	// login: Vec<u8>,
	// #[serde(deserialize_with = "de_string_to_bytes")]
	// blog: Vec<u8>,
	// public_repos: u32,
// }
//----- job delete END-----

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

//---job delete BEGIN----
// impl fmt::Debug for GithubInfo {
	// `fmt` converts the vector of bytes inside the struct back to string for
	//   more friendly display.
	// fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// write!(
			// f,
			// "{{ login: {}, blog: {}, public_repos: {} }}",
			// str::from_utf8(&self.login).map_err(|_| fmt::Error)?,
			// str::from_utf8(&self.blog).map_err(|_| fmt::Error)?,
			// &self.public_repos
		// )
	// }
// }
//-----job delete END------

//-----job add BEGIN----
impl fmt::Debug for PriceInfo {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"{{ price: {}, timestamp: {}}}",
			str::from_utf8(&self.data.priceUsd).map_err(|_| fmt::Error)?,
			self.timestamp
		)
	}
}
//-----job add END------

/// This is the pallet's configuration trait
pub trait Trait: system::Trait + CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as Example {
		/// A vector of recently submitted numbers. Bounded by NUM_VEC_LEN
		//----job delete by lijun  Numbers get(fn numbers): VecDeque<u32>;
		Prices get(fn numbers): VecDeque<u32>;
	}
}

decl_event!(
	/// Events generated by the module.
	pub enum Event<T>
	where
		AccountId = <T as system::Trait>::AccountId,
	{
		/// Event generated when a new number is accepted to contribute to the average.
		//-----job delete by lijun  NewNumber(Option<AccountId>, u32),
		NewPrice(Option<AccountId>, u32),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		// Error returned when not sure which ocw function to executed
		UnknownOffchainMux,

		// Error returned when making signed transactions in off-chain worker
		NoLocalAcctForSigning,
		OffchainSignedTxError,

		// Error returned when making unsigned transactions in off-chain worker
		OffchainUnsignedTxError,

		// Error returned when making unsigned transactions with signed payloads in off-chain worker
		OffchainUnsignedTxSignedPayloadError,

		// Error returned when fetching github info
		HttpFetchingError,
       //----job add BEGIN---
		CanNotGetLock,
		PriceParseError
		//----- job add END----
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
        /*-----job delete BEGIN ---- 
		#[weight = 10000]
	 
		pub fn submit_number_signed(origin, number: u32) -> DispatchResult {
			let who = ensure_signed(origin)?;
			debug::info!("submit_number_signed: ({}, {:?})", number, who);
			Self::append_or_replace_number(number);

			Self::deposit_event(RawEvent::NewNumber(Some(who), number));
			Ok(())
		}

		#[weight = 10000]
		pub fn submit_number_unsigned(origin, number: u32) -> DispatchResult {
			let _ = ensure_none(origin)?;
			debug::info!("submit_number_unsigned: {}", number);
			Self::append_or_replace_number(number);

			Self::deposit_event(RawEvent::NewNumber(None, number));
			Ok(())
		}
		-----job delete by lijun EDN */

		#[weight = 10000]
		pub fn submit_number_unsigned_with_signed_payload(origin, payload: Payload<T::Public>,
			_signature: T::Signature) -> DispatchResult
		{
			let _ = ensure_none(origin)?;
			let Payload { price, public } = payload;
			debug::info!("submit_number_unsigned_with_signed_payload: ({}, {:?})", price, public);
			Self::append_or_replace_price(price);

			Self::deposit_event(RawEvent::NewPrice(None, price));
			Ok(())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			debug::info!("Entering off-chain worker");

			/*----job delete by lijun  BEGIN
			// Here we are showcasing various techniques used when running off-chain workers (ocw)
			// 1. Sending signed transaction from ocw
			// 2. Sending unsigned transaction from ocw
			// 3. Sending unsigned transactions with signed payloads from ocw
			// 4. Fetching JSON via http requests in ocw
			const TX_TYPES: u32 = 4;
			let modu = block_number.try_into().map_or(TX_TYPES, |bn: u32| bn % TX_TYPES);
			let result = match modu {
				0 => Self::offchain_signed_tx(block_number),
				1 => Self::offchain_unsigned_tx(block_number),
				2 => Self::offchain_unsigned_tx_signed_payload(block_number),
				3 => Self::fetch_github_info(),
				_ => Err(Error::<T>::UnknownOffchainMux),
			};

			if let Err(e) = result {
				debug::error!("offchain_worker error: {:?}", e);
			}

			job  delete by lijun END -----*/

			//----job add by lijun BWGIN ----
			match Self::fetch_github_info() {
				Ok(info) => {
					debug::info!("[XXX_DEBUG] offchain_worker success: {:?}", info);
					if let Err(err) = Self::offchain_unsigned_tx_signed_payload(info) {
						debug::error!("[XXX_DEBUG] offchain_worker offchain_unsigned_tx_signed_payload error: {:?}", err);
					}
				},
				Err(e) => {
					debug::error!("[XXX_DEBUG] offchain_worker fetch_github_info error: {:?}", e);
				}
			}
			// -----job add by lijun END -----
		}
	}
}

impl<T: Trait> Module<T> {
	/*----job delete by lijun BEGIN ----
	fn append_or_replace_number(number: u32) {
		
		Numbers::mutate(|numbers| {
			if numbers.len() == NUM_VEC_LEN {
				let _ = numbers.pop_front();
			}
			numbers.push_back(number);
			debug::info!("Number vector: {:?}", numbers);
		});
		jb delete by lijun END -----*/

		//---job add  by lijun BEGIN-----
	fn append_or_replace_price(price: u32) {
		Prices::mutate(|prices| {
			if prices.len() == NUM_VEC_LEN {
				let _ = prices.pop_front();
			}
			prices.push_back(price);
			debug::info!("[XXX_DEBUG] Prices vector: {:?}", prices);
		});
		// ---job add by lijun END------
	}

//--job delete by lijun  fn fetch_github_info() -> Result<(), Error<T>> {
	fn fetch_github_info() -> Result<(PriceInfo), Error<T>> {
		let s_info = StorageValueRef::persistent(b"offchain-demo::gh-info");

/*-job delete  by lijun  BEGIN---
        if let Some(Some(gh_info)) = s_info.get::<GithubInfo>() {
			debug::info!("cached gh-info: {:?}", gh_info);
			return Ok(());
		}		
-----job delete by lijun  END ----*/

/*---job  add by lijun  BEGIN----*/
        if let Some(Some(price_info)) = s_info.get::<PriceInfo>() {
	      debug::info!("[XXX_DEBUG] before price-info: {:?}", price_info);
       }

		let mut lock = StorageLock::<BlockAndTime<Self>>::with_block_and_time_deadline(
			b"offchain-demo::lock", LOCK_BLOCK_EXPIRATION,
			rt_offchain::Duration::from_millis(LOCK_TIMEOUT_EXPIRATION)
		);


		let _guard = lock.try_lock().map_err(|_| <Error<T>>::CanNotGetLock);
		match Self::fetch_n_parse() {
			Ok(price_info) => {
				s_info.set(&price_info);
				Ok(price_info)
			}
			Err(err) => {
				Err(err)
            }
        }
        
    }

	/// Fetch from remote and deserialize the JSON to a struct
	fn fetch_n_parse() -> Result<PriceInfo, Error<T>> {
		let resp_bytes = Self::fetch_from_remote().map_err(|e| {
			debug::error!("fetch_from_remote error: {:?}", e);
			<Error<T>>::HttpFetchingError
		})?;

		let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::HttpFetchingError)?;
		// Print out our fetched JSON string
		debug::info!("{}", resp_str);

		// Deserializing JSON to struct, thanks to `serde` and `serde_derive`
		let price_info: PriceInfo =
			serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError)?;
		Ok(price_info)
	}


	fn fetch_from_remote() -> Result<Vec<u8>, Error<T>> {
		debug::info!("sending request to: {}", HTTP_REMOTE_REQUEST);


		let request = rt_offchain::http::Request::get(HTTP_REMOTE_REQUEST);

	
		let timeout = sp_io::offchain::timestamp()
			.add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));

		// For github API request, we also need to specify `user-agent` in http request header.
		//   See: https://developer.github.com/v3/#user-agent-required
		let pending = request
			/*---job del by lijun -----
			// .add_header("User-Agent", HTTP_HEADER_USER_AGENT)
			-------------------*/
			.deadline(timeout) // Setting the timeout time
			.send() // Sending the request out by the host
			.map_err(|_| <Error<T>>::HttpFetchingError)?;

		let response = pending
			.try_wait(timeout)
			.map_err(|_| <Error<T>>::HttpFetchingError)?
			.map_err(|_| <Error<T>>::HttpFetchingError)?;

		if response.code != 200 {
			debug::error!("Unexpected http request status code: {}", response.code);
			return Err(<Error<T>>::HttpFetchingError);
		}

		Ok(response.body().collect::<Vec<u8>>())
	}


	/*----- job delete by lijun BEGIN -----
	fn offchain_signed_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
		// We retrieve a signer and check if it is valid.
		//   Since this pallet only has one key in the keystore. We use `any_account()1 to
		//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
		//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
		let signer = Signer::<T, T::AuthorityId>::any_account();

		// Translating the current block number to number and submit it on-chain
		let number: u32 = block_number.try_into().unwrap_or(0);

		// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
		//   - `None`: no account is available for sending transaction
		//   - `Some((account, Ok(())))`: transaction is successfully sent
		//   - `Some((account, Err(())))`: error occured when sending the transaction
		let result = signer.send_signed_transaction(|_acct|
			// This is the on-chain function
			Call::submit_number_signed(number)
		);

		// Display error if the signed tx fails.
		if let Some((acc, res)) = result {
			if res.is_err() {
				debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
				return Err(<Error<T>>::OffchainSignedTxError);
			}
			// Transaction is sent successfully
			return Ok(());
		}

		// The case of `None`: no account is available for sending
		debug::error!("No local account available");
		Err(<Error<T>>::NoLocalAcctForSigning)
	}

	fn offchain_unsigned_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
		let number: u32 = block_number.try_into().unwrap_or(0);
		let call = Call::submit_number_unsigned(number);

		// `submit_unsigned_transaction` returns a type of `Result<(), ()>`
		//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.SubmitTransaction.html#method.submit_unsigned_transaction
		SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
			.map_err(|_| {
				debug::error!("Failed in offchain_unsigned_tx");
				<Error<T>>::OffchainUnsignedTxError
			})
	}
	---- job delete by lijun END -----*/

	fn offchain_unsigned_tx_signed_payload(price_info: PriceInfo) -> Result<(), Error<T>> {
		// Retrieve the signer to sign the payload
		let signer = Signer::<T, T::AuthorityId>::any_account();
		let price = Self::parse_price_info(&price_info)?;

		if let Some((_, res)) = signer.send_unsigned_transaction(
			|acct| Payload { price, public: acct.public.clone() },
			Call::submit_number_unsigned_with_signed_payload
		) {
			return res.map_err(|_| {
				debug::error!("Failed in offchain_unsigned_tx_signed_payload");
				<Error<T>>::OffchainUnsignedTxSignedPayloadError
			});
		}

		// The case of `None`: no account is available for sending
		debug::error!("No local account available");
		Err(<Error<T>>::NoLocalAcctForSigning)
	}

	fn parse_price_info(price_info: &PriceInfo) -> Result<u32, Error<T>> {
		let price_str = str::from_utf8(&price_info.data.priceUsd).map_err(|_| <Error<T>>::PriceParseError)?;
		let price: f32 = price_str.parse().map_err(|_| <Error<T>>::PriceParseError)?;
		Ok((price * PRICE) as u32)
	}
}

impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
		let valid_tx = |provide| ValidTransaction::with_tag_prefix("ocw-demo")
			.priority(UNSIGNED_TXS_PRIORITY)
			.and_provides([&provide])
			.longevity(3)
			.propagate(true)
			.build();

		match call {
			// Call::submit_number_unsigned(_number) => valid_tx(b"submit_number_unsigned".to_vec()),
			Call::submit_number_unsigned_with_signed_payload(ref payload, ref signature) => {
				if !SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone()) {
					return InvalidTransaction::BadProof.into();
				}
				valid_tx(b"submit_number_unsigned_with_signed_payload".to_vec())
			},
			_ => InvalidTransaction::Call.into(),
		}
	}
}

impl<T: Trait> rt_offchain::storage_lock::BlockNumberProvider for Module<T> {
	type BlockNumber = T::BlockNumber;
	fn current_block_number() -> Self::BlockNumber {
	  <frame_system::Module<T>>::block_number()
	}
}
