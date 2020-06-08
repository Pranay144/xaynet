use crate::{
    crypto::ByteObject,
    mask::{BoundType, DataType, EncryptedMaskSeed, GroupType, MaskConfig, MaskObject, ModelType},
    state_machine::coordinator::RoundSeed,
    CoordinatorPublicKey,
    CoordinatorSecretKey,
    LocalSeedDict,
    SeedDict,
    SumDict,
    SumParticipantEphemeralPublicKey,
    SumParticipantPublicKey,
    UpdateParticipantPublicKey,
};
use redis::{aio::MultiplexedConnection, AsyncCommands, Client, RedisError, RedisResult};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// A placeholder for the later coordinator state struct.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CoordinatorState {
    // credentials
    pk: CoordinatorPublicKey, // 32 bytes
    sk: CoordinatorSecretKey, // 32 bytes

    // round parameters
    sum: f64,
    update: f64,
    seed: RoundSeed,
    min_sum: usize,
    min_update: usize,

    /// The masking configuration
    mask_config: MaskConfig,
}

impl Default for CoordinatorState {
    fn default() -> Self {
        let pk = CoordinatorPublicKey::zeroed();
        let sk = CoordinatorSecretKey::zeroed();
        let sum = 0.4_f64;
        let update = 0.5_f64;
        let seed = RoundSeed::zeroed();
        let min_sum = 1_usize;
        let min_update = 3_usize;
        let mask_config = MaskConfig {
            group_type: GroupType::Prime,
            data_type: DataType::F32,
            bound_type: BoundType::B0,
            model_type: ModelType::M3,
        };
        Self {
            pk,
            sk,
            sum,
            update,
            seed,
            min_sum,
            min_update,
            mask_config,
        }
    }
}

#[derive(Clone)]
pub struct RedisStore {
    raw_connection: MultiplexedConnection,
    semaphore: Arc<Semaphore>,
}

pub struct Connection {
    connection: MultiplexedConnection,
    _permit: OwnedSemaphorePermit,
}

impl RedisStore {
    /// Create a new store. `url` is the URL to connect to the redis
    /// instance, and `n` is the maximum number of concurrent
    /// connections to the store.
    pub async fn new<S: Into<String>>(url: S, n: usize) -> Result<Self, RedisError> {
        let client = Client::open(url.into())?;
        let connection = client.get_multiplexed_tokio_connection().await?;
        Ok(Self {
            raw_connection: connection,
            semaphore: Arc::new(Semaphore::new(n)),
        })
    }

    pub async fn connection(self) -> Connection {
        let _permit = self.semaphore.acquire_owned().await;
        Connection {
            connection: self.raw_connection,
            _permit,
        }
    }
}

impl Connection {
    /// Retrieve the [`CoordinatorState`].
    pub async fn get_coordinator_state(mut self) -> Result<CoordinatorState, RedisError> {
        self.connection.get("coordinator_state").await
    }

    /// Store the [`CoordinatorState`].
    /// If the coordinator state already exists, it is overwritten.
    pub async fn set_coordinator_state(mut self, state: &CoordinatorState) -> RedisResult<()> {
        self.connection.set("coordinator_state", state).await
    }

    /// Retrieve the entries [`SumDict`].
    pub async fn get_sum_dict(mut self) -> Result<SumDict, RedisError> {
        let result: Vec<(SumParticipantPublicKey, SumParticipantEphemeralPublicKey)> =
            self.connection.hgetall("sum_dict").await?;
        Ok(result.into_iter().collect())
    }

    /// Store a new [`SumDict`] entry.
    /// Returns `1` if field is a new and `0` if field already exists.
    pub async fn add_sum_participant(
        mut self,
        pk: &SumParticipantPublicKey,
        ephm_pk: &SumParticipantEphemeralPublicKey,
    ) -> Result<usize, RedisError> {
        self.connection.hset_nx("sum_dict", pk, ephm_pk).await
    }

    /// Remove an entry in the [`SumDict`].
    /// Returns `1` if field was deleted and `0` if field does not exists.
    pub async fn remove_sum_dict_entry(
        mut self,
        pk: &SumParticipantPublicKey,
    ) -> Result<usize, RedisError> {
        self.connection.hdel("sum_dict", pk).await
    }

    /// Retrieve the length of the [`SumDict`].
    pub async fn get_sum_dict_len(mut self) -> Result<usize, RedisError> {
        self.connection.hlen("sum_dict").await
    }

    /// Retrieve the sum_pks of the [`SumDict`].
    pub async fn get_sum_pks(mut self) -> Result<HashSet<SumParticipantPublicKey>, RedisError> {
        self.connection.hkeys("sum_dict").await
    }

    /// Retrieve [`SeedDict`] entry for the given sum participant.
    pub async fn get_seed_dict_for_sum_pk(
        mut self,
        sum_pk: &SumParticipantPublicKey,
    ) -> Result<HashMap<UpdateParticipantPublicKey, EncryptedMaskSeed>, RedisError> {
        let result: Vec<(UpdateParticipantPublicKey, EncryptedMaskSeed)> =
            self.connection.hgetall(sum_pk).await?;
        Ok(result.into_iter().collect())
    }

    /// Retrieve the whole [`SeedDict`].
    pub async fn get_seed_dict(mut self) -> Result<SeedDict, RedisError> {
        let sum_pks: Vec<SumParticipantPublicKey> = self.connection.hkeys("sum_dict").await?;

        let mut seed_dict: SeedDict = SeedDict::new();
        for sum_pk in sum_pks {
            let sum_pk_seed_dict = self.connection.hgetall(sum_pk).await?;
            seed_dict.insert(sum_pk, sum_pk_seed_dict);
        }

        Ok(seed_dict)
    }

    /// Update the [`SeedDict`] with the seeds from the given update
    /// participant, and return the number of participants that already submitted an update.
    pub async fn update_seed_dict(
        mut self,
        update_pk: &UpdateParticipantPublicKey,
        update: &LocalSeedDict,
    ) -> RedisResult<()> {
        let mut pipe = redis::pipe();
        pipe.sadd("update_participants", update_pk).ignore();
        for (sum_pk, encr_seed) in update {
            pipe.hset_nx(sum_pk, update_pk, encr_seed).ignore();
        }
        pipe.atomic().query_async(&mut self.connection).await
    }

    /// Update the [`MaskDict`] with the given [`MaskObject`].
    /// The score/counter of the given mask is incremented by `1`.
    pub async fn incr_mask_count(mut self, mask: &MaskObject) -> RedisResult<()> {
        redis::pipe()
            .zincr("mask_dict", bincode::serialize(mask).unwrap(), 1_usize)
            .query_async(&mut self.connection)
            .await?;
        Ok(())
    }

    /// Retrieve the two masks with the highest score.
    pub async fn get_best_masks(mut self) -> Result<Vec<(MaskObject, usize)>, RedisError> {
        let result: Vec<(Vec<u8>, usize)> = self
            .connection
            .zrevrange_withscores("mask_dict", 0, 1)
            .await?;

        Ok(result
            .into_iter()
            .map(|(mask, count)| (bincode::deserialize(&mask).unwrap(), count))
            .collect())
    }

    pub async fn schedule_snapshot(mut self) -> RedisResult<()> {
        redis::cmd("BGSAVE")
            .arg("SCHEDULE")
            .query_async(&mut self.connection)
            .await?;
        Ok(())
    }

    /// Delete all data in the current database.
    pub async fn flushdb(mut self) -> RedisResult<()> {
        redis::cmd("FLUSHDB")
            .arg("ASYNC")
            .query_async(&mut self.connection)
            .await
    }

    /// Delete the dictionaries [`SumDict`], [`SeedDict`] and [`MaskDict`].
    pub async fn flush_dicts(mut self) -> RedisResult<()> {
        let sum_pks: Vec<SumParticipantPublicKey> = self.connection.hkeys("sum_dict").await?;
        let mut pipe = redis::pipe();

        // delete sum dict
        pipe.del("sum_dict").ignore();

        //delete seed dict
        pipe.del("update_participants").ignore();
        for sum_pk in sum_pks {
            pipe.del(sum_pk).ignore();
        }

        //delete mask dict
        pipe.del("mask_dict").ignore();
        pipe.atomic().query_async(&mut self.connection).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{EncryptKeyPair, SigningKeyPair},
        mask::{BoundType, DataType, GroupType, MaskConfig, MaskObject, ModelType},
    };
    use num::{bigint::BigUint, traits::identities::Zero};

    fn create_mask(byte_size: usize) -> MaskObject {
        let config = MaskConfig {
            group_type: GroupType::Prime,
            data_type: DataType::F32,
            bound_type: BoundType::B0,
            model_type: ModelType::M3,
        };

        MaskObject::new(config, vec![BigUint::zero(); byte_size])
    }

    async fn create_redis_store() -> RedisStore {
        RedisStore::new("redis://127.0.0.1/", 10).await.unwrap()
    }

    async fn flush_db(store: &RedisStore) {
        store.clone().connection().await.flushdb().await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_set_and_get_coordinator_state() {
        // test the writing and reading of the coordinator state
        let store = create_redis_store().await;
        flush_db(&store).await;

        let set_state = CoordinatorState::default();
        store
            .clone()
            .connection()
            .await
            .set_coordinator_state(&set_state)
            .await
            .unwrap();

        let get_state = store
            .connection()
            .await
            .get_coordinator_state()
            .await
            .unwrap();

        assert_eq!(set_state, get_state)
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_best_masks_one_mask() {
        // test the writing and reading of one mask
        let store = create_redis_store().await;
        flush_db(&store).await;

        let new_mask = create_mask(10);
        store
            .clone()
            .connection()
            .await
            .incr_mask_count(&new_mask)
            .await
            .unwrap();

        let best_masks = store.connection().await.get_best_masks().await.unwrap();
        assert!(best_masks.len() == 1);
        let (best_mask, count) = best_masks.into_iter().next().unwrap();
        assert_eq!(best_mask, new_mask);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_best_masks_two_masks() {
        // test the writing and reading of two masks
        // the first mask is incremented twice
        let store = create_redis_store().await;
        flush_db(&store).await;

        let new_mask_1 = create_mask(10);
        store
            .clone()
            .connection()
            .await
            .incr_mask_count(&new_mask_1)
            .await
            .unwrap();
        store
            .clone()
            .connection()
            .await
            .incr_mask_count(&new_mask_1)
            .await
            .unwrap();

        let new_mask_2 = create_mask(100);
        store
            .clone()
            .connection()
            .await
            .incr_mask_count(&new_mask_2)
            .await
            .unwrap();

        let best_masks = store.connection().await.get_best_masks().await.unwrap();
        assert!(best_masks.len() == 2);
        let mut best_masks_iter = best_masks.into_iter();

        let (first_mask, count) = best_masks_iter.next().unwrap();
        assert_eq!(first_mask, new_mask_1);
        assert_eq!(count, 2);
        let (second_mask, count) = best_masks_iter.next().unwrap();
        assert_eq!(second_mask, new_mask_2);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_best_masks_no_mask() {
        // ensure that get_best_masks returns an empty vec if no mask exist
        let store = create_redis_store().await;
        flush_db(&store).await;

        let best_masks = store.connection().await.get_best_masks().await.unwrap();
        assert!(best_masks.is_empty())
    }

    #[tokio::test]
    #[ignore]
    async fn test_sum_dict() {
        // test multiple sum dict related methods
        let store = create_redis_store().await;
        flush_db(&store).await;

        // create two entries and write them into redis
        let mut entries = vec![];
        for _ in 0..2 {
            let SigningKeyPair { public: pk, .. } = SigningKeyPair::generate();
            let EncryptKeyPair { public: epk, .. } = EncryptKeyPair::generate();
            entries.push((pk.clone(), epk.clone()));

            let add_new_key = store
                .clone()
                .connection()
                .await
                .add_sum_participant(&pk, &epk)
                .await
                .unwrap();
            // 1: "new a key", 0: "key already exist"
            assert_eq!(add_new_key, 1)
        }

        // ensure that add_sum_participant returns 0 if the key already exist
        let (pk, epk) = entries.iter().next().unwrap();
        let key_already_exist = store
            .clone()
            .connection()
            .await
            .add_sum_participant(pk, epk)
            .await
            .unwrap();
        assert_eq!(key_already_exist, 0);

        // ensure that get_sum_dict_len returns 2
        let len_of_sum_dict = store
            .clone()
            .connection()
            .await
            .get_sum_dict_len()
            .await
            .unwrap();
        assert_eq!(len_of_sum_dict, 2);

        // read the written sum keys
        // ensure they are equal
        let sum_pks = store
            .clone()
            .connection()
            .await
            .get_sum_pks()
            .await
            .unwrap();
        for (sum_pk, _) in entries.iter() {
            assert!(sum_pks.contains(sum_pk));
        }

        // remove both sum entries
        for (sum_pk, _) in entries.iter() {
            let remove_sum_pk = store
                .clone()
                .connection()
                .await
                .remove_sum_dict_entry(sum_pk)
                .await
                .unwrap();
            // 1: "key removed", 0: "key does not exist"
            assert_eq!(remove_sum_pk, 1);
        }

        // ensure that get_sum_dict an empty sum dict
        let sum_dict = store
            .clone()
            .connection()
            .await
            .get_sum_dict()
            .await
            .unwrap();
        assert_eq!(sum_dict.len(), 0);
    }

    #[tokio::test]
    #[ignore]
    async fn test_flush_dicts_return() {
        let store = create_redis_store().await;
        flush_db(&store).await;

        let res = store.clone().connection().await.flushdb().await;
        assert!(res.is_ok())
    }
}
