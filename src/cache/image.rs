use bytes::Bytes;
use indexmap::IndexMap;
use tokio::sync::RwLock;

#[derive(Debug)]
pub enum Error {
    EntrySizeLimitExceedsTotalCapacity,
    ImageTooBigForEntry,
    ImageTooBigForCache,
    CacheFull
}

// TODO: Add last updated timestamp.
#[derive(Debug, Clone)]
pub struct ByteCacheEntry {
    pub bytes: Bytes
}

// Individual image destined for the image cache.
impl ByteCacheEntry {
    pub fn new(bytes: Bytes) -> Self {
        Self {
            bytes
        }
    }
}

pub struct ByteCache {
    bytes_table: RwLock<IndexMap<String, ByteCacheEntry>>,
    total_capacity: usize,
    entry_size_limit: usize
}

impl ByteCache {
    pub fn new() -> Self {
        Self {
            bytes_table: RwLock::new(IndexMap::new()),
            total_capacity: 0,
            entry_size_limit: 0,
        }
    }

    // With a total capacity in bytes.
    pub fn with_capacity(cap: usize) -> Self {
        let mut new = Self::new();

        new.total_capacity = cap;

        new
    }

    // With a limit for individual entry sizes.
    pub fn with_entry_size_limit(esl: usize) -> Self {
        let mut new = Self::new();

        new.entry_size_limit = esl;

        new
    }

    // With bot a total capacity limit and an individual entry size limit.
    pub fn with_capacity_and_entry_size_limit(cap: usize, esl: usize) -> Result<Self, Error> {
        if esl > cap {
            return Err(Error::EntrySizeLimitExceedsTotalCapacity)
        }

        let mut new = Self::new();

        new.total_capacity = cap;
        new.entry_size_limit = esl;

        Ok(new)
    }

    pub async fn get(&self, url: &str) -> Option<ByteCacheEntry> {
        self.bytes_table.read().await.get(url).cloned()
    }

    pub async fn size(&self) -> usize {
        let mut size: usize = 0;

        for (_, image) in self.bytes_table.read().await.iter() {
            size += image.bytes.len();
        }

        size
    }

    // Insert image using the url as key.
    // TODO: Freed space might need to be reserved. Hold and pass write lock between functions?
    pub async fn set(&self, url: String, bytes: Bytes) -> Result<Option<ByteCacheEntry>, Error> {
        // Remove the old entry so that a new entry will be added as last in the queue.
        let _ = self.bytes_table.write().await.shift_remove(&url);

        let image_cache_entry = ByteCacheEntry::new(bytes);

        self.free_size(image_cache_entry.bytes.len()).await?;

        Ok(self.bytes_table.write().await.insert(url, image_cache_entry))
    }

    // Free space. Size amount in bytes.
    async fn free_size(&self, size: usize) -> Result<(), Error> {
        // Size may not exceed the total capacity of the image cache.
        if size > self.total_capacity {
            return Err(Error::ImageTooBigForCache)
        }

        let cache_size = self.size().await;
        let size_to_be_freed = size.saturating_sub(self.total_capacity - cache_size);
        let mut size_freed: usize = 0;

        while size_freed < size_to_be_freed {
            let oldest_entry = self.pop()
                .await
                .expect("Image cache has no more entries, yet there isn't enough space.");

            size_freed += oldest_entry.bytes.len();
        }

        Ok(())
    }

    // Remove and return the oldest entry.
    pub async fn pop(&self) -> Option<ByteCacheEntry> {
        self.bytes_table
            .write()
            .await
            .shift_remove_index(0)
            .map(|(_, entry)| entry)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::cache::image::ByteCache;

    #[tokio::test]
    async fn set_bytes_cache_with_capacity_and_entry_size_limit_should_succeed() {
        let byte_cache = ByteCache::with_capacity_and_entry_size_limit(6, 6).unwrap();
        let bytes: Bytes = Bytes::from("abcdef");

        assert!(byte_cache.set("test".to_string(), bytes).await.is_ok())
    }
}
