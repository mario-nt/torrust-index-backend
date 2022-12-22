use std::collections::hash_map::Entry;
use std::collections::HashMap;
use bytes::Bytes;
use tokio::sync::RwLock;

// TODO: Move this to the settings.
const MAX_IMAGE_CACHE_SIZE: usize = 4_294_967_295;

// TODO: Add last updated timestamp.
#[derive(Debug, Clone)]
pub struct ImageCacheEntry {
    pub bytes: Bytes
}

impl ImageCacheEntry {
    pub fn new(bytes: Bytes) -> Self {
        Self {
            bytes
        }
    }

    pub fn update(&mut self, bytes: Bytes) {
        self.bytes = bytes;
    }
}

pub struct ImageCache {
    max_size: usize,
    images: RwLock<HashMap<String, ImageCacheEntry>>
}

impl ImageCache {
    pub fn new() -> Self {
        Self {
            max_size: MAX_IMAGE_CACHE_SIZE,
            images: RwLock::new(HashMap::new())
        }
    }

    // Insert image into cache using the url as key.
    pub async fn set(&self, url: String, bytes: Bytes) -> Option<ImageCacheEntry> {
        match self.images.write().await.entry(url) {
            Entry::Vacant(vacant) => {
                vacant.insert(ImageCacheEntry::new(bytes));

                None
            },
            Entry::Occupied(entry) => {
                let old_entry = entry.get().clone();

                let entry_mut = entry.into_mut();

                entry_mut.update(bytes);

                Some(old_entry)
            }
        }
    }

    pub async fn get(&self, url: &str) -> Option<ImageCacheEntry> {
        self.images.read().await.get(url).cloned()
    }
}
