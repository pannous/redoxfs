use std::collections::{HashMap, VecDeque};
use std::{cmp, ptr};
use syscall::error::Result;

use crate::disk::Disk;
use crate::BLOCK_SIZE;

fn copy_memory(src: &[u8], dest: &mut [u8]) -> usize {
    let len = cmp::min(src.len(), dest.len());
    unsafe { ptr::copy(src.as_ptr(), dest.as_mut_ptr(), len) };
    len
}

/// Read-ahead configuration
const READ_AHEAD_BLOCKS: u64 = 64; // Prefetch 64 blocks (256KB) on sequential access
const SEQUENTIAL_THRESHOLD: u64 = 4; // Consider access sequential after 4 consecutive blocks

pub struct DiskCache<T> {
    inner: T,
    cache: HashMap<u64, [u8; BLOCK_SIZE as usize]>,
    order: VecDeque<u64>,
    size: usize,
    // Read-ahead state for sequential access detection
    last_read_block: u64,
    sequential_count: u64,
}

impl<T: Disk> DiskCache<T> {
    pub fn new(inner: T) -> Self {
        // 32 MB cache (increased from 16 MB for read-ahead)
        let size = 32 * 1024 * 1024 / BLOCK_SIZE as usize;
        DiskCache {
            inner,
            cache: HashMap::with_capacity(size),
            order: VecDeque::with_capacity(size),
            size,
            last_read_block: u64::MAX,
            sequential_count: 0,
        }
    }

    fn insert(&mut self, i: u64, data: [u8; BLOCK_SIZE as usize]) {
        while self.order.len() >= self.size {
            let removed = self.order.pop_front().unwrap();
            self.cache.remove(&removed);
        }

        self.cache.insert(i, data);
        self.order.push_back(i);
    }

    /// Check if access pattern is sequential and update tracking
    fn update_sequential_tracking(&mut self, block: u64, num_blocks: u64) -> bool {
        let end_block = block + num_blocks;
        let is_sequential = block == self.last_read_block + 1
            || (self.last_read_block != u64::MAX && block <= self.last_read_block + 2);

        if is_sequential {
            self.sequential_count += 1;
        } else {
            self.sequential_count = 1;
        }

        self.last_read_block = end_block.saturating_sub(1);
        self.sequential_count >= SEQUENTIAL_THRESHOLD
    }

    /// Prefetch blocks ahead of current position
    unsafe fn prefetch(&mut self, start_block: u64, count: u64) {
        let mut prefetch_buf = vec![0u8; (count * BLOCK_SIZE) as usize];
        if self.inner.read_at(start_block, &mut prefetch_buf).is_ok() {
            for i in 0..count {
                let block_i = start_block + i;
                if !self.cache.contains_key(&block_i) {
                    let offset = (i * BLOCK_SIZE) as usize;
                    let mut cache_buf = [0u8; BLOCK_SIZE as usize];
                    cache_buf.copy_from_slice(&prefetch_buf[offset..offset + BLOCK_SIZE as usize]);
                    self.insert(block_i, cache_buf);
                }
            }
        }
    }
}

impl<T: Disk> Disk for DiskCache<T> {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let num_blocks = buffer.len().div_ceil(BLOCK_SIZE as usize) as u64;

        // Check if all requested blocks are in cache
        let mut read = 0;
        let mut all_cached = true;
        for i in 0..num_blocks {
            let block_i = block + i;
            let buffer_i = (i as usize) * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &mut buffer[buffer_i..buffer_j];

            if let Some(cache_buf) = self.cache.get(&block_i) {
                read += copy_memory(cache_buf, buffer_slice);
            } else {
                all_cached = false;
                break;
            }
        }

        if all_cached {
            // Update sequential tracking even on cache hit
            self.update_sequential_tracking(block, num_blocks);
            return Ok(read);
        }

        // Cache miss - read from disk
        self.inner.read_at(block, buffer)?;

        // Cache the blocks we just read
        read = 0;
        for i in 0..num_blocks {
            let block_i = block + i;
            let buffer_i = (i as usize) * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &buffer[buffer_i..buffer_j];

            let mut cache_buf = [0; BLOCK_SIZE as usize];
            read += copy_memory(buffer_slice, &mut cache_buf);
            self.insert(block_i, cache_buf);
        }

        // Check for sequential access and trigger read-ahead
        let is_sequential = self.update_sequential_tracking(block, num_blocks);
        if is_sequential {
            let prefetch_start = block + num_blocks;
            // Don't prefetch if blocks are already cached
            let mut blocks_to_prefetch = 0u64;
            for i in 0..READ_AHEAD_BLOCKS {
                if !self.cache.contains_key(&(prefetch_start + i)) {
                    blocks_to_prefetch = READ_AHEAD_BLOCKS - i;
                    break;
                }
            }
            if blocks_to_prefetch > 0 {
                self.prefetch(prefetch_start, blocks_to_prefetch);
            }
        }

        Ok(read)
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        //TODO: Write only blocks that have changed
        // println!("Cache write at {}", block);

        self.inner.write_at(block, buffer)?;

        let mut written = 0;
        for i in 0..buffer.len().div_ceil(BLOCK_SIZE as usize) {
            let block_i = block + i as u64;

            let buffer_i = i * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &buffer[buffer_i..buffer_j];

            let mut cache_buf = [0; BLOCK_SIZE as usize];
            written += copy_memory(buffer_slice, &mut cache_buf);
            self.insert(block_i, cache_buf);
        }

        Ok(written)
    }

    fn size(&mut self) -> Result<u64> {
        self.inner.size()
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}
