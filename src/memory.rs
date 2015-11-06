// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

use std::ops::{Add, BitAnd, BitOr, BitXor, Index, Mul, Not, Rem, Shl, Shr, Sub};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::cell::{Cell, RefCell};
use std::hash::{Hash, Hasher};
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};

pub trait BasicOps: Add + BitAnd + BitOr + BitXor + Mul + Not + Rem
                    + Shl<Self> + Shr<Self> + Sub + Sized {}

pub trait MemoryOps {
    type DataType;
    fn read(&self, address: u64, size: usize) -> Self::DataType;
    fn write(&self, address: u64, size: usize, data: Self::DataType);
    // Nop by default
    fn dump_memory(&self) { }
}

// Some notes on design.
// Chunks are assumed to be of fixed size, that is 8 bytes (as our primary
// target is x86-64).
// Adjacent chunks are coalesced together by using the next_chunk and
// previous_chunk pointers.
// When a write starts from the middle of a chunk and number of bytes written
// exceed the size of
// the chunk, depending on the availability of the adjacent chunk, one of the
// two things will
// happen:
// 1. If the adjacent chunk already exists, this means that the write
// continues into this chunk
// 2. If the adjacent chunk does not exist then a new chunk is allocated,
// populating the
//        previous and the next_chunk pointers
// The allocator, at the time of allocation will coalesce if it finds that the
// new chunk requested
//  for is adjacent to an already exisiting chunk.
// Chunk coalescing has almost zero cost as it is effectively equivalent to
// only updating a
//  pointer value.
// Memory region maintains an ordered map of all the allocated chunks in order
// to find an
//  appropriate one when requested for.
//
// Disadvatages, using linear search on the BTreeMap might be costly. It may
// make more sense to
//  use binary search as the set is ordered.
//
//  TODO: Be able to create chunks of arbitrary size.

// Internally used associate addresses with the locations in the buffers.
#[derive(Clone, Debug)]
struct MemMetaData {
    start: u64,
    size: Cell<usize>,
}

impl Hash for MemMetaData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start.hash(state)
    }
}

impl PartialOrd for MemMetaData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.start.partial_cmp(&other.start)
    }
}

impl PartialEq for MemMetaData {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for MemMetaData { }

impl Ord for MemMetaData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}

impl MemMetaData {
    pub fn new(start: u64, size: usize) -> MemMetaData {
        MemMetaData {
            start: start,
            size: Cell::new(size),
        }
    }

    pub fn size(&self) -> usize {
        self.size.get()
    }

    pub fn sizeu64(&self) -> u64 {
        self.size.get() as u64
    }

    pub fn extend_by(&self, n: usize) {
        self.size.set(self.size() + n);
    }
}

// Represents the result struct for find_memory_by_address.
// Returns the MemMetaData that the address is a part of and the offset within that chunk.
struct FindResult {
    meta: MemMetaData,
    offset: usize,
    needs_allocation: bool,
}

// Actual Chunk of that represents memory
pub struct _MemoryChunk<T: BasicOps> {
    // next chunk is used to continue writes into the next chunk. This field is a `None`
    // if there is no chunk that continues the present chunk.
    // This field is basically used to coalesce two adjacent chunks together.
    next_chunk: Option<MemoryChunk<T>>,
    buffer: Rc<RefCell<Vec<T>>>,
    // For later use. To mark that a memory has been written out to disk and can be reused.
    in_use: bool,
}

type MemoryChunk<T> = Rc<RefCell<_MemoryChunk<T>>>;

impl<T: BasicOps> _MemoryChunk<T> {
    fn new() -> _MemoryChunk<T> {
        let buffer = Rc::new(RefCell::new(Vec::new()));
        _MemoryChunk {
            next_chunk: None,
            buffer: buffer,
            in_use: true,
        }
    }
}

// Memory region. Container for memory chunks.
pub struct MemoryRegion<T: BasicOps> {
    min: u64,
    max: u64,
    allocated: BTreeMap<MemMetaData, MemoryChunk<T>>,
}

impl<T: BasicOps> MemoryRegion<T> {
    pub fn new() -> MemoryRegion<T> {
        MemoryRegion {
            min: 0,
            max: 0,
            allocated: BTreeMap::new(),
        }
    }

    fn find_memory_by_address(&self, meta: &MemMetaData) -> Option<FindResult> {
        if self.min > meta.start || self.max < meta.start {
            return None;
        }
        let mut keys = self.allocated.keys().collect::<Vec<&MemMetaData>>();
        while let Some(key) = keys.pop() {
            if meta.start >= key.start && meta.start < key.start + key.sizeu64() {
                let offset = meta.start - key.start;
                let needs_allocation = (meta.start + meta.sizeu64()) >
                                       (key.start + key.sizeu64());
                return Some(FindResult {
                    meta: key.clone(),
                    offset: offset as usize,
                    needs_allocation: needs_allocation,
                });
            }
            if key.start + key.sizeu64() < meta.start {
                break;
            }
        }
        return None;
    }

    // Returns true if the two memory locations are adjacent to each other
    fn is_adjacent(mem: &MemMetaData, mem_: &MemMetaData) -> bool {
        if mem.start == mem_.start + mem_.sizeu64() + 1 {
            true
        } else if mem_.start == mem.start + mem.sizeu64() + 1 {
            true
        } else {
            false
        }
    }

    // Tries and coalesce all chunks that are possible.
    fn coalesce_chunks(&mut self) {
        let mut compacted = Vec::<MemMetaData>::new();
        {
            let mut keys = self.allocated.iter_mut().peekable();
            if let Some((mut key, mut cur_chunk)) = keys.next() {
                loop {
                    if let Some((next_key, mut next_chunk)) = keys.next() {
                        if !MemoryRegion::<T>::is_adjacent(key, next_key) {
                            key = next_key;
                            cur_chunk = next_chunk;
                            continue;
                        }

                        assert!(cur_chunk.borrow().next_chunk.is_none());
                        (*cur_chunk).borrow_mut().next_chunk = Some(next_chunk.clone());
                        key.extend_by(next_key.size());

                        key = next_key;
                        cur_chunk = next_chunk;

                        compacted.push(next_key.clone());
                        continue;
                    }
                    break;
                }
            }
        }
        for key in &compacted {
            self.allocated.remove(key);
        }
    }
    
    fn new_chunk(&mut self, meta: &MemMetaData) {
        let (allocation_size, allocation_start) = match self.find_memory_by_address(meta) {
            Some(ref res) => {
                match res.needs_allocation {
                    true => (meta.size() - res.meta.size() + res.offset,
                              res.meta.start + res.meta.sizeu64()),
                    false => (0, 0),
                }
            },
            None => (meta.size(), meta.start),
        };
        if allocation_size > 0 {
            let new_meta = MemMetaData::new(allocation_start, allocation_size);
            let chunk = Rc::new(RefCell::new(_MemoryChunk::new()));
            self.allocated.insert(new_meta, chunk);
            self.coalesce_chunks();
        }
    }

    pub fn read(&self, address: u64, size: usize) -> Option<&[T]> {
        unimplemented!()
    }

    pub fn write(&mut self, address: u64, size: usize, data: &[T]) {
        unimplemented!()
    }

    pub fn dump_memory(&self) {
        unimplemented!()
    }
}


#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn mem_dummy1() {

    }
}
