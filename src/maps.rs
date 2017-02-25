// Copyright 2017 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! Let's add maps!
//!

use std::vec::Vec;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::Hash;
use std::cmp::Eq;

pub trait EbpfMap<K, V> {
    fn lookup_elem(&self, key: K) -> Option<&V>;

    fn update_elem(&mut self, key: K, value: V, flags: HashMapUpdateFlag) -> u64;

    fn delete_elem(&mut self, key: K) -> u64;
}

pub enum HashMapUpdateFlag {
    CreateOnly,
    UpdateOnly,
    CreateOrUpdate
}

#[derive(Default)]
pub struct EbpfHashMap<K, V> where K: Hash + Eq {
    pub map: HashMap<K, V, RandomState>,
}

pub enum EbpfMapType {
    Unspecified,
    HashMap { map: EbpfHashMap<u64, u64> },
}

#[derive(Default)]
pub struct EbpfMapContainer {
    pub maps: HashMap<u64, EbpfMapType>,
}

pub static mut EBPF_MAPS: *mut EbpfMapContainer = 0 as *mut EbpfMapContainer;

const ERROR_VALUE: u64 = (-1 as i64) as u64;

impl<K, V> EbpfMap<K, V> for EbpfHashMap<K, V> where K: Hash + Eq {
    fn lookup_elem (&self, key: K) -> Option<&V> {
        self.map.get(&key)
    }
    fn update_elem (&mut self, key: K, value: V, flags: HashMapUpdateFlag) -> u64{
        let do_insert = | m: &mut HashMap<K, V, RandomState>, k: K, v: V | {
            if let Some(_) = m.insert(k, v) {
                0
            } else {
                ERROR_VALUE
            }
        };

        match flags {
            HashMapUpdateFlag::CreateOnly => {
                if let Some(_) = self.map.get(&key) {
                    ERROR_VALUE
                } else {
                    do_insert(&mut self.map, key, value)
                }
            },
            HashMapUpdateFlag::UpdateOnly => {
                if let Some(_) = self.map.get(&key) {
                    do_insert(&mut self.map, key, value)
                } else {
                    ERROR_VALUE
                }
            },
            HashMapUpdateFlag::CreateOrUpdate => {
                do_insert(&mut self.map, key, value)
            },
        }
    }
    fn delete_elem (&mut self, key: K) -> u64 {
        match self.map.remove(&key) {
            Some(_) => 0,
            None => (-1 as i64) as u64
        }
    }
}
