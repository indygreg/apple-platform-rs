// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! B-tree interaction.

use crate::block::{Block, BlockReader};
use crate::error::ApfsError;
use crate::error::Result;
use crate::object_map::ObjectMap;
pub use apfs_types::btree::*;
use apfs_types::common::{ObjectIdentifierParsed, TransactionIdentifierRaw};
use apfs_types::{
    common::{ObjectIdentifierRaw, PhysicalObjectIdentifierRaw},
    object::{ObjectType, StorageClass},
    pod::MemoryBackedArray,
    ParsedDiskStruct,
};
use bytes::Bytes;
use log::{debug, trace};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::ops::Deref;

/// Represents a key in a B-tree node.
#[derive(Clone, Debug)]
pub struct NodeKey {
    /// The underlying bytes backing the key.
    data: Bytes,
}

impl Deref for NodeKey {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl From<NodeKey> for Bytes {
    fn from(value: NodeKey) -> Self {
        value.data
    }
}

impl From<Bytes> for NodeKey {
    fn from(data: Bytes) -> Self {
        Self { data }
    }
}

impl NodeKey {
    pub fn bytes(&self) -> Bytes {
        self.data.clone()
    }
}

/// Represents a value in a B-tree node.
#[derive(Clone, Debug)]
pub struct NodeValue {
    /// The underlying data backing the full value.
    data: Bytes,
}

impl Deref for NodeValue {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl From<NodeValue> for Bytes {
    fn from(value: NodeValue) -> Self {
        value.data
    }
}

impl From<Bytes> for NodeValue {
    fn from(data: Bytes) -> Self {
        Self { data }
    }
}

impl NodeValue {
    pub fn bytes(&self) -> Bytes {
        self.data.clone()
    }

    /// Cast self to an object identifier.
    pub fn as_oid(&self) -> Result<ObjectIdentifierRaw> {
        let v = ObjectIdentifierParsed::from_bytes(self.data.clone())?;

        Ok(v.clone_inner())
    }

    /// Cast self to the value of an index node.
    ///
    /// This should be safe to call on non-leaf nodes.
    pub fn as_index_value(&self) -> Result<BTreeIndexNodeValueParsed> {
        let v = BTreeIndexNodeValueParsed::from_bytes(self.data.clone())?;

        Ok(v)
    }
}

/// The table of contents entries for a B-tree node.
#[derive(Clone, Debug)]
pub enum TableOfContents {
    Offset(MemoryBackedArray<KeyValueOffsetRaw, KeyValueOffsetParsed>),
    Location(MemoryBackedArray<KeyValueLocationRaw, KeyValueLocationParsed>),
}

impl TableOfContents {
    /// Iterate over keys.
    ///
    /// `data` is the keys data from the node.
    ///
    /// `tree_info` is the data structure from the root node describing tree
    /// metadata.
    pub fn keys(
        &self,
        data: Bytes,
        tree_info: BTreeInfoRaw,
    ) -> Box<dyn Iterator<Item = Result<NodeKey>> + '_> {
        match self {
            Self::Offset(offsets) => {
                let key_size = tree_info.fixed().key_size() as usize;

                Box::new(offsets.iter().map(move |res| {
                    let off = res?;

                    let start = off.key() as usize;
                    let end = start + key_size;

                    if end <= data.len() {
                        Ok(NodeKey::from(data.slice(start..end)))
                    } else {
                        Err(ApfsError::InputTooSmall)
                    }
                }))
            }
            Self::Location(locs) => Box::new(locs.iter().map(move |res| {
                let loc = res?;

                let start = loc.key().offset() as usize;
                let end = start + loc.key().length() as usize;

                if end <= data.len() {
                    Ok(NodeKey::from(data.slice(start..end)))
                } else {
                    Err(ApfsError::InputTooSmall)
                }
            })),
        }
    }

    /// Iterate over values.
    ///
    /// `data` is values data from the node. This starts at the end of the block.
    /// For root nodes, it starts before the [BTreeInfoRaw] struct.
    ///
    /// `tree_info` is the struct from the root node holding tree metadata.
    pub fn values(
        &self,
        data: Bytes,
        tree_info: BTreeInfoRaw,
    ) -> Box<dyn Iterator<Item = Result<NodeValue>> + '_> {
        match self {
            Self::Offset(offsets) => {
                let value_size = tree_info.fixed().value_size() as usize;

                Box::new(offsets.iter().map(move |res| {
                    let off = res?;

                    // This magic value along with the ghosts flag represents an empty value.
                    if off.value() == BTREE_INVALID_OFFSET
                        && tree_info
                            .fixed()
                            .flags()
                            .contains(BTreeFlagsRaw::AllowGhosts)
                    {
                        Ok(NodeValue::from(data.slice(0..)))
                    } else {
                        let start = data
                            .len()
                            .checked_sub(off.value() as usize)
                            .ok_or(ApfsError::InputTooSmall)?;
                        let end = start + value_size;

                        if end <= data.len() {
                            Ok(NodeValue::from(data.slice(start..end)))
                        } else {
                            Err(ApfsError::InputTooSmall)
                        }
                    }
                }))
            }
            Self::Location(locs) => Box::new(locs.iter().map(move |res| {
                let loc = res?;

                if loc.value().length() == BTREE_INVALID_OFFSET
                    && tree_info
                        .fixed()
                        .flags()
                        .contains(BTreeFlagsRaw::AllowGhosts)
                {
                    Ok(NodeValue::from(data.slice(0..)))
                } else {
                    let start = data
                        .len()
                        .checked_sub(loc.value().offset() as usize)
                        .ok_or(ApfsError::InputTooSmall)?;
                    let end = start + loc.value().length() as usize;

                    if end <= data.len() {
                        Ok(NodeValue::from(data.slice(start..end)))
                    } else {
                        Err(ApfsError::InputTooSmall)
                    }
                }
            })),
        }
    }
}

/// Represents a B-tree node / block.
///
/// Provides common APIs for all B-tree node types.
///
/// Cannot walk entries since the root node's metadata is required for
/// traversal.
#[derive(Clone)]
pub struct BTreeNodeBlock {
    inner: BTreeNodeParsed,
    block_number: PhysicalObjectIdentifierRaw,
    data: Bytes,
}

impl Deref for BTreeNodeBlock {
    type Target = BTreeNodeParsed;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BTreeNodeBlock {
    /// Construct an instance from a block.
    pub fn from_block(block: Block) -> Result<Self> {
        debug!("block {} -> B-tree node", block.number());
        let inner = BTreeNodeParsed::from_bytes(block.bytes())?;
        let block_number = block.number();
        let data = inner.trailing_data()?.clone();

        Ok(Self {
            inner,
            block_number,
            data,
        })
    }

    /// Obtain flags for this node.
    pub fn node_flags(&self) -> BTreeNodeFlagsRaw {
        self.inner.flags()
    }

    /// Whether this is the root node.
    pub fn is_root(&self) -> bool {
        self.inner.flags().contains(BTreeNodeFlagsRaw::Root)
    }

    /// Whether this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.inner.flags().contains(BTreeNodeFlagsRaw::Leaf)
    }

    /// Attempt to resolve the BTreeInfo struct.
    ///
    /// This structure is only present on root nodes.
    pub fn tree_info(&self) -> Result<Option<BTreeInfoRaw>> {
        if self.is_root() {
            // The BTreeInfo struct is at the end of the block.
            let source = self
                .data
                .slice(self.data.len() - core::mem::size_of::<BTreeInfoRaw>()..);

            let info = BTreeInfoParsed::from_bytes(source)?;

            Ok(Some(info.clone_inner()))
        } else {
            Ok(None)
        }
    }

    /// Attempt to resolve a span of bytes from a [NodeLocationRaw].
    fn node_location_span(&self, nl: NodeLocationRaw) -> Result<Bytes> {
        let start = nl.offset() as usize;
        let length = nl.length() as usize;
        let end = start + length;

        if end <= self.data.len() {
            Ok(self.data.slice(start..end))
        } else {
            Err(ApfsError::InputTooSmall)
        }
    }

    /// Obtain the table of contents array.
    pub fn table_of_contents(&self) -> Result<TableOfContents> {
        let data = self.node_location_span(*self.table_space())?;

        if self
            .node_flags()
            .contains(BTreeNodeFlagsRaw::FixedKeyValueSize)
        {
            let toc = MemoryBackedArray::<KeyValueOffsetRaw, KeyValueOffsetParsed>::new(
                data,
                self.number_keys() as _,
            )?;
            Ok(TableOfContents::Offset(toc))
        } else {
            let toc = MemoryBackedArray::<KeyValueLocationRaw, KeyValueLocationParsed>::new(
                data,
                self.number_keys() as _,
            )?;
            Ok(TableOfContents::Location(toc))
        }
    }

    /// Obtain the data backing keys data.
    fn key_space_data(&self) -> Bytes {
        let offset = self.table_space().offset() as usize;
        let length = self.table_space().length() as usize;

        self.data.slice(offset + length..)
    }

    /// Obtain the data backing values.
    fn value_space_data(&self) -> Result<Bytes> {
        if self.is_root() {
            let end = self
                .data
                .len()
                .checked_sub(core::mem::size_of::<BTreeInfoRaw>())
                .ok_or(ApfsError::InputTooSmall)?;

            if end <= self.data.len() {
                Ok(self.data.slice(0..end))
            } else {
                Err(ApfsError::InputTooSmall)
            }
        } else {
            // Strictly speaking we could chop off known leading data. But it is
            // unclear if this provides any value.
            Ok(self.data.clone())
        }
    }
}

/// Represents a node in a B-tree.
#[derive(Clone)]
pub struct BTreeNode {
    inner: BTreeNodeBlock,
    toc: TableOfContents,
    tree_info: BTreeInfoRaw,
}

impl BTreeNode {
    /// Construct an instance from a [BTreeNodeBlock] and the root node's [BTreeInfoRaw].
    pub fn new(inner: BTreeNodeBlock, tree_info: BTreeInfoRaw) -> Result<Self> {
        let toc = inner.table_of_contents()?;

        Ok(Self {
            inner,
            toc,
            tree_info,
        })
    }

    /// Construct an instance from a block and metadata from the root node.
    pub fn from_block(block: Block, tree_info: BTreeInfoRaw) -> Result<Self> {
        let inner = BTreeNodeBlock::from_block(block)?;

        Self::new(inner, tree_info)
    }

    /// Iterate over the keys in this node.
    pub fn keys(&self) -> impl Iterator<Item = Result<NodeKey>> + '_ {
        self.toc.keys(self.key_space_data(), self.tree_info)
    }

    /// Iterate over the values in this node.
    pub fn values(&self) -> Result<impl Iterator<Item = Result<NodeValue>> + '_> {
        Ok(self.toc.values(self.value_space_data()?, self.tree_info))
    }

    /// Iterate over key-value pairs in this node.
    pub fn entries(
        &self,
    ) -> Result<impl Iterator<Item = (Result<NodeKey>, Result<NodeValue>)> + '_> {
        let keys = self.keys();
        let values = self.values()?;

        Ok(keys.zip(values))
    }
}

impl Deref for BTreeNode {
    type Target = BTreeNodeBlock;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An iterator for values in leaf nodes of B-trees.
pub struct BTreeEntryIterator<'a, R: BlockReader, O: ObjectMap> {
    reader: &'a R,
    object_map: &'a O,
    tree_info: BTreeInfoRaw,
    queue: VecDeque<BTreeNode>,
    storage: StorageClass,
    xid: TransactionIdentifierRaw,
    current_leaf: Option<VecDeque<Result<(NodeKey, NodeValue)>>>,
}

impl<'a, R: BlockReader, O: ObjectMap> Iterator for BTreeEntryIterator<'a, R, O> {
    type Item = Result<(NodeKey, NodeValue)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Drain the current leaf first.
        if let Some(next) = self.next_leaf_entry() {
            return Some(next);
        }

        assert!(
            self.current_leaf.is_none(),
            "shouldn't be processing new nodes if we have leaf entries"
        );

        while let Some(node) = self.queue.pop_front() {
            trace!(
                "starting iteration of b-tree node {} ({:?}) @ level {}",
                node.block_number,
                node.node_flags(),
                node.level(),
            );

            // Leaf nodes store actual values.
            // Non-leaf nodes store object identifiers for the next node.
            if node.is_leaf() {
                match self.collect_leaf_entries(node) {
                    Ok(entries) => {
                        // An empty leaf node is a little weird. But it could happen.
                        if entries.is_empty() {
                            continue;
                        } else {
                            self.current_leaf = Some(entries);
                            return self.next_leaf_entry();
                        }
                    }
                    Err(err) => {
                        return Some(Err(err));
                    }
                }
            } else if let Err(err) = self.extend_index_node(node) {
                return Some(Err(err));
            }
        }

        // If we got here we're at the end.
        None
    }
}

impl<'a, R: BlockReader, O: ObjectMap> BTreeEntryIterator<'a, R, O> {
    pub fn new(reader: &'a R, object_map: &'a O, tree: &BTree) -> Self {
        let tree_info = tree.tree_info;
        let storage = tree.tree_info.fixed().node_oid_storage();
        let xid = tree.root.inner.object().transaction_identifier();

        let mut queue = VecDeque::new();
        queue.push_back(tree.root.clone());

        Self {
            reader,
            object_map,
            tree_info,
            queue,
            storage,
            xid,
            current_leaf: None,
        }
    }

    fn next_leaf_entry(&mut self) -> Option<Result<(NodeKey, NodeValue)>> {
        let mut empty = false;

        let res = if let Some(entries) = self.current_leaf.as_mut() {
            empty = entries.len() == 1;

            entries.pop_front()
        } else {
            None
        };

        if empty {
            self.current_leaf = None;
        }

        res
    }

    /// Collect leaf entries into a VecDeque.
    fn collect_leaf_entries(
        &self,
        node: BTreeNode,
    ) -> Result<VecDeque<Result<(NodeKey, NodeValue)>>> {
        Ok(VecDeque::from_iter(
            node.entries()?.map(|(k, v)| Ok((k?, v?))),
        ))
    }

    // Extend the iterator with entries from an index node.
    fn extend_index_node(&mut self, node: BTreeNode) -> Result<()> {
        for value in node.values()? {
            let value = value?;
            let oid = value.as_oid()?;

            let address = match self.storage {
                StorageClass::Physical => PhysicalObjectIdentifierRaw::from(oid),
                StorageClass::Ephemeral => {
                    return Err(ApfsError::Unimplemented(
                        "resolving ephemeral IDs for B-tree walking",
                    ));
                }
                StorageClass::Virtual => self
                    .object_map
                    .find_latest_oid(self.reader, oid.into(), self.xid)?
                    .ok_or_else(|| ApfsError::VirtualObjectNotFound(oid.into()))?
                    .1
                    .address()
                    .into(),
            };

            let block = self.reader.get_block_validated(address)?;
            let bh = block.object_header()?;

            if matches!(
                bh.typ().object_type(),
                ObjectType::BTreeRoot | ObjectType::BTreeNode
            ) {
                trace!("pushing b-tree node {}", address);
                self.queue
                    .push_back(BTreeNode::from_block(block, self.tree_info)?);
            }
        }

        Ok(())
    }
}

/// A high-level interface to a B-tree.
pub struct BTree {
    root: BTreeNode,
    tree_info: BTreeInfoRaw,
}

impl BTree {
    /// Construct an instance from a block.
    ///
    /// Block must be a root node.
    pub fn from_block(block: Block) -> Result<Self> {
        debug!("block {} -> B-tree root", block.number());
        let root = BTreeNodeBlock::from_block(block)?;
        let tree_info = root.tree_info()?.ok_or(ApfsError::BTreeNodeNotRoot)?;
        let root = BTreeNode::new(root, tree_info)?;

        // This is redundant with resolving the BTreeInfo data. But it doesn't
        // hurt to be explicit.
        if !root.flags().contains(BTreeNodeFlagsRaw::Root) {
            return Err(ApfsError::BTreeNodeNotRoot);
        }

        let tree_info = root.tree_info()?.ok_or(ApfsError::BTreeNodeNotRoot)?;

        Ok(Self { root, tree_info })
    }

    pub fn header(&self) -> &BTreeNodeRaw {
        &self.root.inner.inner
    }

    /// Iterate over entries in this b-tree.
    ///
    /// Only leaf entries pointing to actual data entries are emitted. Internal
    /// nodes pointing to children nodes are not emitted.
    pub fn iter_entries<'a>(
        &self,
        reader: &'a impl BlockReader,
        object_map: &'a impl ObjectMap,
    ) -> impl Iterator<Item = Result<(NodeKey, NodeValue)>> + 'a {
        BTreeEntryIterator::new(reader, object_map, self)
    }

    /// Find all entries having a key matching the specified comparison function.
    ///
    /// This walks the tree and emits all entries where the key matches the
    /// provided comparison function.
    ///
    /// Note: this function is currently not optimized.
    pub fn find_entries_matching<'a>(
        &self,
        reader: &'a impl BlockReader,
        object_map: &'a impl ObjectMap,
        compare: impl Fn(&NodeKey) -> Result<Ordering> + 'a,
    ) -> impl Iterator<Item = Result<(NodeKey, NodeValue)>> + 'a {
        BTreeEntryIterator::new(reader, object_map, self).filter_map(move |res| match res {
            Ok((k, v)) => match compare(&k) {
                Ok(Ordering::Equal) => Some(Ok((k, v))),
                Ok(_) => None,
                Err(err) => Some(Err(err)),
            },
            Err(err) => Some(Err(err)),
        })
    }
}
