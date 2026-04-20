use core::ops::Range;

use crate::error::{KacsError, KacsResult};
use crate::pkm_alloc::{slice_to_vec, Vec};
#[cfg(feature = "kernel")]
use crate::pkm_alloc::{AllocError, TryClone};

/// One preorder object-type entry from an AccessCheck object tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectTypeNode {
    /// Depth in the preorder object-type list.
    pub level: u16,
    /// Object-type GUID in little-endian byte order.
    pub guid: [u8; 16],
}

#[cfg(feature = "kernel")]
impl TryClone for ObjectTypeNode {
    fn try_clone(&self) -> Result<Self, AllocError> {
        Ok(*self)
    }
}

/// Parsed object-type tree with cached parent links.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct ObjectTypeList {
    nodes: Vec<ObjectTypeNode>,
    parents: Vec<Option<usize>>,
}

impl ObjectTypeList {
    /// Validates and copies a preorder object-type list.
    pub fn new(nodes: &[ObjectTypeNode]) -> KacsResult<Self> {
        if nodes.is_empty() {
            return Err(KacsError::EmptyObjectTypeList);
        }
        if nodes[0].level != 0 {
            return Err(KacsError::InvalidObjectTypeRootLevel(nodes[0].level));
        }

        let mut parents = Vec::with_capacity(nodes.len())?;
        let mut stack: Vec<usize> = Vec::with_capacity(nodes.len())?;

        for (index, node) in nodes.iter().copied().enumerate() {
            if nodes[..index]
                .iter()
                .any(|existing| existing.guid == node.guid)
            {
                return Err(KacsError::DuplicateObjectTypeGuid(node.guid));
            }

            if index == 0 {
                parents.push(None)?;
                stack.push(index)?;
                continue;
            }

            if node.level == 0 {
                return Err(KacsError::MultipleObjectTypeRoots);
            }

            let previous_level = nodes[index - 1].level;
            if node.level > previous_level + 1 {
                return Err(KacsError::ObjectTypeLevelGap {
                    previous: previous_level,
                    current: node.level,
                });
            }

            while stack.len() > usize::from(node.level) {
                stack.pop();
            }

            let parent = stack.last().copied().ok_or(KacsError::ObjectTypeLevelGap {
                previous: previous_level,
                current: node.level,
            })?;
            parents.push(Some(parent))?;
            stack.push(index)?;
        }

        Ok(Self {
            nodes: slice_to_vec(nodes)?,
            parents,
        })
    }

    /// Returns the number of nodes in the tree.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the original preorder node list.
    pub fn nodes(&self) -> &[ObjectTypeNode] {
        &self.nodes
    }

    pub(crate) fn find(&self, guid: &[u8; 16]) -> Option<usize> {
        self.nodes.iter().position(|node| &node.guid == guid)
    }

    pub(crate) fn parent_of(&self, index: usize) -> Option<usize> {
        self.parents[index]
    }

    pub(crate) fn direct_children(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        self.parents
            .iter()
            .enumerate()
            .filter_map(move |(child, parent)| (*parent == Some(index)).then_some(child))
    }

    pub(crate) fn subtree_range(&self, index: usize) -> Range<usize> {
        let level = self.nodes[index].level;
        let mut end = index + 1;
        while end < self.nodes.len() && self.nodes[end].level > level {
            end += 1;
        }
        index..end
    }
}
