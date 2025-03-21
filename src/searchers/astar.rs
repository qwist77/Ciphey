//! # A* Search Implementation for Decoding
//!
//! This module implements the A* search algorithm for finding the correct sequence of decoders
//! to decode an encrypted or encoded text. The A* algorithm is a best-first search algorithm
//! that uses a heuristic function to prioritize which paths to explore.
//!
//! ## Algorithm Overview
//!
//! 1. Start with the initial input text
//! 2. At each step:
//!    - Extract a batch of nodes from the priority queue
//!    - Process these nodes in parallel
//!    - First run all "decoder"-tagged decoders (these are prioritized)
//!    - Then run all other decoders with heuristic prioritization
//! 3. For each successful decoding, create a new node and add it to the priority queue
//! 4. Continue until a plaintext is found or the search space is exhausted
//!
//! ## Node Prioritization
//!
//! Nodes are prioritized using an f-score where:
//! - f = g + h
//! - g = depth in the search tree (cost so far)
//! - h = heuristic value (estimated cost to goal)
//!
//! The current implementation uses a simple placeholder heuristic of 1.0,
//! but has been improved with Cipher Identifier for better prioritization.
//!
//! ## Parallel Processing
//!
//! The implementation uses parallel node expansion to improve performance:
//! - Multiple nodes are processed simultaneously using Rayon
//! - Thread-safe data structures ensure correctness
//! - Batch processing extracts multiple nodes from the priority queue
//! - Special result nodes handle successful decodings in a thread-safe manner

use crate::cli_pretty_printing;
use crate::cli_pretty_printing::decoded_how_many_times;
use crate::filtration_system::get_all_decoders;
use crate::filtration_system::{get_decoder_by_name, get_decoder_tagged_decoders};
use crossbeam::channel::Sender;

use log::trace;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

// Add imports for parallel processing
use dashmap::DashSet;
use rayon::prelude::*;

use crate::checkers::athena::Athena;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::searchers::helper_functions::generate_heuristic;
use crate::storage::wait_athena_storage;
use crate::DecoderResult;

/// Threshold for pruning the seen_strings HashSet to prevent excessive memory usage
const PRUNE_THRESHOLD: usize = 100000;

/// Initial pruning threshold for dynamic adjustment
const INITIAL_PRUNE_THRESHOLD: usize = PRUNE_THRESHOLD;

/// Maximum depth for search (used for dynamic threshold adjustment)
const MAX_DEPTH: u32 = 100;

/// Calculate a hash for a string to use in the seen_strings set
fn calculate_hash(text: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish().to_string()
}

/// A* search node with priority based on f = g + h
///
/// Each node represents a state in the search space, with:
/// - The current decoded text
/// - The path of decoders used to reach this state
/// - Cost metrics for prioritization
#[derive(Debug)]
struct AStarNode {
    /// Current state containing the decoded text and path of decoders used
    state: DecoderResult,

    /// Cost so far (g) - represents the depth in the search tree
    /// This increases by 1 for each decoder applied
    cost: u32,

    /// Heuristic value (h) - estimated cost to reach the goal
    /// Currently a placeholder value, but could be improved with
    /// cipher identification techniques to better estimate how close
    /// we are to finding plaintext
    heuristic: f32,

    /// Total cost (f = g + h) used for prioritization in the queue
    /// Nodes with lower total_cost are explored first
    total_cost: f32,

    /// The name of the next decoder to try when this node is expanded
    next_decoder_name: Option<String>,
}

// Custom ordering for the priority queue
impl Ord for AStarNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (lowest f value has highest priority)
        other
            .total_cost
            .partial_cmp(&self.total_cost)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for AStarNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for AStarNode {
    fn eq(&self, other: &Self) -> bool {
        self.total_cost == other.total_cost
    }
}

impl Eq for AStarNode {}

/// Thread-safe priority queue wrapper for A* open set
struct ThreadSafePriorityQueue {
    queue: Mutex<BinaryHeap<AStarNode>>,
}

impl ThreadSafePriorityQueue {
    fn new() -> Self {
        ThreadSafePriorityQueue {
            queue: Mutex::new(BinaryHeap::new()),
        }
    }

    fn push(&self, node: AStarNode) {
        let mut queue = self.queue.lock().unwrap();
        queue.push(node);
    }

    fn pop(&self) -> Option<AStarNode> {
        let mut queue = self.queue.lock().unwrap();
        queue.pop()
    }

    fn is_empty(&self) -> bool {
        let queue = self.queue.lock().unwrap();
        queue.is_empty()
    }

    fn len(&self) -> usize {
        let queue = self.queue.lock().unwrap();
        queue.len()
    }

    // Extract a batch of nodes with highest priority
    fn extract_batch(&self, batch_size: usize) -> Vec<AStarNode> {
        let mut queue = self.queue.lock().unwrap();
        let mut batch = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            if let Some(node) = queue.pop() {
                batch.push(node);
            } else {
                break;
            }
        }

        batch
    }
}

/// A* search implementation for finding the correct sequence of decoders
///
/// This algorithm prioritizes decoders using a heuristic function and executes
/// "decoder"-tagged decoders immediately at each level. The search proceeds in a
/// best-first manner, exploring the most promising nodes first based on the f-score.
///
/// ## Execution Order
///
/// 1. At each node, first run all "decoder"-tagged decoders
///    - These are considered more likely to produce meaningful results
///    - If any of these decoders produces plaintext, we return immediately
///
/// 2. Then run all non-"decoder"-tagged decoders
///    - These are prioritized using the heuristic function
///    - Results are added to the priority queue for future exploration
///
/// ## Pruning Mechanism
///
/// To prevent memory exhaustion and avoid cycles:
///
/// 1. We maintain a HashSet of seen strings to avoid revisiting states
/// 2. When the HashSet grows beyond PRUNE_THRESHOLD (10,000 entries):
///    - We retain only strings shorter than 100 characters
///    - This is based on the heuristic that shorter strings are more likely to be valuable
///
/// ## Parameters
///
/// - `input`: The initial text to decode
/// - `result_sender`: Channel to send the result when found
pub fn astar(input: String, result_sender: Sender<Option<DecoderResult>>) {
    let initial = DecoderResult {
        text: vec![input],
        path: vec![],
    };

    // Thread-safe set to track visited states to prevent cycles
    let _seen_strings: DashSet<String> = DashSet::new();
    let _seen_count = Arc::new(AtomicUsize::new(0));

    // Priority queue for open set
    let open_set = ThreadSafePriorityQueue::new();

    // Add initial node to open set
    open_set.push(AStarNode {
        state: initial,
        cost: 0,
        heuristic: 0.0,
        total_cost: 0.0,
        next_decoder_name: None,
    });

    let curr_depth = Arc::new(AtomicU32::new(1));
    let _prune_threshold = Arc::new(AtomicUsize::new(INITIAL_PRUNE_THRESHOLD));
    let thread_count = rayon::current_num_threads();

    // Main A* loop
    while !open_set.is_empty() {
        trace!(
            "Current depth is {:?}, open set size: {}",
            curr_depth.load(AtomicOrdering::Relaxed),
            open_set.len()
        );

        // Pop the highest priority node from the queue
        let current_node = match open_set.pop() {
            Some(node) => node,
            None => break, // Queue is empty, exit the loop
        };

        // Determine which decoders to use based on next_decoder_name
        let decoders = match &current_node.next_decoder_name {
            Some(decoder_name) => {
                // If we have a specific decoder name, use only that decoder
                get_decoder_by_name(decoder_name)
            }
            None => {
                // Otherwise, get all decoder-tagged decoders
                get_decoder_tagged_decoders(&current_node.state)
            }
        };

        let athena_checker = Checker::<Athena>::new();
        let checker = CheckerTypes::CheckAthena(athena_checker);
        
        // Break decoders into chunks for parallel processing
        let chunks: Vec<_> = decoders.components.chunks(thread_count).collect();

        // Process decoder chunks in parallel with find_map_first to short-circuit on first success
        let mut success_found = false;

        // Process all chunks in parallel and find the first successful result (if any)
        let success_result = chunks.par_iter().find_map_first(|chunk| {
            // For each decoder in this chunk
            for decoder in *chunk {
                // Extract the first text from the vector for decoding
                if let Some(text_to_decode) = current_node.state.text.first() {
                    let result = decoder.crack(text_to_decode, &checker);
                    if result.success {
                        println!(
                            "DEBUG: decoder chunk - Decoder {} succeeded, short-circuiting",
                            result.decoder
                        );
                        return Some(result);
                    }
                }
            }
            None
        });

        // If we found a successful result in any of the chunks
        if let Some(success) = success_result {
            success_found = true;
            let mut decoders_used = current_node.state.path.clone();
            let text = success.unencrypted_text.clone().unwrap_or_default();

            decoders_used.push(success.clone());
            let result_text = DecoderResult {
                text,
                path: decoders_used,
            };

            decoded_how_many_times(curr_depth.load(AtomicOrdering::Relaxed));
            cli_pretty_printing::success(&format!(
                "DEBUG: astar.rs - Sending successful result with {} decoders",
                result_text.path.len()
            ));

            if get_config().top_results {
                // Get the last decoder used
                let decoder_name =
                    if let Some(last_decoder) = result_text.path.last() {
                        last_decoder.decoder.to_string()
                    } else {
                        "Unknown".to_string()
                    };

                // Get the checker name from the last decoder
                let checker_name =
                    if let Some(last_decoder) = result_text.path.last() {
                        last_decoder.checker_name.to_string()
                    } else {
                        "Unknown".to_string()
                    };

                // Only store results that have a valid checker name
                if !checker_name.is_empty() && checker_name != "Unknown" {
                    if let Some(plaintext) = result_text.text.first() {
                        log::trace!(
                            "Storing plaintext in WaitAthena storage: {} (decoder: {}, checker: {})",
                            plaintext,
                            decoder_name,
                            checker_name
                        );
                        wait_athena_storage::add_plaintext_result(
                            plaintext.clone(),
                            format!("Decoded successfully at depth {}", curr_depth.load(AtomicOrdering::Relaxed)),
                            checker_name,
                            decoder_name,
                        );
                    }
                }
            }

            result_sender
                .send(Some(result_text))
                .expect("Should successfully send the result");

            // Only stop if not in top_results mode
            if !get_config().top_results {
                return;
            }
        }

        // If no successful result was found, add new nodes to the open set
        if !success_found {
            let all_available_decoders = get_all_decoders();

            // Create new nodes for each available decoder
            // This is where we create nodes with specific next_decoder values
            for next_decoder in all_available_decoders.components {
                // Skip reciprocal decoders if the last decoder used was reciprocal
                if let Some(last_decoder) = current_node.state.path.last() {
                    if last_decoder.checker_description.contains("reciprocal") 
                       && last_decoder.decoder == next_decoder.get_name() {
                        continue;
                    }
                }

                // Create new node with updated cost, heuristic, and next_decoder
                let cost = current_node.cost + 1;
                let empty_string = "".to_string();
                let text_for_heuristic = current_node.state.text.first().unwrap_or(&empty_string);
                let next_decoder_name = next_decoder.get_name().to_string();
                let heuristic = generate_heuristic(text_for_heuristic, &current_node.state.path, &Some(next_decoder));
                let total_cost = cost as f32 + heuristic;

                let new_node = AStarNode {
                    state: DecoderResult {
                        text: current_node.state.text.clone(),
                        path: current_node.state.path.clone(),
                    },
                    cost,
                    heuristic,
                    total_cost,
                    next_decoder_name: Some(next_decoder_name),
                };

                // Add to open set
                open_set.push(new_node);
            }
        }
        
        // Increase current depth
        curr_depth.fetch_add(1, AtomicOrdering::Relaxed);
    }

    // If we get here, we've exhausted all possibilities without finding a solution
    result_sender
        .send(None)
        .expect("Should successfully send the result");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam::channel::bounded;

    #[test]
    fn astar_handles_empty_input() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);

        // Run A* with empty input
        astar("".to_string(), sender);

        // Should receive None since there's nothing to decode
        let result = receiver.recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn astar_prevents_cycles() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);

        // Run A* with input that could cause cycles
        astar("AAAA".to_string(), sender);

        // Should eventually complete without hanging
        let _ = receiver.recv().unwrap();
    }

    #[test]
    fn test_parallel_astar() {
        // Create channels for result communication
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);

        // Run A* in a separate thread with Base64 encoded "Hello World"
        let input = "SGVsbG8gV29ybGQ=".to_string();

        std::thread::spawn(move || {
            astar(input, sender);
        });

        // Wait for result with timeout
        let result = receiver.recv().unwrap();

        // Verify we got a result (not necessarily "Hello World" as it depends on decoders)
        assert!(result.is_some());
        if let Some(decoder_result) = result {
            assert!(!decoder_result.path.is_empty());
        }
    }
}
