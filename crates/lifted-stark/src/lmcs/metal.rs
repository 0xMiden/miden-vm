use core::{ffi::c_void, mem};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::thread_local;
use std::time::{Duration, Instant};
use std::vec::Vec;

use p3_matrix::Matrix;
use p3_util::log2_strict_usize;
use tracing::{info_span, warn};

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const STATE_WIDTH: usize = 12;
const DIGEST_ELEMS_RPO: usize = 4;
// GPU dispatch latency dominates the small top levels of the RPO tree.
const RPO_CPU_TREE_CUTOFF: usize = 16_384;
const ENV_PROFILE: &str = "RPO_METAL_PROFILE";
const ENV_PROFILE_EVENTS: &str = "RPO_METAL_PROFILE_EVENTS";
const ENV_PROFILE_SPLIT: &str = "RPO_METAL_PROFILE_SPLIT";
const ENV_THREADGROUP_SIZE: &str = "RPO_METAL_TG_SIZE";
const ENV_TREE_CUTOFF: &str = "RPO_METAL_TREE_CUTOFF";

#[derive(Default)]
struct ProfileStats {
    num_matrices: usize,
    height: usize,
    staged: bool,
    cutoff: usize,
    matrix_descs: Vec<(u32, u32, u32)>,
    execute_elapsed: Option<Duration>,
    events: Vec<ProfileEvent>,
}

struct ProfileEvent {
    label: &'static str,
    detail: u64,
    threads: u64,
    threadgroup: u64,
    elapsed: Option<Duration>,
}

thread_local! {
    static PROFILE_STATS: RefCell<Option<ProfileStats>> = const { RefCell::new(None) };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MatrixDesc {
    offset: u64,
    height: u32,
    width: u32,
    log_scaling: u32,
    _pad: u32,
}

pub(crate) fn has_u64_word_layout<T>() -> bool {
    mem::size_of::<T>() == mem::size_of::<u64>() && mem::align_of::<T>() <= mem::align_of::<u64>()
}

struct GpuContext {
    device: metal::Device,
    queue: metal::CommandQueue,
    hash_leaves_pipeline: metal::ComputePipelineState,
    absorb_matrix_pipeline: metal::ComputePipelineState,
    absorb_matrix_expanded_pipeline: metal::ComputePipelineState,
    squeeze_leaves_pipeline: metal::ComputePipelineState,
    compress_pipeline: metal::ComputePipelineState,
}

static GPU: OnceLock<Option<GpuContext>> = OnceLock::new();

fn get_gpu() -> Option<&'static GpuContext> {
    GPU.get_or_init(GpuContext::new).as_ref()
}

impl GpuContext {
    fn new() -> Option<Self> {
        let device = metal::Device::system_default()?;
        let queue = device.new_command_queue();

        let opts = metal::CompileOptions::new();
        let library = match device.new_library_with_source(include_str!("rpo_lmcs.metal"), &opts) {
            Ok(library) => library,
            Err(err) => {
                warn!(error = %err, "RPO LMCS Metal shader compilation failed");
                return None;
            },
        };

        let mk = |name: &str| -> Option<metal::ComputePipelineState> {
            let func = library.get_function(name, None).ok()?;
            device.new_compute_pipeline_state_with_function(&func).ok()
        };

        Some(Self {
            hash_leaves_pipeline: mk("rpo_lmcs_hash_leaves")?,
            absorb_matrix_pipeline: mk("rpo_lmcs_absorb_matrix")?,
            absorb_matrix_expanded_pipeline: mk("rpo_lmcs_absorb_matrix_expanded")?,
            squeeze_leaves_pipeline: mk("rpo_lmcs_squeeze_leaves")?,
            compress_pipeline: mk("rpo_lmcs_compress_level")?,
            device,
            queue,
        })
    }

    fn buf<T>(&self, values: &[T]) -> metal::Buffer {
        self.device.new_buffer_with_data(
            values.as_ptr() as *const c_void,
            mem::size_of_val(values) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        )
    }

    fn empty_buf(&self, bytes: usize) -> metal::Buffer {
        self.device
            .new_buffer(bytes as u64, metal::MTLResourceOptions::StorageModeShared)
    }

    fn zeroed_buf(&self, bytes: usize) -> metal::Buffer {
        let buf = self.empty_buf(bytes);
        unsafe {
            // SAFETY: the buffer was allocated with exactly `bytes` writable bytes.
            core::ptr::write_bytes(buf.contents() as *mut u8, 0, bytes);
        }
        buf
    }

    fn dispatch(
        &self,
        label: &'static str,
        detail: u64,
        cmd: &metal::CommandBufferRef,
        pipeline: &metal::ComputePipelineState,
        bufs: &[&metal::Buffer],
        threads: u64,
    ) {
        let threadgroup = threads_per_threadgroup(pipeline, threads);
        if profile_split_enabled() {
            let cmd = self.queue.new_command_buffer();
            let started = Instant::now();
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (idx, buf) in bufs.iter().enumerate() {
                enc.set_buffer(idx as u64, Some(buf), 0);
            }
            enc.dispatch_threads(
                metal::MTLSize::new(threads, 1, 1),
                metal::MTLSize::new(threadgroup, 1, 1),
            );
            enc.end_encoding();
            cmd.commit();
            cmd.wait_until_completed();
            profile_record(label, detail, threads, threadgroup, Some(started.elapsed()));
            return;
        }

        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (idx, buf) in bufs.iter().enumerate() {
            enc.set_buffer(idx as u64, Some(buf), 0);
        }
        enc.dispatch_threads(
            metal::MTLSize::new(threads, 1, 1),
            metal::MTLSize::new(threadgroup, 1, 1),
        );
        enc.end_encoding();
        profile_record(label, detail, threads, threadgroup, None);
    }

    fn dispatch_with_bytes<T>(
        &self,
        label: &'static str,
        detail: u64,
        cmd: &metal::CommandBufferRef,
        pipeline: &metal::ComputePipelineState,
        bufs: &[(u64, &metal::Buffer)],
        bytes_index: u64,
        bytes: &[T],
        threads: u64,
    ) {
        let threadgroup = threads_per_threadgroup(pipeline, threads);
        if profile_split_enabled() {
            let cmd = self.queue.new_command_buffer();
            let started = Instant::now();
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (idx, buf) in bufs {
                enc.set_buffer(*idx, Some(*buf), 0);
            }
            enc.set_bytes(
                bytes_index,
                mem::size_of_val(bytes) as u64,
                bytes.as_ptr() as *const c_void,
            );
            enc.dispatch_threads(
                metal::MTLSize::new(threads, 1, 1),
                metal::MTLSize::new(threadgroup, 1, 1),
            );
            enc.end_encoding();
            cmd.commit();
            cmd.wait_until_completed();
            profile_record(label, detail, threads, threadgroup, Some(started.elapsed()));
            return;
        }

        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (idx, buf) in bufs {
            enc.set_buffer(*idx, Some(*buf), 0);
        }
        enc.set_bytes(bytes_index, mem::size_of_val(bytes) as u64, bytes.as_ptr() as *const c_void);
        enc.dispatch_threads(
            metal::MTLSize::new(threads, 1, 1),
            metal::MTLSize::new(threadgroup, 1, 1),
        );
        enc.end_encoding();
        profile_record(label, detail, threads, threadgroup, None);
    }
}

fn threads_per_threadgroup(pipeline: &metal::ComputePipelineState, threads: u64) -> u64 {
    let width = pipeline.thread_execution_width().max(1);
    let max_threads = pipeline.max_total_threads_per_threadgroup().max(width);
    let default = if threads >= (1 << 20) { 256 } else { width };
    let requested = std::env::var(ENV_THREADGROUP_SIZE)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default);
    let rounded = requested.max(width).min(max_threads);
    let rounded = (rounded / width).max(1) * width;
    rounded.min(max_threads).min(threads.max(1))
}

fn tree_cutoff(final_height: usize) -> usize {
    let cutoff = std::env::var(ENV_TREE_CUTOFF)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(RPO_CPU_TREE_CUTOFF);
    cutoff.clamp(1, final_height)
}

fn profile_enabled() -> bool {
    std::env::var_os(ENV_PROFILE).is_some() || profile_split_enabled()
}

fn profile_split_enabled() -> bool {
    std::env::var_os(ENV_PROFILE_SPLIT).is_some()
}

fn profile_begin(
    num_matrices: usize,
    height: usize,
    staged: bool,
    cutoff: usize,
    descs: &[MatrixDesc],
) {
    if !profile_enabled() {
        return;
    }
    let matrix_descs =
        descs.iter().map(|desc| (desc.height, desc.width, desc.log_scaling)).collect();
    PROFILE_STATS.with(|stats| {
        *stats.borrow_mut() = Some(ProfileStats {
            num_matrices,
            height,
            staged,
            cutoff,
            matrix_descs,
            ..ProfileStats::default()
        });
    });
}

fn profile_record(
    label: &'static str,
    detail: u64,
    threads: u64,
    threadgroup: u64,
    elapsed: Option<Duration>,
) {
    if !profile_enabled() {
        return;
    }
    PROFILE_STATS.with(|stats| {
        if let Some(stats) = stats.borrow_mut().as_mut() {
            stats.events.push(ProfileEvent {
                label,
                detail,
                threads,
                threadgroup,
                elapsed,
            });
        }
    });
}

fn profile_record_execute(elapsed: Duration) {
    if !profile_enabled() || profile_split_enabled() {
        return;
    }
    PROFILE_STATS.with(|stats| {
        if let Some(stats) = stats.borrow_mut().as_mut() {
            stats.execute_elapsed = Some(elapsed);
        }
    });
}

fn profile_finish() {
    if !profile_enabled() {
        return;
    }

    PROFILE_STATS.with(|stats| {
        let Some(stats) = stats.borrow_mut().take() else {
            return;
        };

        let mut by_label: BTreeMap<&'static str, (u64, u64, u64, Duration)> = BTreeMap::new();
        for event in &stats.events {
            let entry = by_label.entry(event.label).or_default();
            entry.0 += 1;
            entry.1 += event.threads;
            entry.2 = entry.2.max(event.threadgroup);
            if let Some(elapsed) = event.elapsed {
                entry.3 += elapsed;
            }
        }

        std::eprintln!(
            "RPO Metal profile: matrices={} height={} staged={} cutoff={} split={} dispatches={}",
            stats.num_matrices,
            stats.height,
            stats.staged,
            stats.cutoff,
            profile_split_enabled(),
            stats.events.len(),
        );
        if !stats.matrix_descs.is_empty() {
            let descs = stats
                .matrix_descs
                .iter()
                .map(|(height, width, log_scaling)| {
                    std::format!("{height}x{width}/scale={log_scaling}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            std::eprintln!("  matrix descs: [{descs}]");
        }
        if let Some(elapsed) = stats.execute_elapsed {
            std::eprintln!("  batched execute wall time: {:.3} ms", elapsed.as_secs_f64() * 1e3);
        }
        if std::env::var_os(ENV_PROFILE_EVENTS).is_some() {
            for event in &stats.events {
                if let Some(elapsed) = event.elapsed {
                    std::eprintln!(
                        "  event {label:28} detail={detail:6} threads={threads:10} tg={threadgroup:4} wall={wall:.3} ms",
                        label = event.label,
                        detail = event.detail,
                        threads = event.threads,
                        threadgroup = event.threadgroup,
                        wall = elapsed.as_secs_f64() * 1e3,
                    );
                } else {
                    std::eprintln!(
                        "  event {label:28} detail={detail:6} threads={threads:10} tg={threadgroup:4}",
                        label = event.label,
                        detail = event.detail,
                        threads = event.threads,
                        threadgroup = event.threadgroup,
                    );
                }
            }
        }
        for (label, (calls, threads, max_threadgroup, elapsed)) in by_label {
            if profile_split_enabled() {
                std::eprintln!(
                    "  {label:28} calls={calls:3} threads={threads:10} max_tg={max_threadgroup:4} wall={:.3} ms",
                    elapsed.as_secs_f64() * 1e3,
                );
            } else {
                std::eprintln!(
                    "  {label:28} calls={calls:3} threads={threads:10} max_tg={max_threadgroup:4}",
                );
            }
        }
    });
}

pub(crate) fn try_build_rpo_digest_layers<F, D, M, const DIGEST_ELEMS: usize>(
    matrices: &[M],
) -> Option<Vec<Vec<[D; DIGEST_ELEMS]>>>
where
    F: Copy + Send + Sync,
    D: Copy + Send + Sync,
    M: Matrix<F>,
{
    if DIGEST_ELEMS != DIGEST_ELEMS_RPO
        || !has_u64_word_layout::<F>()
        || !has_u64_word_layout::<D>()
        || matrices.is_empty()
    {
        return None;
    }

    let gpu = get_gpu()?;
    let (data_buf, descs, final_height) =
        info_span!("RPO Metal flatten matrices", matrices = matrices.len())
            .in_scope(|| flatten_matrices_to_buffer(gpu, matrices))?;
    let log_n = log2_strict_usize(final_height);
    let desc_buf = info_span!("RPO Metal upload descriptors", matrices = descs.len())
        .in_scope(|| gpu.buf(&descs));
    let cmd = gpu.queue.new_command_buffer();
    let staged = should_use_staged_hashing(matrices);
    let cutoff = tree_cutoff(final_height);
    profile_begin(descs.len(), final_height, staged, cutoff, &descs);
    let (digest_buf, _keepalive_bufs) =
        info_span!("RPO Metal encode leaves", staged, height = final_height).in_scope(|| {
            if staged {
                encode_staged_hash_leaves(
                    gpu,
                    cmd,
                    &data_buf,
                    &desc_buf,
                    matrices,
                    final_height,
                    log_n,
                )
            } else {
                Some((
                    encode_direct_hash_leaves(
                        gpu,
                        cmd,
                        &data_buf,
                        &desc_buf,
                        descs.len(),
                        final_height,
                        log_n,
                    ),
                    Vec::new(),
                ))
            }
        })?;

    let mut layer_bufs = std::vec::Vec::new();
    let mut level_size = final_height;
    info_span!("RPO Metal encode tree", height = final_height, cutoff).in_scope(|| {
        while level_size > cutoff {
            let parent_count = level_size / 2;
            let dst = gpu.empty_buf(parent_count * DIGEST_ELEMS_RPO * mem::size_of::<u64>());
            let src = layer_bufs.last().unwrap_or(&digest_buf);
            gpu.dispatch(
                "compress_level",
                parent_count as u64,
                cmd,
                &gpu.compress_pipeline,
                &[src, &dst],
                parent_count as u64,
            );
            layer_bufs.push(dst);
            level_size = parent_count;
        }
    });

    info_span!("RPO Metal execute").in_scope(|| {
        let started = Instant::now();
        cmd.commit();
        cmd.wait_until_completed();
        profile_record_execute(started.elapsed());
    });

    let digest_layers = info_span!("RPO Metal read layers", layers = 1 + layer_bufs.len())
        .in_scope(|| {
            let mut digest_layers = Vec::with_capacity(1 + layer_bufs.len());
            digest_layers.push(read_digest_layer::<D, DIGEST_ELEMS>(&digest_buf, final_height));

            let mut layer_size = final_height;
            for buf in &layer_bufs {
                layer_size /= 2;
                digest_layers.push(read_digest_layer::<D, DIGEST_ELEMS>(buf, layer_size));
            }
            digest_layers
        });

    profile_finish();
    Some(digest_layers)
}

fn should_use_staged_hashing<F, M>(matrices: &[M]) -> bool
where
    F: Clone + Send + Sync,
    M: Matrix<F>,
{
    matrices.windows(2).any(|window| window[0].height() != window[1].height())
}

fn encode_direct_hash_leaves(
    gpu: &GpuContext,
    cmd: &metal::CommandBufferRef,
    data_buf: &metal::Buffer,
    desc_buf: &metal::Buffer,
    num_matrices: usize,
    final_height: usize,
    log_n: usize,
) -> metal::Buffer {
    let digest_buf = gpu.empty_buf(final_height * DIGEST_ELEMS_RPO * mem::size_of::<u64>());
    let params = [num_matrices as u32, log_n as u32];
    gpu.dispatch_with_bytes(
        "hash_leaves",
        num_matrices as u64,
        cmd,
        &gpu.hash_leaves_pipeline,
        &[(0, data_buf), (1, desc_buf), (2, &digest_buf)],
        3,
        &params,
        final_height as u64,
    );
    digest_buf
}

fn encode_staged_hash_leaves<F, M>(
    gpu: &GpuContext,
    cmd: &metal::CommandBufferRef,
    data_buf: &metal::Buffer,
    desc_buf: &metal::Buffer,
    matrices: &[M],
    final_height: usize,
    log_n: usize,
) -> Option<(metal::Buffer, Vec<metal::Buffer>)>
where
    F: Clone + Send + Sync,
    M: Matrix<F>,
{
    let mut state_bufs = Vec::new();
    let first_height = matrices.first()?.height();
    state_bufs.push(gpu.zeroed_buf(first_height * STATE_WIDTH * mem::size_of::<u64>()));

    let mut active_height = first_height;
    for (matrix_idx, matrix) in matrices.iter().enumerate() {
        let height = matrix.height();
        if height > active_height {
            let repeat_log = log2_strict_usize(height / active_height);
            let dst = gpu.empty_buf(height * STATE_WIDTH * mem::size_of::<u64>());
            let src = state_bufs.last().expect("state buffer exists");
            gpu.dispatch_with_bytes(
                "absorb_matrix_expanded",
                matrix_idx as u64,
                cmd,
                &gpu.absorb_matrix_expanded_pipeline,
                &[(0, data_buf), (1, desc_buf), (2, src), (3, &dst)],
                4,
                &[matrix_idx as u32, repeat_log as u32],
                height as u64,
            );
            state_bufs.push(dst);
            active_height = height;
            continue;
        }

        let state_buf = state_bufs.last().expect("state buffer exists");
        gpu.dispatch_with_bytes(
            "absorb_matrix",
            matrix_idx as u64,
            cmd,
            &gpu.absorb_matrix_pipeline,
            &[(0, data_buf), (1, desc_buf), (2, state_buf)],
            3,
            &[matrix_idx as u32],
            height as u64,
        );
    }

    debug_assert_eq!(active_height, final_height);
    let digest_buf = gpu.empty_buf(final_height * DIGEST_ELEMS_RPO * mem::size_of::<u64>());
    let state_buf = state_bufs.last().expect("state buffer exists");
    gpu.dispatch_with_bytes(
        "squeeze_leaves",
        log_n as u64,
        cmd,
        &gpu.squeeze_leaves_pipeline,
        &[(0, state_buf), (1, &digest_buf)],
        2,
        &[log_n as u32],
        final_height as u64,
    );

    Some((digest_buf, state_bufs))
}

fn flatten_matrices_to_buffer<F, M>(
    gpu: &GpuContext,
    matrices: &[M],
) -> Option<(metal::Buffer, Vec<MatrixDesc>, usize)>
where
    F: Copy + Send + Sync,
    M: Matrix<F>,
{
    let final_height = validate_heights(matrices)?;
    let data_len: usize = matrices.iter().map(|matrix| matrix.height() * matrix.width()).sum();
    let data_buf = gpu.empty_buf(data_len.max(1) * mem::size_of::<u64>());
    let data = data_buf.contents() as *mut u64;
    let mut descs = Vec::with_capacity(matrices.len());
    let mut offset = 0;

    for matrix in matrices {
        let matrix_offset = offset as u64;
        for row_idx in 0..matrix.height() {
            let row = matrix.row(row_idx).expect("row index was validated");
            for value in row {
                unsafe {
                    // SAFETY: `data_buf` contains `data_len` u64 slots and `offset < data_len`
                    // for every matrix element written by this loop.
                    data.add(offset).write(canonical_u64_from_field(value));
                }
                offset += 1;
            }
        }

        descs.push(MatrixDesc {
            offset: matrix_offset,
            height: matrix.height().try_into().ok()?,
            width: matrix.width().try_into().ok()?,
            log_scaling: log2_strict_usize(final_height / matrix.height()).try_into().ok()?,
            _pad: 0,
        });
    }

    debug_assert_eq!(offset, data_len);
    Some((data_buf, descs, final_height))
}

fn validate_heights<F, M>(matrices: &[M]) -> Option<usize>
where
    F: Clone + Send + Sync,
    M: Matrix<F>,
{
    let mut active_height = 0;
    for matrix in matrices {
        let height = matrix.height();
        if height == 0 || !height.is_power_of_two() || height < active_height {
            return None;
        }
        active_height = height;
    }
    (active_height != 0).then_some(active_height)
}

#[inline]
fn canonical_u64_from_field<F: Copy>(value: F) -> u64 {
    debug_assert!(has_u64_word_layout::<F>());
    // SAFETY: the caller enables this path only for Goldilocks-backed 64-bit field words.
    let raw = unsafe { mem::transmute_copy::<F, u64>(&value) };
    if raw >= GOLDILOCKS_MODULUS {
        raw - GOLDILOCKS_MODULUS
    } else {
        raw
    }
}

#[inline]
fn field_from_canonical_u64<D: Copy>(value: u64) -> D {
    debug_assert!(value < GOLDILOCKS_MODULUS);
    debug_assert!(has_u64_word_layout::<D>());
    // SAFETY: the input is a canonical Goldilocks word and `D` has the checked word layout.
    unsafe { mem::transmute_copy::<u64, D>(&value) }
}

fn read_digest_layer<D: Copy, const DIGEST_ELEMS: usize>(
    buf: &metal::Buffer,
    len: usize,
) -> Vec<[D; DIGEST_ELEMS]> {
    let words = unsafe {
        // SAFETY: RPO digest buffers store `len * DIGEST_ELEMS` contiguous u64 words, and the
        // command buffer has completed before layers are read.
        core::slice::from_raw_parts(buf.contents() as *const u64, len * DIGEST_ELEMS)
    };
    (0..len)
        .map(|row| {
            core::array::from_fn(|idx| field_from_canonical_u64(words[row * DIGEST_ELEMS + idx]))
        })
        .collect()
}
