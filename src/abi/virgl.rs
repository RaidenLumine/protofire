//! src/abi/virgl.rs
//!
//! Minimal VIRGL command-stream framing used by the demo 3D renderer.
//!
//! The real VIRGL wire format is defined by the virglrenderer project and is
//! not vendored in this repository, so the demo defines a small, documented
//! subset of its own: every command is `[type, arg_count, args...]` u32 words,
//! where `arg_count` counts the argument words that follow the header.  The
//! kernel treats submitted command streams as opaque bytes and forwards them
//! to the GPU device unchanged (see `syscall/gpu.rs`), so this framing only
//! has to be self-consistent between the renderer and the device/mock that
//! consumes the stream.
//!
//! The renderer drives two command types — a full-viewport clear and a
//! triangle draw — and the mock device validates that the submitted bytes
//! decode back to exactly that stream.

/// Number of header words in every command (`[type, arg_count]`).
pub const VIRGL_CMD_HEADER_WORDS: usize = 2;

/// Command type: clear the render target to a solid color.
pub const VIRGL_CMD_CLEAR: u32 = 1;
/// Command type: draw a triangle strip into the render target.
pub const VIRGL_CMD_DRAW: u32 = 2;

/// Argument words for a `VIRGL_CMD_CLEAR` (`[r, g, b, a]`).
pub const VIRGL_CLEAR_ARG_WORDS: usize = 4;
/// Argument words for a `VIRGL_CMD_DRAW`
/// (`[num_vertices, vertex_start, mode, instance_count, reserved]`).
pub const VIRGL_DRAW_ARG_WORDS: usize = 5;

/// Fixed capacity (in u32 words) of the demo command buffer.
pub const VIRGL_CMD_BUFFER_WORDS: usize = 32;

/// Render-target dimensions chosen by the demo (matches the mock's display).
pub const VIRGL_DEMO_WIDTH: u32 = 640;
pub const VIRGL_DEMO_HEIGHT: u32 = 480;
/// Demo context and resource identifiers (single-context, single-target).
pub const VIRGL_DEMO_CTX_ID: u32 = 1;
pub const VIRGL_DEMO_RESOURCE_ID: u32 = 1;
/// Render-target descriptor fields (opaque to the kernel, meaningful to the
/// device): a 2D RGBA render target bound for both rendering and sampling.
pub const VIRGL_DEMO_RESOURCE_TARGET: u32 = 2; // PIPE_TEXTURE_2D
pub const VIRGL_DEMO_RESOURCE_FORMAT: u32 = 1; // PIPE_FORMAT_B8G8R8A8_UNORM
pub const VIRGL_DEMO_RESOURCE_BIND: u32 = 3; // RT | SAMPLER_VIEW
/// Bytes per pixel of the RGBA render target.
pub const VIRGL_DEMO_BYTES_PER_PIXEL: u32 = 4;
/// Row stride of the render target.
pub const VIRGL_DEMO_STRIDE: u32 = VIRGL_DEMO_WIDTH * VIRGL_DEMO_BYTES_PER_PIXEL;
/// Clear color used by the demo (opaque black).
pub const VIRGL_DEMO_CLEAR_COLOR: [u32; 4] = [0, 0, 0, 0];
/// Primitive mode used by the demo draw (triangle list).
pub const VIRGL_DEMO_DRAW_MODE: u32 = 4; // PIPE_PRIM_TRIANGLES
/// Number of vertices in the demo draw.
pub const VIRGL_DEMO_DRAW_VERTICES: u32 = 3;

/// Total words consumed by a `VIRGL_CMD_CLEAR`.
pub const fn clear_command_words() -> usize {
    VIRGL_CMD_HEADER_WORDS + VIRGL_CLEAR_ARG_WORDS
}

/// Total words consumed by a `VIRGL_CMD_DRAW`.
pub const fn draw_command_words() -> usize {
    VIRGL_CMD_HEADER_WORDS + VIRGL_DRAW_ARG_WORDS
}

/// Total words in the canonical demo stream (clear + draw).
pub const fn demo_command_word_count() -> usize {
    clear_command_words() + draw_command_words()
}

/// Total bytes in the canonical demo stream (little-endian u32 words).
pub const fn demo_command_byte_count() -> usize {
    demo_command_word_count() * 4
}

/// Failure mode reported by the command encoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The caller-provided buffer is smaller than the encoded command.
    BufferTooSmall,
}

/// Encode a `VIRGL_CMD_CLEAR` at the start of `buffer`, returning the number
/// of words written (`Err` when `buffer` is too small).
pub fn encode_clear(buffer: &mut [u32], color: [u32; 4]) -> Result<usize, EncodeError> {
    let used = clear_command_words();
    if buffer.len() < used {
        return Err(EncodeError::BufferTooSmall);
    }
    buffer[0] = VIRGL_CMD_CLEAR;
    buffer[1] = VIRGL_CLEAR_ARG_WORDS as u32;
    buffer[2..6].copy_from_slice(&color);
    Ok(used)
}

/// Encode a `VIRGL_CMD_DRAW` at the start of `buffer`, returning the number of
/// words written (`Err` when `buffer` is too small).
pub fn encode_draw(
    buffer: &mut [u32],
    num_vertices: u32,
    vertex_start: u32,
    mode: u32,
    instance_count: u32,
) -> Result<usize, EncodeError> {
    let used = draw_command_words();
    if buffer.len() < used {
        return Err(EncodeError::BufferTooSmall);
    }
    buffer[0] = VIRGL_CMD_DRAW;
    buffer[1] = VIRGL_DRAW_ARG_WORDS as u32;
    buffer[2] = num_vertices;
    buffer[3] = vertex_start;
    buffer[4] = mode;
    buffer[5] = instance_count;
    buffer[6] = 0; // reserved
    Ok(used)
}

/// A decoded command from the minimal framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirglCommand<'a> {
    pub command_type: u32,
    pub arg_count: u32,
    pub args: &'a [u32],
}

/// Failure mode reported by [`walk_commands`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirglCommandError {
    /// A command header is truncated (fewer than `VIRGL_CMD_HEADER_WORDS`).
    TruncatedHeader,
    /// A command advertises more argument words than remain in the buffer.
    TruncatedArgs,
}

/// Decode every command in `words`, validating the `[type, arg_count, args...]`
/// framing.  An empty tail is accepted; a partial header or short arg run is a
/// framing error.
pub fn walk_commands(
    words: &[u32],
) -> Result<alloc::vec::Vec<VirglCommand<'_>>, VirglCommandError> {
    let mut commands = alloc::vec::Vec::new();
    let mut index = 0;
    while index < words.len() {
        if words.len() - index < VIRGL_CMD_HEADER_WORDS {
            return Err(VirglCommandError::TruncatedHeader);
        }
        let command_type = words[index];
        let arg_count = words[index + 1] as usize;
        let end = index + VIRGL_CMD_HEADER_WORDS + arg_count;
        if end > words.len() {
            return Err(VirglCommandError::TruncatedArgs);
        }
        commands.push(VirglCommand {
            command_type,
            arg_count: arg_count as u32,
            args: &words[index + VIRGL_CMD_HEADER_WORDS..end],
        });
        index = end;
    }
    Ok(commands)
}

/// Serialise u32 words as little-endian bytes into `out`, returning the number
/// of bytes written (truncated to `out` capacity).
pub fn words_to_le_bytes(words: &[u32], out: &mut [u8]) -> usize {
    let word_count = words.len().min(out.len() / 4);
    for (index, word) in words[..word_count].iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    word_count * 4
}

/// Decode little-endian u32 words from `bytes` into `out`, returning the number
/// of words written (truncated to `out` capacity).
pub fn le_bytes_to_words(bytes: &[u8], out: &mut [u32]) -> usize {
    let word_count = (bytes.len() / 4).min(out.len());
    for index in 0..word_count {
        out[index] = u32::from_le_bytes(
            bytes[index * 4..index * 4 + 4]
                .try_into()
                .expect("word slice in bounds"),
        );
    }
    word_count
}

/// Build the canonical demo command stream: a full-viewport clear followed by a
/// triangle draw.  Returns the buffer and the number of words used.
pub fn build_demo_clear_draw() -> ([u32; VIRGL_CMD_BUFFER_WORDS], usize) {
    let mut buffer = [0u32; VIRGL_CMD_BUFFER_WORDS];
    let clear_words = encode_clear(&mut buffer, VIRGL_DEMO_CLEAR_COLOR).expect("buffer capacity");
    let draw_words = encode_draw(
        &mut buffer[clear_words..],
        VIRGL_DEMO_DRAW_VERTICES,
        0,
        VIRGL_DEMO_DRAW_MODE,
        1,
    )
    .expect("buffer capacity");
    (buffer, clear_words + draw_words)
}

/// Build the demo's render-target descriptor (a 640×480 2D RGBA texture).
pub fn build_demo_render_target_desc() -> crate::abi::gpu::GpuResCreate3dDesc {
    crate::abi::gpu::GpuResCreate3dDesc {
        resource_id: VIRGL_DEMO_RESOURCE_ID,
        target: VIRGL_DEMO_RESOURCE_TARGET,
        format: VIRGL_DEMO_RESOURCE_FORMAT,
        bind: VIRGL_DEMO_RESOURCE_BIND,
        width: VIRGL_DEMO_WIDTH,
        height: VIRGL_DEMO_HEIGHT,
        depth: 1,
        array_size: 1,
        levels: 1,
        sample_count: 0,
        num_samples: 0,
        stride: VIRGL_DEMO_STRIDE,
    }
}

/// Serialise a `GpuResCreate3dDesc` into its ABI byte layout (12 × u32, LE).
pub fn serialize_create_3d_desc(
    desc: &crate::abi::gpu::GpuResCreate3dDesc,
    out: &mut [u8],
) -> usize {
    let fields = [
        desc.resource_id,
        desc.target,
        desc.format,
        desc.bind,
        desc.width,
        desc.height,
        desc.depth,
        desc.array_size,
        desc.levels,
        desc.sample_count,
        desc.num_samples,
        desc.stride,
    ];
    words_to_le_bytes(&fields, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_sizes_match_frame_layout() {
        assert_eq!(clear_command_words(), 6);
        assert_eq!(draw_command_words(), 7);
        assert_eq!(demo_command_word_count(), 13);
        assert_eq!(demo_command_byte_count(), 52);
        assert!(demo_command_word_count() <= VIRGL_CMD_BUFFER_WORDS);
    }

    #[test]
    fn encode_decode_round_trip() {
        let (words, used) = build_demo_clear_draw();
        let decoded = walk_commands(&words[..used]).expect("valid framing");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].command_type, VIRGL_CMD_CLEAR);
        assert_eq!(decoded[0].arg_count, VIRGL_CLEAR_ARG_WORDS as u32);
        assert_eq!(decoded[0].args, &VIRGL_DEMO_CLEAR_COLOR);
        assert_eq!(decoded[1].command_type, VIRGL_CMD_DRAW);
        assert_eq!(decoded[1].arg_count, VIRGL_DRAW_ARG_WORDS as u32);
        assert_eq!(decoded[1].args[0], VIRGL_DEMO_DRAW_VERTICES);
        assert_eq!(decoded[1].args[1], 0);
        assert_eq!(decoded[1].args[2], VIRGL_DEMO_DRAW_MODE);
        assert_eq!(decoded[1].args[3], 1);
    }

    #[test]
    fn byte_serialization_round_trip() {
        let (words, used) = build_demo_clear_draw();
        let mut bytes = [0u8; demo_command_byte_count()];
        let written = words_to_le_bytes(&words[..used], &mut bytes);
        assert_eq!(written, demo_command_byte_count());

        let mut decoded_words = [0u32; VIRGL_CMD_BUFFER_WORDS];
        let decoded_count = le_bytes_to_words(&bytes, &mut decoded_words);
        assert_eq!(decoded_count, used);
        assert_eq!(&decoded_words[..used], &words[..used]);
    }

    #[test]
    fn walk_commands_rejects_malformed_streams() {
        // Header present but args truncated.
        assert_eq!(
            walk_commands(&[VIRGL_CMD_CLEAR, VIRGL_CLEAR_ARG_WORDS as u32, 0, 0, 0]),
            Err(VirglCommandError::TruncatedArgs)
        );
        // Header itself truncated.
        assert_eq!(
            walk_commands(&[VIRGL_CMD_CLEAR]),
            Err(VirglCommandError::TruncatedHeader)
        );
        // Empty stream decodes cleanly.
        assert_eq!(walk_commands(&[]), Ok(alloc::vec![]));
    }

    #[test]
    fn render_target_desc_serializes_to_abi_size() {
        let desc = build_demo_render_target_desc();
        assert_eq!(desc.resource_id, VIRGL_DEMO_RESOURCE_ID);
        assert_eq!(desc.width, VIRGL_DEMO_WIDTH);
        assert_eq!(desc.height, VIRGL_DEMO_HEIGHT);
        assert_eq!(desc.stride, VIRGL_DEMO_STRIDE);

        let mut bytes = [0u8; crate::abi::gpu::GPU_RES_CREATE_3D_DESC_SIZE];
        let written = serialize_create_3d_desc(&desc, &mut bytes);
        assert_eq!(written, crate::abi::gpu::GPU_RES_CREATE_3D_DESC_SIZE);
        // resource_id is the first u32.
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            VIRGL_DEMO_RESOURCE_ID
        );
    }
}
