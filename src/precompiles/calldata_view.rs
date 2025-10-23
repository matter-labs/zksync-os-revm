use revm::{context::LocalContextTr, context_interface::ContextTr, interpreter::CallInput};

/// Helper wrapper that lends a stable slice over call input bytes.
///
/// The REVM interpreter keeps call data in a shared buffer that is reused across frames.
/// When a precompile is invoked we need a borrow of that buffer while we parse the input,
/// but we must also release the borrow before mutating the context (e.g. touching accounts).
///
/// `CalldataView` encapsulates that pattern:
/// - it either stores a direct reference to the original bytes (when the input was `Bytes`)
///   or holds the `Ref<[u8]>` returned by `shared_memory_buffer_slice`;
/// - callers grab the slice via `as_slice()`, do their parsing, and then drop the wrapper
///   once they are ready to mutate the context.
pub struct CalldataView<'a> {
    direct: &'a [u8],
    borrow: Option<core::cell::Ref<'a, [u8]>>,
}

impl<'a> CalldataView<'a> {
    pub fn new<CTX>(ctx: &'a CTX, input: &'a CallInput) -> Self
    where
        CTX: ContextTr<Local: LocalContextTr>,
    {
        match input {
            CallInput::Bytes(bytes) => Self {
                direct: bytes.as_ref(),
                borrow: None,
            },
            CallInput::SharedBuffer(range) => {
                match ctx.local().shared_memory_buffer_slice(range.clone()) {
                    Some(borrow) => Self {
                        direct: &[],
                        borrow: Some(borrow),
                    },
                    None => Self {
                        direct: &[],
                        borrow: None,
                    },
                }
            }
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        if let Some(ref borrow) = self.borrow {
            borrow.as_ref()
        } else {
            self.direct
        }
    }
}
