# StreamBuffer

StreamBuffer are reference-counted mutable buffers for ingress data. They work like FIFO byte queues and are designed to work with decoders. Stream buffers have several C APIs and can be exposed to Lua code as a userdata which retains a reference to the stream buffer.

## streambuffer_t *stb_alloc()

Allocate an empty stream buffer. The reference count is set to 1. If memory allocation is failed, NULL is returned.

## void stb_pull(streambuffer_t *sb, int nb)

Remove first nb bytes in the buffer.

## streambuffer_t *stb_retain(streambuffer_t *sb)

Increase the reference count and return the StreamBuffer itself.

## void stb_unref(streambuffer_t *sb)

Decrease the reference count. If the reference count reaches 0, the StreamBuffer is freed.

