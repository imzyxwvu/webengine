# Decoder

Decoders are Lua closures which take a StreamBuffer as argument and try to decode the message at the beginning of the buffer. If a message is successfully decoded, a Lua object is returned and bytes of this message are removed from the StreamBuffer with stb_pull(). If data in the StreamBuffer is not enough for current message, nil is returned, and the decoder will be called again when more data is available. When the decoder considers the current data is illegal, it throws a Lua error.

Decoders are typically implemented in C as Lua C closures for performance advantages. C also does a better job handling byte buffers. It is possible to implement decoders with pure Lua.

Currently there are some decoders already implemented in webcore:

* decode_request: Decodes a HTTP/1.x request with all header keys downcased.
* decode_request: Decodes a HTTP/1.x response.
* decode_fcgi: Decodes a FastCGI frame.
* decode_wsframe: Decodes a WebSocket frame.
* decode_any: Transforms all data in the buffer to a Lua string.
