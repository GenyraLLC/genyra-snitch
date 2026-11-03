# Local binding fix

Source: crates.io `frida` 0.17.2, https://github.com/frida/frida-rust . Individual source files retain their wxWindows Library Licence 3.1 notices.

`Script::handle_message` passes a `CallbackHandler` pointer as GLib user data. The non-RPC branch of `call_on_message` incorrectly casts it to the user's handler type. This fork accesses `CallbackHandler.script_handler` instead. The original code reproducibly segfaulted on the first fixture event. The integration harness exercises real attach, connection/send events, unload and detach.

No upstream report has been sent.
