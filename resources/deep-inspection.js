// Adapted from upstream Snitch; see UPSTREAM.json and LICENSE.
function emit(payload) { send({type: "rust-snitch", id: 0, result: "ok", returns: payload}); }

var AF_INET = 2, AF_INET6_WIN = 23, AF_INET6_UNIX = 10;
function parseSockaddr(p) {
    try {
        var fam = p.readU16();
        if (fam === AF_INET) {
            return {ip: [p.add(4).readU8(), p.add(5).readU8(),
                         p.add(6).readU8(), p.add(7).readU8()].join('.'),
                    port: (p.add(2).readU8() << 8) | p.add(3).readU8()};
        }
        if (fam === AF_INET6_WIN || fam === AF_INET6_UNIX) {
            var b = [];
            for (var i = 8; i < 24; i += 2)
                b.push(((p.add(i).readU8() << 8) | p.add(i + 1).readU8()).toString(16));
            return {ip: b.join(':'),
                    port: (p.add(2).readU8() << 8) | p.add(3).readU8()};
        }
    } catch (e) {}
    return null;
}
function hook(api, lib) {
    var addr = null;
    try { addr = lib ? Process.getModuleByName(lib).getExportByName(api)
                     : Module.findGlobalExportByName(api); }
    catch (e) { addr = null; }
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var saPtr = api === 'sendto' ? ptr(args[4]) : (api === 'sendmsg' ? ptr(args[1]).readPointer() : ptr(args[1]));
            var sa = parseSockaddr(saPtr);
            if (!sa || !sa.ip || sa.ip === '0.0.0.0') return;
            var mod = null;
            try { mod = Process.findModuleByAddress(this.returnAddress); }
            catch (e) {}
            emit({api: api, ip: sa.ip, port: sa.port,
                  module: mod ? mod.name : '?',
                  path: mod ? mod.path : ''});
        }
    });
}
// EN: POSIX sockets (Linux libc / macOS libsystem) + WinSock2.
// FR: sockets POSIX (libc Linux / libsystem macOS) + WinSock2.
['connect', 'sendto', 'sendmsg'].forEach(function (a) {
    hook(a, null); hook(a, 'libc.so'); hook(a, 'libSystem.B.dylib');
});
['WSAConnect', 'connect'].forEach(function (a) {
    hook(a, 'ws2_32.dll');
});

// ── Payload tracing / Traçage de payload ────────────────────────────────
// EN: Data-flow evidence (the honest user-mode DTA slice): hook the send
//     boundary itself, record which module emitted the bytes plus a 16-byte
//     head + declared length — enough to prove "this DLL sent these bytes"
//     without storing payloads. Bounded by the global event budget.
// FR: Preuve de flux de données (la tranche DTA user-mode honnête) : hooker
//     la frontière send elle-même, noter quel module a émis les octets plus
//     une tête de 16 octets + longueur déclarée — suffit pour prouver
//     « cette DLL a envoyé ces octets » sans stocker les payloads. Borné
//     par le budget global d'événements.
var _sendCount = 0, _SEND_MAX = 200;
function hookSend(api, lib, bufIdx, lenIdx) {
    var addr = null;
    try { addr = lib ? Process.getModuleByName(lib).getExportByName(api)
                     : Module.findGlobalExportByName(api); }
    catch (e) { addr = null; }
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (++_sendCount > _SEND_MAX) return;
            var n = args[lenIdx].toInt32();
            if (n <= 0) return;
            var head = '';
            try { head = args[bufIdx].readByteArray(Math.min(n, 16)); }
            catch (e) { return; }
            var mod = null;
            try { mod = Process.findModuleByAddress(this.returnAddress); }
            catch (e) {}
            var hex = [];
            var bytes = new Uint8Array(head);
            for (var i = 0; i < bytes.length; i++)
                hex.push(('0' + bytes[i].toString(16)).slice(-2));
            emit({api: api, kind: 'send', n: n, head: hex.join(''),
                  module: mod ? mod.name : '?',
                  path: mod ? mod.path : ''});
        }
    });
}
// EN: POSIX send(fd,buf,len,flags) — send() on a connected socket carries
//     no sockaddr; sendto(fd,buf,len,flags,sa,salen) has buf/len at 1/2.
// FR: send POSIX (fd,buf,len,flags) — pas de sockaddr sur socket connectée ;
//     sendto a buf/len en positions 1/2.
hookSend('send', null, 1, 2); hookSend('send', 'libc.so', 1, 2);
hookSend('send', 'libSystem.B.dylib', 1, 2);
hookSend('sendto', null, 1, 2); hookSend('sendto', 'libc.so', 1, 2);
hookSend('send', 'ws2_32.dll', 1, 2);
// EN: WSASend(s, lpBuffers, count, ...) — lpBuffers points at a WSABUF
//     array {u32 len; pad; char* buf} on x64.
// FR: WSASend(s, lpBuffers, count, ...) — tableau de WSABUF
//     {u32 len ; pad ; char* buf} en x64.
(function hookWSASend() {
    var addr = null;
    try { addr = Module.getExportByName('ws2_32.dll', 'WSASend'); }
    catch (e) { return; }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (++_sendCount > _SEND_MAX) return;
            try {
                var wsa = ptr(args[1]);
                var n = wsa.readU32();
                var buf = wsa.add(Process.pointerSize).readPointer();
                if (n <= 0 || buf.isNull()) return;
                var head = buf.readByteArray(Math.min(n, 16));
                var mod = null;
                try { mod = Process.findModuleByAddress(this.returnAddress); }
                catch (e) {}
                var bytes = new Uint8Array(head), hex = [];
                for (var i = 0; i < bytes.length; i++)
                    hex.push(('0' + bytes[i].toString(16)).slice(-2));
                emit({api: 'WSASend', kind: 'send', n: n, head: hex.join(''),
                      module: mod ? mod.name : '?',
                      path: mod ? mod.path : ''});
            } catch (e) {}
        }
    });
})();
