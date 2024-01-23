import socket
from struct import *
import zlib
import time
import json
from enum import IntEnum, auto
import threading
import random
from packaging.version import Version, parse
from queue import Queue
import toml
import asyncio
import json
import websockets

# global var
Lock = threading.Lock()
SendMessageQueue = Queue()
RecvMessageQueue = Queue()
HeapSize = 0

CEVERSION = None
PORT = 52736

# const var
PROCESS_ALL_ACCESS = 0x1F0FFF

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPTHREAD = 0x4
TH32CS_SNAPMODULE = 0x8

PAGE_NOACCESS = 1
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_WRITECOPY = 8
PAGE_EXECUTE = 16
PAGE_EXECUTE_READ = 32
PAGE_EXECUTE_READWRITE = 64

MEM_MAPPED = 262144
MEM_PRIVATE = 131072

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

MAP_SHARED = 1
MAP_PRIVATE = 2
MAP_ANONYMOUS = 32

VQE_PAGEDONLY = 1
VQE_DIRTYONLY = 2
VQE_NOSHARED = 4

RegionList = None
ModuleList = None
ModuleListIterator = 0


def ProtectionStringToType(protectionstring):
    if protectionstring.find("s") != -1:
        return MEM_MAPPED
    else:
        return MEM_PRIVATE


def ProtectionStringToProtection(protectionstring):
    w = 0
    x = 0

    if protectionstring.find("x") != -1:
        x = True
    else:
        x = False

    if protectionstring.find("w") != -1:
        w = True
    else:
        w = False

    if x:
        # executable
        if w:
            return PAGE_EXECUTE_READWRITE
        else:
            return PAGE_EXECUTE_READ
    else:
        # not executable
        if w:
            return PAGE_READWRITE
        else:
            return PAGE_READONLY

def module32first():
    global HeapSize
    if HeapSize == 0:
        SendMessageQueue.put({"command": "get_heap_size"})
        HeapSize = RecvMessageQueue.get()
    base = 0
    size = HeapSize
    name = "HEAP"
    return [base, size, name]


def module32next():
    return False


class CECMD(IntEnum):
    CMD_GETVERSION = 0
    CMD_CLOSECONNECTION = 1
    CMD_TERMINATESERVER = 2
    CMD_OPENPROCESS = 3
    CMD_CREATETOOLHELP32SNAPSHOT = 4
    CMD_PROCESS32FIRST = 5
    CMD_PROCESS32NEXT = 6
    CMD_CLOSEHANDLE = 7
    CMD_VIRTUALQUERYEX = 8
    CMD_READPROCESSMEMORY = 9
    CMD_WRITEPROCESSMEMORY = 10
    CMD_STARTDEBUG = 11
    CMD_STOPDEBUG = 12
    CMD_WAITFORDEBUGEVENT = 13
    CMD_CONTINUEFROMDEBUGEVENT = 14
    CMD_SETBREAKPOINT = 15
    CMD_REMOVEBREAKPOINT = 16
    CMD_SUSPENDTHREAD = 17
    CMD_RESUMETHREAD = 18
    CMD_GETTHREADCONTEXT = 19
    CMD_SETTHREADCONTEXT = 20
    CMD_GETARCHITECTURE = 21
    CMD_MODULE32FIRST = 22
    CMD_MODULE32NEXT = 23
    CMD_GETSYMBOLLISTFROMFILE = 24
    CMD_LOADEXTENSION = 25
    CMD_ALLOC = 26
    CMD_FREE = 27
    CMD_CREATETHREAD = 28
    CMD_LOADMODULE = 29
    CMD_SPEEDHACK_SETSPEED = 30
    CMD_VIRTUALQUERYEXFULL = 31
    CMD_GETREGIONINFO = 32
    CMD_GETABI = 33
    CMD_SET_CONNECTION_NAME = 34
    CMD_CREATETOOLHELP32SNAPSHOTEX = 35
    CMD_CHANGEMEMORYPROTECTION = 36
    CMD_GETOPTIONS = 37
    CMD_GETOPTIONVALUE = 38
    CMD_SETOPTIONVALUE = 39
    CMD_PTRACE_MMAP = 40
    CMD_OPENNAMEDPIPE = 41
    CMD_PIPEREAD = 42
    CMD_PIPEWRITE = 43
    CMD_GETCESERVERPATH = 44
    CMD_ISANDROID = 45
    CMD_AOBSCAN = 200
    CMD_COMMANDLIST2 = 255


def recvall(s, size, flags=0):
    buffer = bytearray(size)
    view = memoryview(buffer)
    pos = 0
    while pos < size:
        read = s.recv_into(view[pos:], size - pos, flags)
        if not read:
            continue  # IncompleteReadError(bytes(view[:pos]), size)
        pos += read
    return bytes(buffer)


class BinaryReader:
    def __init__(self, base):
        self.base = base

    def ReadInt8(self):
        result = recvall(self.base, 1)
        ret = unpack("<b", result)[0]
        return ret

    def ReadInt16(self):
        result = recvall(self.base, 2)
        ret = unpack("<h", result)[0]
        return ret

    def ReadInt32(self):
        result = recvall(self.base, 4)
        ret = unpack("<i", result)[0]
        return ret

    def ReadInt64(self):
        result = recvall(self.base, 8)
        ret = unpack("<q", result)[0]
        return ret

    def ReadUInt8(self):
        result = recvall(self.base, 1)
        ret = unpack("<B", result)[0]
        return ret

    def ReadUInt16(self):
        result = recvall(self.base, 2)
        ret = unpack("<H", result)[0]
        return ret

    def ReadUInt32(self):
        result = recvall(self.base, 4)
        ret = unpack("<I", result)[0]
        return ret

    def ReadUInt64(self):
        result = recvall(self.base, 8)
        ret = unpack("<Q", result)[0]
        return ret

    def ReadString16(self):
        l = self.ReadUInt16()
        result = recvall(self.base, l)
        ret = result.decode()
        return ret


class BinaryWriter:
    def __init__(self, base):
        self.base = base

    def WriteInt8(self, number):
        i8 = pack("<b", number)
        self.base.sendall(i8)

    def WriteInt16(self, number):
        i16 = pack("<h", number)
        self.base.sendall(i16)

    def WriteInt32(self, number):
        i32 = pack("<i", number)
        self.base.sendall(i32)

    def WriteInt64(self, number):
        i64 = pack("<q", number)
        self.base.sendall(i64)

    def WriteUInt8(self, number):
        ui8 = pack("<B", number)
        self.base.sendall(ui8)

    def WriteUInt16(self, number):
        ui16 = pack("<H", number)
        self.base.sendall(ui16)

    def WriteUInt32(self, number):
        ui32 = pack("<I", number)
        self.base.sendall(ui32)

    def WriteUInt64(self, number):
        ui64 = pack("<Q", number)
        self.base.sendall(ui64)


def GetSymbolListFromFile(filename, output):
    ret = False

    if ret != False and len(ret) > 0:
        bytecode = b""
        for i in range(len(ret)):
            baseaddress = ret[i][0]
            size = ret[i][1]
            _type = 0
            name = ret[i][3].encode()
            if len(name) > 127:
                name = name[0:127]
            namelength = len(name)
            try:
                tmp = pack(
                    "<Qiib" + str(namelength) + "s",
                    baseaddress,
                    size,
                    _type,
                    namelength,
                    name,
                )
                bytecode = b"".join([bytecode, tmp])
            except Exception as e:
                pass
        compress_data = zlib.compress(bytecode)
        sendall_data = pack("<iii", 0, len(compress_data) + 12, len(bytecode))
        sendall_data += compress_data
        output[0] = sendall_data
    else:
        output[0] = b"\x00\x00\x00\x00\x00\x00\x00\x00"


script_dict = {}


def handler(ns, command, thread_count):
    global HeapSize
    
    reader = BinaryReader(ns)
    writer = BinaryWriter(ns)

    # print(str(thread_count) + ":" + str(CECMD(command).name))
    if command == CECMD.CMD_CREATETOOLHELP32SNAPSHOT:
        dwFlags = reader.ReadInt32()
        pid = reader.ReadInt32()
        hSnapshot = random.randint(1, 0x10000)
        writer.WriteInt32(hSnapshot)

    elif command == CECMD.CMD_CREATETOOLHELP32SNAPSHOTEX:
        dwFlags = reader.ReadInt32()
        pid = reader.ReadInt32()
        bytecode = b""
        if dwFlags & TH32CS_SNAPMODULE == TH32CS_SNAPMODULE:
            ret = module32first()
            while True:
                if ret != False:
                    modulename = ret[2].encode()
                    modulenamesize = len(modulename)
                    modulebase = ret[0]
                    modulepart = 0
                    modulesize = ret[1]
                    if parse(CEVERSION) >= parse("7.5.1"):
                        tmp = pack(
                            "<iQIIII" + str(modulenamesize) + "s",
                            1,
                            modulebase,
                            modulepart,
                            modulesize,
                            0,
                            modulenamesize,
                            modulename,
                        )
                    else:
                        tmp = pack(
                            "<iQIII" + str(modulenamesize) + "s",
                            1,
                            modulebase,
                            modulepart,
                            modulesize,
                            modulenamesize,
                            modulename,
                        )
                    bytecode = b"".join([bytecode, tmp])
                else:
                    break
                ret = module32next()
            if parse(CEVERSION) >= parse("7.5.1"):
                tmp = pack("<iQIIII", 0, 0, 0, 0, 0, 0)
            else:
                tmp = pack("<iQIII", 0, 0, 0, 0, 0)
            bytecode = b"".join([bytecode, tmp])
            ns.sendall(bytecode)
        elif dwFlags & TH32CS_SNAPTHREAD == TH32CS_SNAPTHREAD:
            writer.WriteInt32(1)
            writer.WriteInt32(1)
        else:
            hSnapshot = random.randint(1, 0x10000)
            writer.WriteInt32(hSnapshot)

    elif command == CECMD.CMD_PROCESS32FIRST or command == CECMD.CMD_PROCESS32NEXT:
        hSnapshot = reader.ReadInt32()
        print("hSnapshot:" + str(hSnapshot))
        if command == CECMD.CMD_PROCESS32FIRST:
            ret = 1
        else:
            ret = 0
        if ret != 0:
            processname = "webassembly".encode()
            processnamesize = len(processname)
            _pid = 1234
            bytecode = pack(
                "<iii" + str(processnamesize) + "s",
                ret,
                _pid,
                processnamesize,
                processname,
            )
            ns.sendall(bytecode)
        else:
            bytecode = pack("<iii", 0, 0, 0)
            ns.sendall(bytecode)

    elif command == CECMD.CMD_MODULE32FIRST or command == CECMD.CMD_MODULE32NEXT:
        hSnapshot = reader.ReadInt32()
        if command == CECMD.CMD_MODULE32FIRST:
            ret = module32first()
        else:
            ret = module32next()
        if ret != False:
            modulename = ret[2].encode()
            modulenamesize = len(modulename)
            modulebase = ret[0]
            modulepart = 0
            modulesize = ret[1]
            if parse(CEVERSION) >= parse("7.5.1"):
                bytecode = pack(
                    "<iQIIII" + str(modulenamesize) + "s",
                    1,
                    modulebase,
                    modulepart,
                    modulesize,
                    0,
                    modulenamesize,
                    modulename,
                )
            elif parse(CEVERSION) >= parse("7.3.1"):
                bytecode = pack(
                    "<iQIII" + str(modulenamesize) + "s",
                    1,
                    modulebase,
                    modulepart,
                    modulesize,
                    modulenamesize,
                    modulename,
                )
            else:
                bytecode = pack(
                    "<iQII" + str(modulenamesize) + "s",
                    1,
                    modulebase,
                    modulesize,
                    modulenamesize,
                    modulename,
                )
            ns.sendall(bytecode)
        else:
            if parse(CEVERSION) >= parse("7.3.1"):
                bytecode = pack("<iQIII", 0, 0, 0, 0, 0)
            else:
                bytecode = pack("<iQII", 0, 0, 0, 0)
            ns.sendall(bytecode)

    elif command == CECMD.CMD_CLOSEHANDLE:
        h = reader.ReadInt32()
        # CloseHandle(h)
        writer.WriteInt32(1)

    elif command == CECMD.CMD_OPENPROCESS:
        pid = reader.ReadInt32()
        processhandle = random.randint(0, 0x10000)
        print("Processhandle:" + str(processhandle))
        pHandle = processhandle
        writer.WriteInt32(processhandle)

    elif command == CECMD.CMD_GETARCHITECTURE:
        if parse(CEVERSION) >= parse("7.4.1"):
            handle = reader.ReadInt32()
        arch = 3
        writer.WriteInt8(arch)

    elif command == CECMD.CMD_SET_CONNECTION_NAME:
        size = reader.ReadInt32()
        ns.recv(size)

    elif command == CECMD.CMD_READPROCESSMEMORY:
        handle = reader.ReadUInt32()
        address = reader.ReadUInt64()
        size = reader.ReadUInt32()
        compress = reader.ReadInt8()

        SendMessageQueue.put(
            {"command": "read_memory", "address": address, "size": size}
        )
        ret = RecvMessageQueue.get()
        if compress == 0:
            if type(ret) == bytes:
                writer.WriteInt32(len(ret))
                ns.sendall(ret)
            else:
                writer.WriteInt32(0)
        else:
            if type(ret) == bytes:
                uncompressedSize = len(ret)
                compress_data = zlib.compress(ret, level=compress)
                writer.WriteInt32(uncompressedSize)
                writer.WriteInt32(len(compress_data))
                ns.sendall(compress_data)
            else:
                writer.WriteInt32(0)
                writer.WriteInt32(0)

    elif command == CECMD.CMD_WRITEPROCESSMEMORY:
        handle = reader.ReadUInt32()
        address = reader.ReadUInt64()
        size = reader.ReadUInt32()
        if size > 0:
            _buf = ns.recv(size)

            SendMessageQueue.put(
                {"command": "write_memory", "address": address, "bytes": _buf.hex()}
            )
            ret = RecvMessageQueue.get()
            if ret != False:
                writer.WriteInt32(size)
            else:
                writer.WriteInt32(0)
        else:
            writer.WriteInt32(0)

    elif command == CECMD.CMD_VIRTUALQUERYEXFULL:
        handle = reader.ReadInt32()
        flags = reader.ReadInt8()
        if HeapSize == 0:
            SendMessageQueue.put({"command": "get_heap_size"})
            HeapSize = RecvMessageQueue.get()
        regionSize = 1
        protection = ProtectionStringToProtection("rw")
        baseaddress = 0
        _type = MEM_PRIVATE
        size = HeapSize
        bytecode = pack("<QQII", baseaddress, size, protection, _type)
        writer.WriteInt32(regionSize)
        ns.sendall(bytecode)

    elif command == CECMD.CMD_VIRTUALQUERYEX:
        handle = reader.ReadInt32()
        baseaddress = reader.ReadUInt64()
        if HeapSize == 0:
            SendMessageQueue.put({"command": "get_heap_size"})
            HeapSize = RecvMessageQueue.get()
        if baseaddress >= HeapSize:
            _type = ProtectionStringToProtection("")
            protection = PAGE_NOACCESS
            size = 0
        else:
            baseaddress = 0
            _type = MEM_PRIVATE
            protection = ProtectionStringToProtection("rw")
            size = HeapSize
        bytecode = pack("<bIIQQ", 1, protection, _type, baseaddress, size)
        ns.sendall(bytecode)

    elif command == CECMD.CMD_GETREGIONINFO:
        handle = reader.ReadInt32()
        baseaddress = reader.ReadUInt64()
        if HeapSize == 0:
            SendMessageQueue.put({"command": "get_heap_size"})
            HeapSize = RecvMessageQueue.get()
        if baseaddress >= HeapSize:
            _type = ProtectionStringToProtection("")
            protection = PAGE_NOACCESS
            size = 0
        else:
            baseaddress = 0
            _type = MEM_PRIVATE
            protection = ProtectionStringToProtection("rw")
            size = HeapSize
        bytecode = pack("<bIIQQ", 1, protection, _type, baseaddress, size)
        ns.sendall(bytecode)
        filename = "HEAP"
        filenamesize = len(filename)
        writer.WriteUInt8(filenamesize)
        ns.sendall(filename.encode())

    elif command == CECMD.CMD_TERMINATESERVER:
        ns.close()
        return -1

    elif command == CECMD.CMD_GETVERSION:
        if parse(CEVERSION) >= parse("7.5.1"):
            version = 6
            versionstring = "CHEATENGINE Network 2.3".encode()
        elif parse(CEVERSION) >= parse("7.4.3"):
            version = 5
            versionstring = "CHEATENGINE Network 2.2".encode()
        elif parse(CEVERSION) >= parse("7.4.2"):
            version = 4
            versionstring = "CHEATENGINE Network 2.2".encode()
        elif parse(CEVERSION) >= parse("7.3.2"):
            version = 2
            versionstring = "CHEATENGINE Network 2.1".encode()
        else:
            version = 1
            versionstring = "CHEATENGINE Network 2.0".encode()
        versionsize = len(versionstring)
        bytecode = pack(
            "<ib" + str(versionsize) + "s", version, versionsize, versionstring
        )
        ns.sendall(bytecode)

    elif command == CECMD.CMD_GETSYMBOLLISTFROMFILE:
        if parse(CEVERSION) >= parse("7.5.1"):
            fileoffset = reader.ReadUInt32()
            symbolpathsize = reader.ReadUInt32()
            symbolname = ns.recv(symbolpathsize).decode()
            output = [0]
            GetSymbolListFromFile(symbolname, output)
        else:
            symbolpathsize = reader.ReadInt16()
            symbolname = ns.recv(symbolpathsize + 2).decode()
            output = [0]
            GetSymbolListFromFile(symbolname[2:], output)
        ns.sendall(output[0])

    elif command == CECMD.CMD_LOADEXTENSION:
        handle = reader.ReadInt32()
        writer.WriteInt32(1)

    elif command == CECMD.CMD_SPEEDHACK_SETSPEED:
        handle = reader.ReadInt32()
        data = ns.recv(4)
        speedratio = unpack("<f", data)[0]
        r = 0# API.ExtSetSpeed(speedratio)
        writer.WriteInt32(r)

    elif command == CECMD.CMD_ALLOC:
        handle = reader.ReadInt32()
        preferedBase = reader.ReadUInt64()
        size = reader.ReadInt32()
        address = 0# API.ExtAlloc(preferedBase, size)
        writer.WriteUInt64(address)

    elif command == CECMD.CMD_FREE:
        handle = reader.ReadInt32()
        address = reader.ReadUInt64()
        size = reader.ReadInt32()
        r = 0# API.ExtFree(address, size)
        writer.WriteInt32(r)

    elif command == CECMD.CMD_LOADMODULE:
        handle = reader.ReadInt32()
        modulepathlength = reader.ReadInt32()
        modulepath = ns.recv(modulepathlength).decode()
        if modulepath.find("libMonoDataCollector") != -1:
            writer.WriteUInt64(0x7FFFDEADBEAF)
        else:
            r = 0# API.ExtLoadModule(modulepath)
            writer.WriteUInt64(r)

    elif command == CECMD.CMD_CREATETHREAD:
        handle = reader.ReadInt32()
        startaddress = reader.ReadUInt64()
        parameter = reader.ReadUInt64()
        r = 0# API.ExtCreateThread(startaddress, parameter)
        threadhandle = random.randint(0, 0x10000)
        writer.WriteInt32(threadhandle)

    elif command == CECMD.CMD_GETABI:
        writer.WriteInt8(1)

    elif command == CECMD.CMD_STARTDEBUG:
        handle = reader.ReadInt32()
        writer.WriteInt32(0)

    elif command == CECMD.CMD_WAITFORDEBUGEVENT:
        handle = reader.ReadInt32()
        timeout = reader.ReadInt32()
        time.sleep(timeout / (1000 * 20))
        writer.WriteInt32(0)

    elif command == CECMD.CMD_CONTINUEFROMDEBUGEVENT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        ignore = reader.ReadInt32()
        writer.WriteInt32(1)

    elif command == CECMD.CMD_SETBREAKPOINT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        debugreg = reader.ReadInt32()
        address = reader.ReadUInt64()
        bptype = reader.ReadInt32()
        bpsize = reader.ReadInt32()
        writer.WriteInt32(0)

    elif command == CECMD.CMD_REMOVEBREAKPOINT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        debugreg = reader.ReadInt32()
        wasWatchpoint = reader.ReadInt32()
        writer.WriteInt32(0)

    elif command == CECMD.CMD_GETTHREADCONTEXT:
        handle = reader.ReadInt32()
        tid = reader.ReadInt32()
        if parse(CEVERSION) < parse("7.4.2"):
            _type = reader.ReadInt32()
        writer.WriteInt32(1)

    elif command == CECMD.CMD_SETTHREADCONTEXT:
        if parse(CEVERSION) >= parse("7.4.2"):
            handle = reader.ReadInt32()
            tid = reader.ReadInt32()
            structsize = reader.ReadInt32()
            context = ns.recv(structsize)
            writer.WriteInt32(0)
        else:
            print("SETTHREADCONTEXT not support.")

    elif command == CECMD.CMD_CHANGEMEMORYPROTECTION:
        handle = reader.ReadInt32()
        address = reader.ReadUInt64()
        size = reader.ReadInt32()
        windowsprotection = reader.ReadInt32()
        newprotectionstr = "---"
        if windowsprotection == PAGE_EXECUTE_READWRITE:
            newprotectionstr = "rwx"
        elif windowsprotection == PAGE_EXECUTE_READ:
            newprotectionstr = "r-x"
        elif windowsprotection == PAGE_EXECUTE:
            newprotectionstr = "--x"
        elif windowsprotection == PAGE_READWRITE:
            newprotectionstr = "rw-"
        elif windowsprotection == PAGE_READONLY:
            newprotectionstr = "r--"
        result = False# API.ExtChangeMemoryProtection(address, size, newprotectionstr)
        if result == True:
            ret = 1
        else:
            ret = 0
        writer.WriteInt32(ret)
        writer.WriteInt32(windowsprotection)

    elif command == CECMD.CMD_GETOPTIONS:
        writer.WriteInt16(0)

    elif command == CECMD.CMD_OPENNAMEDPIPE:
        pipename = reader.ReadString16()
        timeout = reader.ReadUInt32()
        pipehandle = random.randint(1, 0x10000)
        writer.WriteInt32(pipehandle)

    elif command == CECMD.CMD_PIPEREAD:
        pipehandle = reader.ReadUInt32()
        size = reader.ReadUInt32()
        timeout = reader.ReadUInt32()

        writer.WriteUInt32(len(ret))
        ns.sendall(ret)

    elif command == CECMD.CMD_PIPEWRITE:
        pipehandle = reader.ReadUInt32()
        size = reader.ReadUInt32()
        timeout = reader.ReadUInt32()
        buf = ns.recv(size)

        writer.WriteUInt32(size)

    elif command == CECMD.CMD_ISANDROID:
        writer.WriteInt8(1)

    elif command == CECMD.CMD_GETCESERVERPATH:
        path = b"/wasm"
        writer.WriteInt16(len(path))
        ns.sendall(path)
    else:
        pass
    # print("END")
    return 1


def main_thread(conn, thread_count):
    while True:
        try:
            b = conn.recv(1)
            if b == b"":
                conn.close()
                print("Peer has disconnected")
                break
            command = unpack("<b", b)[0]
            ret = handler(conn, command, thread_count)
        except:
            import traceback

            print("EXCEPTION:" + str(CECMD(command)))
            traceback.print_exc()
            conn.close()
            break
        if ret == -1:
            break


def ceserver():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        thread_count = 0
        s.bind(("127.0.0.1", PORT))
        s.listen(32)
        s.settimeout(1)
        while True:
            try:
                conn, addr = s.accept()
                print("accept", addr)

                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # conn.settimeout(5000)
                thread_count += 1
                thread = threading.Thread(
                    target=main_thread,
                    args=([conn, thread_count]),
                    daemon=True,
                )
                thread.start()
            except socket.timeout:
                continue


def websocket_server():
    async def echo(websocket, path):
        print("Starting the ceserver.")
        ceserver_thread = threading.Thread(target=ceserver, daemon=True)
        ceserver_thread.start()

        request_id = 0
        while True:
            request_id += 1
            message = await asyncio.to_thread(SendMessageQueue.get)
            message["id"] = request_id
            await websocket.send(json.dumps(message))
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            except asyncio.TimeoutError:
                print(f"Timeout waiting for response:Message => {message}")
                break
            # read_memory
            if type(message) == bytes:
                RecvMessageQueue.put(message)
                continue
            # other
            else:
                data = json.loads(message)
            if data["id"] == request_id:
                RecvMessageQueue.put(data["message"])
            else:
                print(f"Incorrect response for request {request_id}")

    async def main():
        start_server = websockets.serve(echo, "localhost", 8765)
        await start_server
        await asyncio.Future()

    print("Waiting for a WebSocket connection from JavaScript.")
    asyncio.run(main())


def init():
    global CEVERSION
    global PORT

    with open("config.toml") as f:
        config = toml.loads(f.read())

    CEVERSION = config["general"]["ceversion"]
    PORT = config["general"]["listen_port"]
    websocket_server()


init()
