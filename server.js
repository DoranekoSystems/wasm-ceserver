function hexStringToBytes(hexString) {
  var bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return bytes;
}

function overwriteHeapBuffer(byteData, offset) {
  var heap8 = new Uint8Array(window.HEAP8.buffer);
  var sourceArray =
    byteData instanceof Uint8Array ? byteData : new Uint8Array(byteData);
  heap8.set(sourceArray, offset);
}

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

function main() {
  var ws = new WebSocket("ws://localhost:8765");

  ws.onopen = function () {
    console.log("Connected to the WebSocket server");
  };

  ws.onmessage = function (event) {
    // console.log("Received message: " + event.data);
    var data = JSON.parse(event.data);
    if (data.command == "get_heap_size") {
      ws.send(
        JSON.stringify({
          id: data.id,
          message: window.HEAP8.length,
        })
      );
    } else if (data.command == "read_memory") {
      var originalBuffer = window.HEAP8.buffer;

      if (data.address + data.size <= originalBuffer.byteLength) {
        var slicedBuffer = originalBuffer.slice(
          data.address,
          data.address + data.size
        );
        ws.send(slicedBuffer);
      } else {
        ws.send(
          JSON.stringify({
            id: data.id,
            message: false,
          })
        );
      }
    } else if (data.command == "write_memory") {
      var byteData = hexStringToBytes(data.bytes);
      overwriteHeapBuffer(byteData, data.address);
      ws.send(
        JSON.stringify({
          id: data.id,
          message: true,
        })
      );
    }
  };

  ws.onerror = function (event) {
    console.error("WebSocket error observed:", event);
  };
}

main();
