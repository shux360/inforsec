export function writeJsonLine(socket, message) {
  socket.write(`${JSON.stringify(message)}\n`);
}

export function createJsonLineParser(onMessage, onError) {
  let buffer = '';

  return (chunk) => {
    buffer += chunk.toString('utf8');
    let newlineIndex = buffer.indexOf('\n');

    while (newlineIndex !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      if (line) {
        try {
          onMessage(JSON.parse(line));
        } catch (error) {
          onError(error);
        }
      }

      newlineIndex = buffer.indexOf('\n');
    }
  };
}
