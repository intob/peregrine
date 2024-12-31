function appendMessage(text, isSent) {
    const div = document.createElement("div");
    div.classList.add("message");
    div.classList.add(isSent ? "sent-message" : "received-message");
    const body = document.createElement("div");
    body.textContent = text;
    div.appendChild(body);
    document.body.appendChild(div);
    div.scrollIntoView();
}

const sock = new WebSocket("ws://localhost:3000/ws");

sock.onopen = () => {
    let n = 0;
    appendMessage("Connected to WebSocket", false);
    const interval = setInterval(() => {
        n++;
        if (sock.readyState === WebSocket.OPEN) {
            const message = "Hello server!";
            sock.send(message);
            appendMessage(`Sent: ${message}`, true);
        }
        if (n >= 10) {
            sock.close()
            appendMessage("Client closed connection", true);
            clearInterval(interval);
        }
    }, 1000);
};

sock.onmessage = (event) => {
    appendMessage(`Received: ${event.data}`, false);
};

sock.onclose = () => {
    appendMessage("Server closed connection", false);
};

sock.onerror = (error) => {
    appendMessage(`Error: ${error}`, false);
};