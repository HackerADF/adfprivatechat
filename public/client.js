const socket = io();
const params = new URLSearchParams(window.location.search);
const username = params.get("username") || "Guest";

const form = document.getElementById('form');
const input = document.getElementById('input');
const messages = document.getElementById('messages');

// Handle form submission
form.addEventListener('submit', function(e) {
  e.preventDefault();
  if (input.value) {
    const timestamp = new Date().toLocaleTimeString(); // Get current timestamp
    socket.emit('chat message', { username: username, message: input.value, timestamp: timestamp });
    input.value = ''; // Clear input field after sending
  }
});

// Listen for chat messages and display them with username and timestamp
socket.on('chat message', function(data) {
  const item = document.createElement('li');
  
  // Correctly extract and display username, timestamp, and message
  const messageContent = `${data.username} (${data.timestamp}): ${data.message}`;
  item.textContent = messageContent;  // Use data.message instead of the entire data object

  messages.appendChild(item);
  window.scrollTo(0, document.body.scrollHeight); // Scroll to bottom
});
