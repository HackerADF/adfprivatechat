const socket = io();

const form = document.getElementById('chat-form');
const input = document.getElementById('message');
const chatBox = document.getElementById('chat-box');

form.addEventListener('submit', e => {
  e.preventDefault();
  const message = input.value.trim();
  if (message !== '') {
    socket.emit('chat message', message);
    input.value = '';
  }
});

socket.on('chat message', msg => {
  const msgElem = document.createElement('p');
  msgElem.textContent = msg;
  chatBox.appendChild(msgElem);
  chatBox.scrollTop = chatBox.scrollHeight;
});
