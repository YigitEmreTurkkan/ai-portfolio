fetch('http://127.0.0.1:8788/api/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ message: 'hi' })
})
.then(res => res.json().then(data => ({status: res.status, data})))
.then(console.log)
.catch(console.error);
