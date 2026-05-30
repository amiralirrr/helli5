const http = require('http');
const Gun = require('gun');

const port = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Helli5 Gun relay is running.');
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

Gun({ web: server, radisk: true, file: 'data' });

server.listen(port, () => console.log(`Gun relay listening on ${port}`));
