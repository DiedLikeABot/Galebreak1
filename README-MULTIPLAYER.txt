STORM ROYALE — MULTIPLAYER

What this adds:
- Real WebSocket multiplayer rooms
- Player names + room codes
- Other players appear in the 3D world
- Position/look/weapon synchronization
- Player-vs-player damage and eliminations
- Shot effects, hit markers, minimap player dots
- Basic build replication
- Bots remain available as local opponents

RUN IT:
1. Install Node.js 18+.
2. Put storm-royale-multiplayer.html, server.js, package.json in the same folder.
3. In Terminal, cd to that folder.
4. Run: npm install
5. Run: npm start
6. Open http://localhost:8080 in two browser windows/devices.
7. Enter the same room code and click CONNECT.
8. Click BOARD THE BUS.

FOR TWO COMPUTERS:
- Run the server on one computer.
- Find that computer's LAN IP (for example 192.168.1.25).
- On the other computer open http://192.168.1.25:8080
- Both players use the same room code.
- Make sure the server computer's firewall allows Node.js on port 8080.

INTERNET PLAY:
- The server must be hosted on a machine/cloud host reachable by both players.
- For HTTPS hosting, use WSS through your host/reverse proxy.
