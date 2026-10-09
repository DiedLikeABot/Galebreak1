# GALEBREAK

A browser battle royale with building. Drop from the balloon bus, loot, build,
and outlast the storm on an island generated fresh every match.

Four modes: Battle Royale, Tournament, Zone Wars, Box Fight.

## Running it

    npm install
    npm start

Then open http://localhost:8080

The server also serves the game itself, so one address gives you both the
client and the multiplayer rooms.

## Deploying

    Build command:  npm install
    Start command:  node server.js

The server listens on `process.env.PORT`, so it works on Render, Railway,
Fly.io and Glitch without changes.

## Google sign in (optional)

Set an environment variable on the host:

    GOOGLE_CLIENT_ID=your-id.apps.googleusercontent.com

Then add your deployed address to Authorised JavaScript origins in the
Google Cloud console. Without it, username accounts still work.

## Files

    index.html     the whole game, self contained (three.js is bundled)
    server.js      rooms, matchmaking, accounts, chat and voice signalling
    package.json   one dependency: ws

## Build artefacts

    .codex         asset integrity manifest, generated at build time
