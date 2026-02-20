# Flag Command

## Information

- **Difficulty**: Easy
- **Category**: Web
- **Platform**: HackTheBox
- **Date**: 2025-10-28
- **Points**: 900

## Challenge Description

In the **Flag Command** challenge from HTB's **Cyber Apocalypse 2024** event, you wake up inside a whimsical forest and interact with a browser‑based terminal. At each step the game presents four directions to choose from and responds with comedic narratives. The objective is to find a way out of the enchanted maze and recover the flag.

## Reconnaissance

### Initial Analysis

After exploring the initial commands (e.g. `start`, `HEAD NORTH`), I inspected the network requests via the developer tools and found two key endpoints:

- **`GET /api/options`** – returns JSON containing all valid commands for each step plus a hidden **secret** array.
- **`POST /api/monitor`** – accepts the command input and returns the game’s response. When the flag is returned, the JSON message includes `HTB{...}`.

### Findings

- The game’s JavaScript code loads the options from `/api/options` and stores a `secret` array.
- The `secret` array contained one value: `Blip‑blop, in a pickle with a hiccup! Shmiggity‑shmack`.

## Exploitation

### Identifying the hidden command

By making a manual request to `/api/options` or examining the client‑side JavaScript, we can identify the secret command:

```bash
curl -s https://<challenge-url>/api/options | jq '.allPossibleCommands.secret'
```

The result shows the secret string:

```json
[
  "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"
]
```

### Extracting the flag

Submitting this secret string via the terminal UI or directly using a POST request to `/api/monitor` yields the flag:

```bash
curl -s -X POST "https://<challenge-url>/api/monitor" \
  -H "Content-Type: application/json" \
  -d '{"command":"Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}'
```

The response includes the flag in the `message` field. Typing the phrase into the terminal and pressing **Enter** achieves the same result.

### Flag

```
HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!_f6fbabffe2db660fffcf4fa66d276382}
```

## Lessons Learned

- Inspect client‑side JavaScript and network traffic to uncover hidden functionality in web challenges.
- Browser developer tools are invaluable for discovering hidden API endpoints and secret commands.
- Understanding the game logic can reveal shortcuts to the flag without brute‑forcing each step.

## Tools Used

- Browser developer tools (Network inspector, JavaScript console)
- `curl`/HTTP client
- Text editor for note‑taking

## References

- [CTFtime – Flag Command writeup](https://ctftime.org/writeup/38738)
- [HackTheBox Cyber Apocalypse 2024 Flag Command write‑ups](https://book.cryptocat.me/ctf-writeups/2024/htb-cyber-apocalypse/web/flag_command)
