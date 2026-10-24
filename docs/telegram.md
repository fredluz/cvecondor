# Telegram: urgent lines on the phone, and replies to them

For the agent in charge. Read `AGENTS.md` first; its rules apply here, above all: **a secret value never appears in the chat, in a command line, in a file in the checkout or in your output.** Follow this file when the user wants Telegram, from `agent/setup.md` step 4c or whenever they ask for it later.

What the user gets: each urgent line (something exploitable now, a workaround or stop under way) arrives as a Telegram message, and they can answer it there in plain text. The watcher hands each text they write to you (the agent in charge, run headless with the responder's `act` command) and sends your answer back.

The user does only what only they can do inside Telegram: create the bot, tap Start, send one test message. You do the rest.

## What the code does (so you promise nothing more)

- **Out:** a `telegram` notifier posts every notice it is subscribed to (`events`, default `urgent`) to its `chatId` with `sendMessage`. `cvecondor notify-test` sends a test line through every notifier.
- **In** (only with `"replies": true`; needs a `responder`, or the config does not load): the watcher long-polls `getUpdates` for `message` updates (`src/relay.rs`).
  - Only **text messages from the configured chat** are answered. Voice messages, photos, files, stickers, edits and anything from another chat get **no answer** (the watcher logs `relay: ignored an update from chat <id>`). Tell the user to type.
  - Each text goes to the agent with `AGENTS.md`, the last five urgent lines, and the message they replied to if they used Telegram's reply. Messages are handled one at a time; one run is allowed 15 minutes; the answer is cut to 1000 characters.
  - If the agent can't run (its quota, its login, a timeout), the bot says so in the chat, keeps the message (`relay-retries.json`) and answers it later, marked late.
  - Each exchange is kept in the inbox as `reply: <their text>`.
  - **The first batch the watcher ever reads from a bot is skipped**, never answered (it logs `relay: first read of this bot: skipped N earlier update(s)`). Only messages sent after that line are answered.
  - The bot has **one reader**. A second program polling it, or a webhook set on it, makes Telegram answer 409; the relay logs `this bot has another getUpdates reader or a webhook` and retries every 5 minutes.
- **Live replies need the daemon** (`cvecondor run`: systemd, launchd, the container). With cron or the GitHub Action, `cvecondor cycle` polls once at its end, so a message is answered when the next cycle runs, not at once. Say so if that is their setup.

## 1. Before you start

Settle these from `deployment.md` and `agent/setup.md` (steps 1 and 4b), and ask the user only for what you can't find:

- **Where the env file is** (`cvecondor.env` next to the config; on a server, over ssh) and **the command prefix** for `cvecondor`. Every command below that touches the env file runs where it is.
- **Is a responder configured?** Without one, Telegram works one way (urgent lines out), and you leave `replies` out. Say that in one line, and offer to set the responder up (step 4b) so replies can follow.
- **The chat should be a private chat with the bot.** In a group, every member's text would be handled as if the user wrote it. Use a group only if the user insists, and tell them that.

## 2. Create the bot (the user, in Telegram)

Say, in a line or two: *"CVECondor needs a bot of its own. A bot's messages can be read by only one program, and CVECondor reads this one to get your replies, so a bot you already use for something else would break both."* Then:

1. Open Telegram and search for **@BotFather** (the one with the blue check mark), open it, tap **Start**.
2. Send `/newbot`.
3. It asks for a **name**: anything shown in the chat, for example `CVECondor`.
4. It asks for a **username**: it must be unique, end in `bot`, and use letters, digits and underscores, for example `acme_cvecondor_bot`. If it says the name is taken, try another.
5. BotFather answers with a message containing the **token** (digits, a colon, then letters). Don't copy it anywhere yet; tell them what the next step does with it.

## 3. The token goes into the env file, never into the chat

Give them this command, with the path filled in (see "Getting a value into the env file without it showing" in `agent/setup.md` for the server form and the checks). It prompts without echoing, so the token appears nowhere:

```sh
bash -c 'umask 077; read -rs -p "TELEGRAM_BOT_TOKEN: " T; echo; printf "TELEGRAM_BOT_TOKEN=%s\n" "$T" >> ~/.config/cvecondor/cvecondor.env'
```

(They can instead paste `TELEGRAM_BOT_TOKEN=<token>` as a new line in that file with their editor; name the path.) Afterwards they clear the terminal (`clear`, or Cmd-K): the token is still on their screen from BotFather's message, and in that chat until they delete it.

Check it by name only: `cut -d= -f1 <env file>` must list `TELEGRAM_BOT_TOKEN` once. The env file stays outside the checkout, `chmod 600`, and out of any container's `environment` (`agent/setup.md` step 6).

If the user pasted the token into the chat anyway: write it to the env file without echoing it, then tell them the transcript now holds it, and that **@BotFather → `/revoke`** gives a new one (repeat this step with it).

### Talking to Telegram without the token showing

The token must not be on a command line (`ps` shows arguments) or in output. This helper reads it from the env file and hands curl its URL on stdin. Set `ENVFILE` to the env file's path:

```sh
ENVFILE=~/.config/cvecondor/cvecondor.env
tg() {  # tg <method>: prints Telegram's JSON answer
  T=$(grep '^TELEGRAM_BOT_TOKEN=' "$ENVFILE" | cut -d= -f2-)
  printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$T" "$1" | curl -sS --max-time 20 -K -
}
```

If the env file is on a server, run the whole snippet there, with the helper defined inside the same session: `ssh <host> bash -s <<'EOF'` … `EOF`. Never use `set -x`, and never print the helper's input.

**Prove the token works:** `tg getMe | jq '{ok, username: .result.username}'`.
- `ok: true`: keep the `username`; you need it next.
- `"ok": false` with `401`: Telegram doesn't know the token. A paste went wrong (empty, cut, extra characters). Remove the line without showing it (`agent/setup.md`, the `grep -v` form), and have them run the command again.

## 4. Find the chat id yourself

1. Ask the user to open `https://t.me/<username>` (give them the actual link, from `getMe`) or search for the bot's username, and tap **Start** once. A bot can't write to someone who hasn't written to it first. If they want a group, they add the bot to it and send a message there.
2. **Before the watcher reads replies from this bot** (so before step 5 starts it), list what the bot has received:
   ```sh
   tg getUpdates | jq -c '[.result[] | (.message // .my_chat_member // .channel_post | select(.) | .chat)] | unique_by(.id)[] | {id, type, title, first_name, username} | with_entries(select(.value != null))'
   ```
   Never add `offset` to this call: it would tell Telegram those updates are done, and the watcher's first read of the bot would then swallow the user's first real message. (Telegram keeps unconfirmed updates for 24 hours.) Don't run it while the watcher's relay is reading this bot; Telegram answers one of the two with a 409.
3. One chat: that is the id. A private chat's id is a positive number; a group's is negative. Several chats: ask which one, by the names and usernames shown, never by id alone.
4. Nothing came back (`result` is empty): they haven't tapped Start, or tapped it on another bot. Ask once more, with the link; look again. A `409` here means another program polls this bot or a webhook is set: it is not a bot for CVECondor. Create a new one (step 2). Don't delete a webhook someone else uses.

## 5. Wire it and test it

1. In `config.json` (references only; the token stays `${…}`), add or change the notifier. `chatId` is a string:
   ```jsonc
   { "type": "telegram", "botToken": "${TELEGRAM_BOT_TOKEN}", "chatId": "123456789", "replies": true }
   ```
   Leave `replies` out if there is no responder. Don't duplicate the bot: a second notifier with `replies` on the same token is rejected. Run `cvecondor status`: it loads the config and fails with a plain message if a field or the env var is wrong.
2. **Send a test line:** `cvecondor notify-test`. It goes through every notifier; look at the `sent:` line for `telegram`, and ask the user to confirm the line arrived in the bot's chat.
3. **Restart the watcher** the way `deployment.md` says (the daemon reads the config at start). In its log (`journalctl -u cvecondor -n 50`, `docker logs --tail 50 cvecondor`, or the launchd plist's log path) look for `relay: answering the user's Telegram messages`. If it is absent, either `replies` is off, the watcher wasn't restarted, or it runs from cron or the Action (see the end of "What the code does").
4. **Wait for the first read.** The Start tap from step 4 is still waiting at Telegram, so within seconds the log has `relay: first read of this bot: skipped N earlier update(s)`. Only messages sent after that line are answered. If the line doesn't show within a minute, there was nothing waiting: ask the user to send the bot `hi` (it will not be answered) and wait for the line. (A bot this watcher has read before has no such line: it answers whatever is waiting, the Start tap included.)
5. **Ask the user to reply** in the bot's chat with a short text, for example `are you there?` (it need not be a Telegram "reply" to the test line; if they do reply to it, the agent sees it). A headless agent run takes up to a minute or two.
6. **Confirm it arrived.** The answer shows up in the chat, and the exchange is in the inbox:
   ```sh
   cvecondor inbox --peek   # --peek leaves it unread for the user's next conversation
   ```
   An entry `[report] reply: are you there?` means the relay passed the message to the agent in charge and sent the answer. Ask the user whether they saw the answer in Telegram.

Then tell the user, in two lines: what arrives on Telegram (urgent lines only, everything else waits for you), and that they can answer in text there, **not by voice message: it gets no answer**.

Record in `deployment.md`: the notifier is Telegram, the bot's username (not the token), whether replies are on, and that the token is `TELEGRAM_BOT_TOKEN` in the env file (revoke: BotFather → `/revoke`).

## When something fails

Say what failed in plain words, and fix the cause; don't re-ask the user to repeat the whole flow.

| What happened | What it means, and what to do |
|---|---|
| `getMe` says `401` | Telegram doesn't know that token (pasted wrong). Remove the env line unseen, re-run the prompt (step 3). |
| `notify-test` says `telegram: HTTP 401` or `HTTP 404` | The token in the env file is wrong or revoked. Same fix. |
| `notify-test` says `telegram: HTTP 400` | Typically the chat id is wrong, or the user never tapped Start on this bot. Check both (step 4). |
| `notify-test` says `telegram: HTTP 403` | Typically the user blocked the bot, or removed it from the group. Ask them to unblock it and tap Start. |
| `notify-test` fails with a network error | The machine can't reach `api.telegram.org` (firewall, proxy). It is the watcher's machine that needs it. |
| The test line arrived; their text got no answer, and the log's `relay: first read…` line is *later* than their message | The message came before the first read, so it was skipped by design. Ask for one more. |
| No answer, and the log says `relay: ignored an update from chat <id>` | They wrote from a different chat than `chatId`, or sent a voice message, photo or file (those are never answered). Ask them to type in the bot's private chat, or fix `chatId` and restart. |
| The log says `relay: this bot has another getUpdates reader or a webhook` | Something else uses this bot (your own `getUpdates` from step 4, another program, a webhook). Stop it, or make a new bot for CVECondor and redo steps 2–4. |
| The bot answers `I can't answer right now (…)` | The relay works; the agent CLI behind the responder can't run (login, quota). The message is kept and answered later. Fix the responder (`agent/setup.md` step 4b; `cvecondor respond <key> --mode propose` shows whether it runs). |
| Nothing in the log at all | The notifier has no `replies: true`, or the watcher wasn't restarted, or it isn't the daemon (cron, the Action: answered at the end of the next cycle). `cvecondor status` and `deployment.md` tell which. |
