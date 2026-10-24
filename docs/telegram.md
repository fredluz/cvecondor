# Telegram: urgent lines on the phone, and replies to them

For the agent in charge. Read `AGENTS.md` first; its rules apply here, above all: **a secret value never appears in the chat, in a command line, in a file in the checkout or in your output.** Follow this file when the user wants Telegram, from `agent/setup.md` step 4c or whenever they ask for it later.

What the user gets: each urgent line (something exploitable now, a workaround or stop under way) arrives as a Telegram message, and they can answer it there in text. The watcher hands each text they write to you (the agent in charge, run headless with the responder's `act` command) and sends your answer back.

The user does only what only they can do inside Telegram: create the bot, tap Start, send one test message. You do the rest, with `cvecondor telegram-chat`, `status` and `notify-test telegram`.

## What the code does (so you promise nothing more)

- **Out:** a `telegram` notifier posts every notice it is subscribed to (`events`, default `urgent`) to its `chatId`.
- **In** (only with `"replies": true`; needs a `responder`, or the config does not load): the watcher long-polls the bot (`src/relay.rs`).
  - Only **text messages from the configured chat** are answered. Voice messages, photos, files, stickers, edits and anything from another chat get **no answer**; voice replies are planned ([issue #2](https://github.com/fredluz/cvecondor/issues/2)). Tell the user to type.
  - Each text goes to the agent with `AGENTS.md`, the last five urgent lines, and the message they replied to if they used Telegram's reply. Messages are handled one at a time; one run is allowed 15 minutes; the answer is cut to 1000 characters.
  - If the agent can't run (its quota, its login, a timeout), the bot says so in the chat, keeps the message and answers it later, marked late.
  - Each exchange is kept in the inbox as `reply: <their text>`.
  - The relay's **first read** of a bot catches up at once and ignores whatever was sent before it (`relay: first read of this bot: skipped N earlier update(s)`); only messages sent after it are answered. It is recorded even when nothing was waiting, so a real first message is never lost. `status` shows when the relay is reading.
  - The bot has **one reader**. A second program polling it, or a webhook, makes Telegram answer 409 (`status` shows `FAILING: this bot has another getUpdates reader`). `cvecondor telegram-chat` copes with it: it reads the chats the relay has seen instead.
- **Live replies need the daemon** (`cvecondor run`: systemd, launchd, the container). With cron or the GitHub Action, `cvecondor cycle` polls once at its end, so a message is answered when the next cycle runs, not at once. Say so if that is their setup.

## 1. Before you start

Settle these from `deployment.md` and `agent/setup.md` (steps 1 and 4b), and ask the user only for what you can't find:

- **Where the env file is** (`cvecondor.env` next to the config; on a server, over ssh) and **the command prefix** for `cvecondor`. Run every `cvecondor` command below with it, where the env file is.
- **Is a responder configured?** Without one, Telegram works one way (urgent lines out), and you leave `--replies` out. Say that in one line, and offer to set the responder up (step 4b) so replies can follow.
- **The chat should be a private chat with the bot.** In a group, every member's text would be handled as if the user wrote it. Use a group only if the user insists, and tell them that.

## 2. Create the bot (the user, in Telegram)

Say, in a line or two: *"CVECondor needs a bot of its own. A bot's messages can be read by only one program, and CVECondor reads this one to get your replies, so a bot you already use for something else would break both."* Then:

1. Open Telegram and search for **@BotFather** (the one with the blue check mark), open it, tap **Start**.
2. Send `/newbot`.
3. It asks for a **name**: anything shown in the chat, for example `CVECondor`.
4. It asks for a **username**: it must be unique, end in `bot`, and use letters, digits and underscores, for example `acme_cvecondor_bot`. If it says the name is taken, try another.
5. BotFather answers with a message containing the **token** (digits, a colon, then letters). Tell them what the next step does with it.

## 3. The token goes into the env file, never into the chat

Give them this command, with the path filled in (see "Getting a value into the env file without it showing" in `agent/setup.md` for the server form and the checks). It prompts without echoing, so the token appears nowhere:

```sh
bash -c 'umask 077; read -rs -p "TELEGRAM_BOT_TOKEN: " T; echo; printf "TELEGRAM_BOT_TOKEN=%s\n" "$T" >> ~/.config/cvecondor/cvecondor.env'
```

(They can instead paste `TELEGRAM_BOT_TOKEN=<token>` as a new line in that file with their editor; name the path.) Afterwards they clear the terminal (`clear`, or Cmd-K): the token is still on their screen from BotFather's message, and in that chat until they delete it.

Check it by name only: `cut -d= -f1 <env file>` must list `TELEGRAM_BOT_TOKEN` once. The env file stays outside the checkout, `chmod 600`, and out of any container's `environment` (`agent/setup.md` step 6).

If the user pasted the token into the chat anyway: write it to the env file without echoing it, then tell them the transcript now holds it, and that **@BotFather → `/revoke`** gives a new one (repeat this step with it).

## 4. Find the chat (you)

```sh
cvecondor telegram-chat --wait 120
```

It reads the token from the env file (default variable `TELEGRAM_BOT_TOKEN`; `--env NAME` for another), checks it with Telegram, and prints the bot's name and its link, `https://t.me/<username>`. Tell the user to open that link and tap **Start** (a bot can't write to someone who hasn't written to it first; for a group, add the bot to it and send a message there). `--wait 120` waits up to two minutes for that, so one command covers it; without `--wait` it reports what is there now.

It then lists the chats that wrote to the bot, with ids, names and kinds:

```
Bot: @acme_cvecondor_bot (https://t.me/acme_cvecondor_bot)
Chats that wrote to it:
  123456789  private: Ana Silva @ana
```

It never confirms an update, so it is safe to run at any time, including while the watcher is running: if the watcher's relay already holds the bot, it says so and lists the chats the relay has seen.

- One chat: that is it. Several: ask the user which one, by the names shown, never by id.
- A plain-words error means one of: Telegram doesn't know the token (`HTTP 401`: a paste went wrong or it was revoked; remove the line without showing it, `grep -v '^TELEGRAM_BOT_TOKEN=' <env file>` into a new file as in `agent/setup.md`, and re-run step 3), a webhook is set on the bot (it isn't a bot for CVECondor: make a new one), or nobody has tapped Start yet (run it again).

## 5. Wire it and test it

1. **Write the chat into the config:**
   ```sh
   cvecondor telegram-chat --use only --replies      # --use <id> when several chats wrote; leave --replies out without a responder
   ```
   It sets `chatId` on the Telegram notifier that reads `${TELEGRAM_BOT_TOKEN}`, or adds that notifier, keeping the config's comments and layout, and `replies: true` with `--replies`. It refuses, and writes nothing, if the result wouldn't load (replies without a responder, say). The notifier it writes:
   ```jsonc
   { "type": "telegram", "botToken": "${TELEGRAM_BOT_TOKEN}", "chatId": "123456789", "replies": true }
   ```
2. **Restart the watcher** the way `deployment.md` says (the daemon reads the config at start).
3. **Check it with `cvecondor status`.** The notifier lines show each notifier by number, its events, and for Telegram whether replies are on and being read:
   ```
   Notifiers:
     1. telegram (urgent) to chat 123456789; replies on, reading (last poll 12 s ago)
   ```
   `reading` is what you wait for (a few seconds after the restart). `NOT reading` with no poll recorded means the watcher wasn't restarted, or it runs from cron or the Action (answers come at the end of each cycle). `FAILING: …` carries the reason, in the table below.
4. **Send a test line:** `cvecondor notify-test telegram` (a number from `status` works too). Look at the `sent:` line, and ask the user to confirm the line arrived in the bot's chat.
5. **Ask the user to reply** in the bot's chat with a short text, for example `are you there?` (any text; it needn't be a Telegram "reply" to the test line, though if it is, the agent sees what it replied to). A headless agent run takes up to a minute or two. Send it after `status` says `reading`: anything sent before the relay's first read is ignored.
6. **Confirm it arrived.** The answer shows up in the chat, and the exchange is in the inbox:
   ```sh
   cvecondor inbox --peek   # --peek leaves it unread for the user's next conversation
   ```
   An entry `[report] reply: are you there?` means the relay passed the message to the agent in charge and sent the answer. Ask the user whether they saw the answer in Telegram.

Then tell the user, in two lines: what arrives on Telegram (urgent lines only, everything else waits for you), and that they can answer in text there, **not by voice message: it gets no answer yet** ([issue #2](https://github.com/fredluz/cvecondor/issues/2)).

Record in `deployment.md`: the notifier is Telegram, the bot's username (not the token), whether replies are on, and that the token is `TELEGRAM_BOT_TOKEN` in the env file (revoke: BotFather → `/revoke`).

## When something fails

Say what failed in plain words, and fix the cause; don't re-ask the user to repeat the whole flow.

| What happened | What it means, and what to do |
|---|---|
| `telegram-chat` says Telegram does not know the token | The token in the env file is wrong or revoked (HTTP 401). Remove the line unseen, re-run step 3. |
| `telegram-chat` says `TELEGRAM_BOT_TOKEN is not set` | The env file next to the config doesn't have it yet (step 3), or it is under another name: pass `--env NAME`. |
| `telegram-chat` says nobody has written to the bot | The user hasn't tapped Start on this bot. Give them the link it printed; run it again with `--wait 120`. |
| `telegram-chat` says a webhook is set | Something else uses this bot. Make a new bot for CVECondor (step 2) and redo step 3 with it. |
| `notify-test telegram` says `telegram: HTTP 401` or `HTTP 404` | The token in the env file is wrong or revoked. Same fix as the first row. |
| `notify-test telegram` says `telegram: HTTP 400` | Typically the chat id is wrong, or the user never tapped Start on this bot. Re-run step 4 and `--use`. |
| `notify-test telegram` says `telegram: HTTP 403` | Typically the user blocked the bot, or removed it from the group. Ask them to unblock it and tap Start. |
| `notify-test telegram` fails with a network error | The machine can't reach `api.telegram.org` (firewall, proxy). The watcher's machine needs it. |
| `status` says `replies off` | The notifier has no `replies: true`. `cvecondor telegram-chat --use <id> --replies`, then restart. |
| `status` says `NOT reading` | The watcher isn't running, wasn't restarted after the config change, or runs from cron or the Action (answers come at the end of each cycle). Check `deployment.md`. |
| `status` says `FAILING: this bot has another getUpdates reader or a webhook` | Something else uses this bot (another program, a webhook). Stop it, or make a new bot for CVECondor and redo steps 2–5. |
| `status` says `FAILING: getUpdates: HTTP 401` | The token was revoked after setup. Step 3 with a fresh token, restart. |
| The user wrote, got no answer, and `status` says `reading` | They wrote from a different chat than `chatId` (`cvecondor telegram-chat` lists the chats that wrote, and `--use` switches), or sent a voice message, photo or file (never answered), or wrote before the relay's first read. Ask them to type in the bot's private chat once more. |
| The bot answers `I can't answer right now (…)` | The relay works; the agent CLI behind the responder can't run (login, quota). The message is kept and answered later. Fix the responder (`agent/setup.md` step 4b; `cvecondor respond <key> --mode propose` shows whether it runs). |
