"""Render docs/guard.gif: clawd-guard through one turn.

Claude is asked to ship a fix. It tries to force-push to main and is refused,
pushes its branch instead, is refused a write to .env, then asks before a
`git reset --hard` over uncommitted work, which the person declines. Each
catch raises a toast and updates the band above the prompt, as the hooks in
hooks/register.tsx draw them: the same reasons (hooks/rules.ts), counters and
Dismiss button. Needs Pillow, the DejaVu fonts and Noto Color Emoji (paths
below are Debian/Ubuntu).

    python3 docs/guard_gif.py docs/guard.gif
"""
import sys
from PIL import Image, ImageDraw, ImageFont

OUT = sys.argv[1]
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
EMOJI = "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf"
SIZE = 22

BG = (30, 30, 34)
TEXT = (220, 220, 220)
DIM = (120, 120, 128)
BORDER = (90, 90, 98)
YELLOW = (229, 192, 123)
GREEN = (120, 200, 120)
RED = (224, 108, 117)
BLUE = (97, 175, 239)
ACCENT = (215, 119, 87)

mono = ImageFont.truetype(MONO, SIZE)
bold = ImageFont.truetype(MONO.replace("SansMono.ttf", "SansMono-Bold.ttf"), SIZE)
asc, desc = mono.getmetrics()
CW = round(mono.getlength("M"))
CH = asc + desc

COLS = 92             # a 92-column terminal
CANVAS = 19           # rows on screen
PAD = 18
SHIELD = "🛡"          # drawn from the emoji font, two cells wide


def shield_image():
    font = ImageFont.truetype(EMOJI, 109)   # the one size the bitmap font has
    img = Image.new("RGBA", (136, 128), (0, 0, 0, 0))
    ImageDraw.Draw(img).text((0, 0), "\U0001F6E1", font=font, embedded_color=True)
    img = img.crop(img.getbbox())
    side = CH - 4
    return img.resize((round(img.width * side / img.height), side), Image.LANCZOS)


SHIELD_IMG = shield_image()

# Box-drawing glyphs drawn as lines across the whole cell, as a terminal joins
# them: the font's own stop short of the line height and leave gaps.
LINES = {"⎿": "ne", "│": "ns", "─": "we", "├": "nse", "└": "ne", "╭": "se", "╮": "sw", "╰": "ne", "╯": "nw"}


def box(draw, ch, x, top, colour):
    mx, my = x + CW // 2, top + CH // 2
    ends = {"n": (mx, top), "s": (mx, top + CH - 1), "w": (x, my), "e": (x + CW - 1, my)}
    for side in LINES[ch]:
        (x0, y0), (x1, y1) = sorted([ends[side], (mx, my)])
        draw.rectangle([x0, y0, x1 + 1, y1 + 1], fill=colour)


def width(line):
    return sum(2 if t == SHIELD else len(t) for t, _, _ in line)


def render(rows):
    img = Image.new("RGB", (COLS * CW + 2 * PAD, CANVAS * CH + 2 * PAD), BG)
    draw = ImageDraw.Draw(img)
    for r, line in enumerate(rows):
        col = 0
        for text, colour, is_bold in line:
            top = PAD + r * CH
            if text == SHIELD:
                img.paste(SHIELD_IMG, (PAD + col * CW + 1, top + 2), SHIELD_IMG)
                col += 2
                continue
            for ch in text:
                x = PAD + col * CW
                if ch in LINES:
                    box(draw, ch, x, top, colour or TEXT)
                elif ch != " ":
                    draw.text((x, top + asc), ch, font=bold if is_bold else mono, fill=colour or TEXT, anchor="ls")
                col += 1
    return img


def cut(text, room):
    return text if len(text) <= room else text[: room - 1] + "…"


# ---------- what is on screen ----------

state = dict(
    transcript=[],        # rows of runs
    prompt="",
    working=False,
    denied=0, asked=0, last=None, band=True,
    toast=None,           # (text, colour)
    dialog=None,          # (command, reason, choice)
)


def band_row():
    """The AbovePrompt band, as register.tsx draws it."""
    last = state["last"]
    if last is None or not state["band"]:
        return None
    action, summary = last
    room = max(20, COLS - 44)
    return [(SHIELD, None, False), (" ", TEXT, False), (str(state["denied"]), TEXT, True),
            (" blocked · ", DIM, False), (str(state["asked"]), TEXT, True), (" asked · ", DIM, False),
            (cut(summary, room) + " ", RED if action == "deny" else YELLOW, False), ("[ Dismiss ]", TEXT, False)]


def footer():
    rule = [("─" * COLS, BORDER, False)]
    if state["dialog"] is not None:
        command, reason, choice = state["dialog"]
        inner = COLS - 4
        edge = lambda runs: [("│ ", BORDER, False)] + runs + [(" " * (inner - width(runs)), TEXT, False), (" │", BORDER, False)]
        opts = []
        for i, label in enumerate(["Yes", "No, and tell Claude what to do differently"]):
            on = i == choice
            opts.append(edge([("❯ " if on else "  ", ACCENT, False), (f"{i + 1}. {label}", ACCENT if on else TEXT, on)]))
        return [
            [("╭" + "─" * (COLS - 2) + "╮", ACCENT, False)],
            edge([("Bash command", ACCENT, True)]),
            edge([("  " + command, TEXT, False)]),
            edge([("  " + cut(reason, inner - 2), YELLOW, False)]),
            edge([("Do you want to proceed?", TEXT, False)]),
            *opts,
            [("╰" + "─" * (COLS - 2) + "╯", ACCENT, False)],
        ]
    hint = "esc to interrupt" if state["working"] else "? for shortcuts"
    hint_row = [("  " + hint, DIM, False)]
    if state["toast"] is not None:
        text, colour = state["toast"]
        runs = [(SHIELD, None, False), (" " + text, colour, False)]
        gap = COLS - width(hint_row) - width(runs)
        hint_row += [(" " * gap, TEXT, False)] + runs
    rows = []
    band = band_row()
    if band is not None:
        rows.append(band)
    rows += [rule, [("> ", TEXT, False), (state["prompt"], TEXT, False)], rule, hint_row]
    return rows


frames, durations = [], []


def add(ms):
    bottom = footer()
    top = state["transcript"][-(CANVAS - len(bottom) - 1):]
    rows = top + [[]] * (CANVAS - len(bottom) - len(top)) + bottom
    frames.append(render(rows))
    durations.append(ms)


def say(*rows):
    for row in rows:
        state["transcript"].append(row)


def tool(name, arg):
    return [("● ", GREEN, False), (name, TEXT, True), (f"({arg})", TEXT, False)]


def result(text, colour=DIM):
    return [("  ⎿  ", DIM, False), (text, colour, False)]


def claude(text):
    return [("● ", TEXT, False), (text, TEXT, False)]


def catch(action, reason, rule):
    """A call refused or put to the person: count it, raise the toast and the band."""
    state["denied" if action == "deny" else "asked"] += 1
    state["last"] = (action, reason)
    state["band"] = True
    state["toast"] = ("Blocked: " if action == "deny" else "Needs approval: ") + reason, RED if action == "deny" else YELLOW


# ---------- the turn ----------

PROMPT = "ship the login fix to main and tidy up the repo"
add(900)
for i in range(0, len(PROMPT) + 1, 3):
    state["prompt"] = PROMPT[:i]
    add(70)
state["prompt"] = PROMPT
add(600)

say([("> ", DIM, False), (PROMPT, DIM, False)], [])
state["prompt"], state["working"] = "", True
add(700)

say(tool("Bash", "git push --force origin main"))
add(900)
reason = "force-push to protected branch main"
say(result(f"Error: clawd-guard: {reason} [git-force-push-protected]", RED), [])
catch("deny", reason, "git-force-push-protected")
add(2600)

say(claude("main is protected, so I'll push the branch and open a PR instead."), [])
state["toast"] = None
add(1400)
say(tool("Bash", "git push -u origin fix/login"))
add(800)
say(result("branch 'fix/login' set up to track 'origin/fix/login'."), [])
add(1200)

say(tool("Write", ".env"))
add(900)
reason = ".env is a protected file (.env)"
say(result(f"Error: clawd-guard: {reason} [protected-file]", RED), [])
catch("deny", reason, "protected-file")
add(2600)

state["toast"] = None
say(claude("I'll leave .env to you. Now resetting the stray changes."), [])
add(1200)
say(tool("Bash", "git reset --hard"))
reason = "git reset --hard discards work and there are uncommitted changes"
catch("ask", reason, "git-discard-dirty")
state["toast"] = None
state["dialog"] = ("git reset --hard", f"clawd-guard: {reason} [git-discard-dirty]", 0)
add(2200)
state["dialog"] = state["dialog"][:2] + (1,)
add(1400)
state["dialog"] = None
say(result("User declined: keep the uncommitted changes", YELLOW), [])
add(1000)

say(claude("Pushed fix/login and kept your uncommitted work. .env is unchanged."))
state["working"] = False
add(4000)

# Each frame to its own palette with no dithering: dithered grey turns the
# frame's lines into dashes.
frames = [f.quantize(colors=128, dither=Image.Dither.NONE) for f in frames]
frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0,
               optimize=True, disposal=1)
print(OUT, frames[0].size, len(frames), "frames", sum(durations) / 1000, "s")
