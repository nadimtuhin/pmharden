/**
 * Lightweight terminal spinner — no dependencies, pure Node readline.
 * Works in TTY; silently no-ops in CI / piped output.
 */

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const DONE_ICON = "✔";
const FAIL_ICON = "✖";

export class Spinner {
  private frame = 0;
  private timer: ReturnType<typeof setInterval> | null = null;
  private text: string;
  private isTTY: boolean;

  constructor(text: string) {
    this.text = text;
    this.isTTY = process.stdout.isTTY === true;
  }

  start(): this {
    if (!this.isTTY) {
      process.stdout.write(`${this.text}\n`);
      return this;
    }
    this.render();
    this.timer = setInterval(() => this.render(), 80);
    return this;
  }

  update(text: string): this {
    this.text = text;
    return this;
  }

  succeed(text?: string): void {
    this.stop();
    const msg = text ?? this.text;
    if (this.isTTY) {
      process.stdout.write(`\r\x1b[K\x1b[32m${DONE_ICON}\x1b[0m ${msg}\n`);
    } else {
      process.stdout.write(`${DONE_ICON} ${msg}\n`);
    }
  }

  fail(text?: string): void {
    this.stop();
    const msg = text ?? this.text;
    if (this.isTTY) {
      process.stdout.write(`\r\x1b[K\x1b[31m${FAIL_ICON}\x1b[0m ${msg}\n`);
    } else {
      process.stdout.write(`${FAIL_ICON} ${msg}\n`);
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.isTTY) {
      process.stdout.write(`\r\x1b[K`);
    }
  }

  private render(): void {
    const icon = FRAMES[this.frame % FRAMES.length]!;
    process.stdout.write(`\r\x1b[K\x1b[36m${icon}\x1b[0m ${this.text}`);
    this.frame++;
  }
}
