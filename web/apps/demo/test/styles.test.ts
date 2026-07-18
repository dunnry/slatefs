import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const styles = readFileSync(
  fileURLToPath(new URL("../src/styles.css", import.meta.url)),
  "utf8",
);

describe("demo responsive shell styles", () => {
  it("sizes every outer shell boundary to the viewport", () => {
    expect(styles).toMatch(/html,\s*body,\s*#app\s*{[^}]*width: 100%/s);
    expect(styles).toMatch(/\.app\s*{[^}]*width: 100%[^}]*min-width: 0/s);
    expect(styles).toMatch(
      /\.workspace\s*{[^}]*min-width: 0[^}]*max-width: 100%/s,
    );
    expect(styles).toMatch(/\.panel\s*{[^}]*width: 100%[^}]*min-width: 0/s);
  });

  it("gives shadow hosts and their toolbars shrinkable full-width boxes", () => {
    expect(styles).toMatch(
      /\.panel > slatefs-file-explorer,[\s\S]*?\.inspector > slatefs-file-properties\s*{[^}]*width: 100%[^}]*min-width: 0[^}]*max-width: 100%/,
    );
    expect(styles).toMatch(
      /\.panel > \*::part\(toolbar\),\s*\.workspace-head \*::part\(toolbar\)\s*{[^}]*width: 100%[^}]*flex-wrap: wrap/s,
    );
  });

  it("uses the full mobile viewport and keeps fixed UI in separate bands", () => {
    expect(styles).toMatch(/@media \(max-width: 620px\)/);
    expect(styles).toContain(
      "grid-template-columns: repeat(5, minmax(0, 1fr));",
    );
    expect(styles).toMatch(
      /@media \(max-width: 620px\) \{[\s\S]*?\.rail\s*{[^}]*left: 0;[^}]*right: 0;[^}]*width: 100%;[^}]*max-width: 100%/,
    );
    expect(styles).toMatch(
      /right: 0\.5rem;\s*bottom: 4\.7rem;\s*left: 0\.5rem;\s*width: auto;[\s\S]*?100dvh - 10\.2rem/,
    );
  });
});
