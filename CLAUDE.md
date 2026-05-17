# Supply-Chain-Guard - Claude-Notizen

Diese Datei wird automatisch in jede Claude-Code-Session geladen. Sie ist die einzige verlaessliche Stelle fuer projektweite Regeln - Memory-Eintraege werden nicht in jeder Session aktiv.

## Release-Prozess (verbindlich)

Jeder Release MUSS in dieser Reihenfolge laufen. Wenn `npm run build` fehlschlaegt weil `check:changelog` rot ist, NICHT bypassen - Eintrag nachtragen.

1. **README.md aktualisieren** - neuer `### vX.Y.Z (YYYY-MM-DD)` Block ganz oben unter `## Changelog`, mit Titel und Bullet-Liste. Stil: siehe vorherige Eintraege.
2. **SECURITY.md** - Supported-Versions-Tabelle pflegen (nur bei neuer Major/Minor).
3. **CONTRIBUTING.md** - nur wenn neue Module oder Dateien dazukommen.
4. **Version bumpen** in `package.json`, `src/cli.ts`, internen Konstanten in `src/reporter.ts` (Text-Header, SARIF, SBOM, HTML-Footer) - alle gleichzeitig.
5. **Tests anpassen**, die altes Output-Format pruefen.
6. **`npm run build`** muss gruen sein - laeuft jetzt `check:changelog` als `prebuild` und scheitert wenn die `package.json`-Version keinen README-Eintrag hat.
7. **`npm test`** muss gruen sein.
8. **Ein Commit** fuer alles (Code + Docs + Tests).
9. **`git tag vX.Y.Z`** NACH dem Commit.
10. **`git push origin main && git push origin vX.Y.Z`** - CI erzeugt das GitHub-Release.

## Harte Regeln

- **IOCs immer defangen.** Domains, Subdomains, URLs und IPs von Threats werden in Doku, README, Commits, PRs und Chat NIE roh geschrieben. Schema:
  - Domain: `example[.]com` statt `example.com`
  - URL-Schema: `hxxps://` / `hxxp://` statt `https://` / `http://`
  - IPv4: `1[.]2[.]3[.]4` statt `1.2.3.4`
  - E-Mail: `user[@]example[.]com`
  - SHA-256 / MD5 bleiben roh (nicht klickbar)
  - **Ausnahmen** (bleiben funktional): eigene Projekt-Links (`github.com/homeofe/...`, `blog.elvatis.com`, npmjs.com-Badges) und Code in `src/` (dort werden die Werte verglichen, nicht angezeigt)
  - **Grund:** sonst koennen externe Scanner / Crawler die roh dokumentierten IOCs als legitime Treffer einsammeln oder Klicks ausloesen
- **Tags niemals verschieben.** Fuer Fixes immer neue Patch-Version (z.B. 5.2.13 -> 5.2.14). Kein `git tag -f`, kein `git push --force` auf Tags.
- **Keine Em-Dashes** (`—`) in Doku oder Commits. Immer normaler Bindestrich (`-`) oder Doppelpunkt (`:`). Gilt auch fuer neue Changelog-Eintraege - aeltere Eintraege im README haben noch Em-Dashes, nicht perpetuieren.
- **Nie Hooks oder Signaturen bypassen** (`--no-verify`, `--no-gpg-sign`) ohne explizite Erlaubnis. Wenn `prebuild` rot ist, ist das die Aufgabe, nicht das Hindernis.

## Historische Drift (warum es diese Datei gibt)

Der README-Changelog ist zweimal hinter den Tags zurueckgeblieben:
- Commit `6d0e887` - Backfill fuer v5.2.5 bis v5.2.7
- Backfill fuer v5.2.9 bis v5.2.13

Konsequenz: `scripts/check-changelog.mjs` ist als `prebuild` verdrahtet. Verlass dich nicht auf Memory oder Checkliste allein - der Build muss gegen die Doku gaten.
