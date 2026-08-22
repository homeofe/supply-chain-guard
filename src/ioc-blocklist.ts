/**
 * Known Indicators of Compromise (IOC) blocklist.
 *
 * Contains known malicious domains, IPs, hashes, GitHub accounts,
 * and compromised package versions. Updated as new threats emerge.
 */

// ---------------------------------------------------------------------------
// Known malicious C2 domains
// ---------------------------------------------------------------------------

export const KNOWN_C2_DOMAINS: string[] = [
  // Vidar stealer C2 (Claude Code leak campaign, April 2026)
  "rti.cargomanbd.com",

  // GlassWorm C2 domains
  "connect.*.workers.dev",

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  "audit.checkmarx.cx",
  "checkmarx.cx",

  // CanisterSprawl npm worm / TeamPCP Update 008 (April 2026)
  "whereisitat.lucyatemysuperbox.space",

  // MacSync Stealer / malicious Homebrew ad (May 2026)
  "glowmedaesthetics.com",

  // DAEMON Tools QUIC RAT supply-chain attack (May 2026)
  "env-check.daemontools.cc",

  // Beagle backdoor / fake Claude AI website (May 2026)
  "claude-pro.com",
  "license.claude-pro.com",

  // TCLBANKER Brazilian banking trojan via trojanized Logitech AI Prompt Builder (May 2026)
  "campagna1-api.ef971a42.workers.dev",
  "documents.ef971a42.workers.dev",
  "mxtestacionamentos.com",

  // JDownloader site compromise / Python RAT installers (May 2026)
  "parkspringshotel.com",
  "auraguest.lk",
  "checkinnhotels.com",

  // Fake OpenAI Privacy Filter on Hugging Face / sefirah infostealer (May 2026)
  "recargapopular.com",

  // MacSync Stealer Claude.ai/Google ads variant (May 2026)
  "customroofingcontractors.com",
  "bernasibutuwqu2.com",
  "briskinternet.com",

  // Mini Shai-Hulud Worm / TeamPCP - TanStack/UiPath/Mistral/OpenSearch/Guardrails compromise (May 2026)
  "filev2.getsession.org",
  "seed1.getsession.org",
  "api.masscan.cloud",
  "git-tanstack.com",

  // node-ipc credential stealer via maintainer email hijack (May 2026)
  "sh.azurestaticprovider.net",

  // Phantom Bot DDoS + Shai-Hulud clone npm infostealer (deadcode09284814, May 2026)
  // Leaked Shai-Hulud source code re-weaponized for Golang DDoS + credential theft
  "87e0bbc636999b.lhr.life",
  "edcf8b03c84634.lhr.life",

  // Mini Shai-Hulud @antv wave + actions-cool tag hijack + Nx Console (May 2026)
  // Shared C2 domain across all three concurrent TeamPCP supply-chain attacks
  // (637 @antv versions, actions-cool/issues-helper + maintain-one-comment, nrwl.angular-console 18.95.0)
  "t.m-kosche.com",

  // Laravel-Lang DebugElevator PHP credential stealer (May 23, 2026)
  // 4 Composer packages hijacked via abused GitHub version tags, ~700 historical
  // versions republished with src/helpers.php containing ~5,900-line PHP stealer.
  // Exfiltrates to /exfil endpoint; PDB references developer "Mero" and "claude".
  "flipboxstudio.info",

  // TrapDoor cross-ecosystem credential stealer (npm/PyPI/Crates.io, May 25, 2026)
  // 34+ malicious packages across three registries by single actor ddjidd564
  // targeting AI / DeFi / Web3 developers. GitHub Pages dead-drop C2.
  "ddjidd564.github.io",

  // Polymarket impersonation npm publisher polymarketdev (May 22, 2026)
  // 9 npm packages typosquatting Polymarket SDK; wallet-key exfiltration via
  // Cloudflare Worker. Surfaced alongside Megalodon GitHub Actions campaign.
  "polymarketbot.polymarketdev.workers.dev",

  // ACR Stealer fake Claude page / Google Search malvertising (SANS ISC diary 33018, May 26, 2026)
  // Claude-impersonation pages pushed via Google Search ads serve a corrupted zip that
  // fetches a PowerShell script leading to ACR Stealer. Base domains stored (attacker-
  // controlled; subdomains rotate). i.ibb.co (legit ImgBB image host abused to stage
  // init-block.jpg) is intentionally NOT listed to avoid mass false positives.
  "fairpoint29.com",
  "primemetricsa.com",
  "creativecommunityinfo.art",
  "enhanceblabber.cc",

  // codexui-android npm token stealer (Aikido, disclosed May 27, 2026; THN June 1, 2026)
  // Legitimate-looking Codex remote-UI npm package (~27K-29K weekly downloads since
  // 0.1.82). Reads the user's OpenAI Codex auth file, XOR-encrypts with key
  // "anyclaw2026", base64-encodes and POSTs to /startlog on the C2. Same endpoint is
  // hit by the bundled Android apps "OpenClaw Codex Claude AI Agent" and "Codex"
  // running the package in a PRoot sandbox. Package still live at publish time.
  "sentry.anyclaw.store",

  // LiteLLM PyPI supply-chain compromise (March 24, 2026; re-disclosed Trail of Bits May 22, 2026)
  // TeamPCP-claimed compromise of litellm 1.82.7 / 1.82.8 dropped a litellm_init.pth
  // that auto-runs on every Python startup. Three-stage payload: 50+ category cred
  // harvester (RSA-4096 + AES-256 hybrid encryption) exfil to models.litellm.cloud,
  // Kubernetes lateral-movement toolkit, persistent backdoor polling checkmarx.zone
  // (Checkmarx-brand abuse to bypass DNS allowlists) every 50 minutes for second
  // stages. Origin: poisoned Trivy in LiteLLM's own CI/CD.
  "models.litellm.cloud",
  "checkmarx.zone",

  // Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 8, 2026).
  // The 17 typosquat packages HTTPS-POST stolen KEY/SECRET/TOKEN/PASS/AUTH/API
  // env vars to this exact ngrok tunnel (:443). A specific subdomain, not a
  // broad ngrok-free.dev block, so no false positives on legitimate tunnels.
  "caliber-spinner-finishing.ngrok-free.dev",

  // Injective Labs SDK npm compromise (The Hacker News / BleepingComputer /
  // Socket / Aikido, July 8-10, 2026). @injectivelabs/sdk-ts@1.20.21 shipped
  // "fake telemetry" that base64-encodes captured mnemonic seed phrases +
  // private keys and HTTPS-POSTs them to this lookalike host (styled after
  // Injective's real grpc-web infra naming). The full specific hostname is
  // matched, NOT a broad injective.network block, so legitimate endpoints such
  // as sentry.chain.grpc-web.injective.network are not flagged.
  "testnet.archival.chain.grpc-web.injective.network",

  // Pepesoft NuGet game-cheat surveillance (Socket, July 14, 2026). Specific
  // sub-hosts only - never the workers.dev / selcloud.ru / pepesoft.ru apex, so
  // legitimate Cloudflare Workers / Selectel usage is not flagged.
  "calm-voice-9797.888c888x888.workers.dev",
  "s3.ru-3.storage.selcloud.ru",
  "bots.pepesoft.ru",

  // NadMesh botnet (XLab via The Hacker News, July 2026). Go-based botnet that
  // hunts exposed AI services (Ollama / vLLM / etc.) and CI/CD hosts, harvesting
  // AWS keys and Kubernetes tokens. Single confirmed C2 domain per XLab's IOCs.
  "cdnorigin.net",

  // cPanel/WHM GitHub Actions abuse campaign (Socket, July 23, 2026). Malicious
  // dev-main versions of a legitimate developer's 10 Packagist packages injected
  // 55-62 GitHub Actions workflow files that spin up runners, pull an architecture-
  // specific Linux payload from C2 43[.]228[.]157[.]68, and scan for cPanel/WHM
  // servers vulnerable to CVE-2026-41940. This is the DNS-callback host used for
  // out-of-band beaconing - a specific UUID subdomain, NOT the dnshook.site apex
  // (a legitimate DNS-logging service), so no false positives on the parent host.
  "f5b0b742-240a-4811-8a5b-b0ba6060685d.dnshook.site",

  // FakeAgent campaign / SectopRAT via fake Claude Desktop app (Huntress / BleepingComputer /
  // Help Net Security / cyberpress, July 21-22, 2026). Bing "Claude Desktop app" ads pointed at
  // a malicious public Claude Artifact that redirected through these attacker-registered domains
  // to a trojanized ClaudeDesktop.exe (JetBrains Chromium binary sideloading a malicious
  // libcef.dll -> SectopRAT / ArechClient2 infostealer with HVNC; EtherHiding via BNB Smart
  // Chain resolves the live C2). These are attacker-owned apexes/subdomains. The legitimate
  // claude.ai apex is intentionally NOT listed (Anthropic-owned; only the abused artifact path
  // was malicious), and the it.com registry apex is NOT listed - only the specific attacker
  // subdomain downloading-api.it.com.
  "download-app.us",
  "claude.ai.download-app.us",
  "downloading-api.it.com",
  "5ca8758c-02d0-4a72-89c8-d468b66dda41.com",
  "polse.us",

  // NeoShadow npm supply-chain attack (Aikido, detected 2025-12-30, published 2026-01-05).
  // Four typosquats (viem-js, cyrpto, tailwin, supabase-js) drop a JavaScript loader that
  // runs a payload through MSBuild and resolves its live C2 from an Ethereum contract.
  // metrics-flow[.]com is the attacker-registered static C2 apex. Single-source for the
  // atomic indicators: only Aikido published the domain/IP/hash set (o3.security
  // corroborates the packages via MAL-2026-334).
  "metrics-flow.com",

  // SANDWORM_MODE / "Echoes of Shai-Hulud" npm worm (Socket + OX Security, 2026-02-20).
  // Worm steals npm tokens and CI secrets, injects malicious MCP servers into Claude Code /
  // Cursor / VS Code, and detonates 48h after install. The specific attacker subdomain is
  // listed, NOT the shared workers[.]dev apex (Cloudflare Workers is legitimate infra used
  // by many projects).
  "pkg-metrics.official334.workers.dev",
  // Secondary C2 apexes, attacker-registered. Single-source (Socket; OX Security's write-up
  // lists only the workers[.]dev subdomain).
  "freefan.net",
  "fanfree.net",

  // Alibaba developer toolchain RAT (Socket, July 2026). A hijacked lib-mtop pulled a
  // dependency chain (local-config-parser / smart-config-manager / cloud-config-fetcher)
  // that writes .cloud-preferences.json and evaluates the rules inside it, giving a
  // cross-platform RAT on developer machines and CI runners. Specific attacker
  // subdomains only: the cn-shanghai.fcapp.run apex is Alibaba Function Compute and
  // ai-app.pub is shared app hosting, so neither parent host is listed.
  "xemzqli2vu.ai-app.pub",
  "diamond-cli-znsxphqell.cn-shanghai.fcapp.run",

  // Fake Corepack install site / infostealer + proxyware (Socket + Gurucul + iTnews,
  // July 2026). Node.js 25 stopped bundling Corepack, so developers started installing
  // it by hand and an attacker registered an impersonation site. There has never been an
  // official Corepack website - the project ships from github.com/nodejs/corepack - so
  // the domain itself is the indicator, and it is a plausible thing to find pasted into
  // a README, Dockerfile or CI install step. The download button funnels through a
  // malvertising redirect chain into a fake VPN installer that steals browser profile
  // data and SSH keys, then enrols the host in a bandwidth-sharing proxy network.
  "corepack.org",
  // Redirect chain and infostealer infrastructure, all attacker-registered apexes.
  "moonlighthathel.org",
  "aifpleasurebeh.org",
  "ghabovethec.info",
  "ukankingwithea.com",
  "beadpie.xyz",
  "yakteam.xyz",
  // Landing and affiliate hops. Specific subdomains only: go2cloud[.]org is the shared
  // Tune/HasOffers affiliate-tracking apex, and canatrace[.]com is not attacker-owned as
  // a whole, so neither parent host is listed.
  "openshield.canatrace.com",
  "nostop.go2cloud.org",

  // mrmustard PyPI compromise (StepSecurity + safedep, July 2026). An attacker took over
  // a maintainer's GitHub account, used the project's own self-hosted CI runners to steal
  // its PyPI publishing token, and pushed a poisoned 0.7.4 whose payload runs on every
  // `import mrmustard`. It collects SSH private keys, AWS credentials and Kubernetes
  // configs - plus SLURM job queues and GPU inventories, so the target is research and HPC
  // estates - and POSTs them here. Attacker subdomain only: femboy[.]energy is not listed
  // on its own, and the exfil path /v1/collect is covered by the host entry.
  "metrics.femboy.energy",

  // ChainDrop npm worm / "Mini Shai-Hulud" (StepSecurity + Aikido + Socket + Endor Labs,
  // August 4 2026). A takeover of the jaredwray npm/GitHub account seeded keyv@6.0.0 and
  // the cacheable family, then a self-replicating worm republished the same preinstall
  // dropper across hundreds of packages in under four hours. Stage 2 harvests .npmrc and
  // GitHub CLI tokens, AWS and Vault credentials, kubeconfigs and crypto wallets, and
  // POSTs them to hxxps://npm-cache[.]com:443/router. Attacker-registered lookalike of the
  // npm cache endpoint, so the apex is safe to list; the /router path is covered by the
  // host entry. The cloud metadata addresses (169.254.169.254, 169.254.170.2) the stage-2
  // payload queries are deliberately NOT listed - they are legitimate link-local endpoints
  // present in ordinary infrastructure code, and blocking them would flag every repo.
  "npm-cache.com",
  // Sibling routers resolved from the same Ethereum contract, published once
  // Microsoft and Datadog reversed the resolver (August 2026). Same
  // ":443/router" exfil path, same registrant pattern: attacker-registered
  // lookalikes of pypi[.]org and a JS CDN, no legitimate use, so the apexes are
  // safe to list. Two independent sources each (Microsoft + Datadog + op-c).
  "pypi-get.com",
  "js-mirror.com",
  // Rotation target the contract handed out before the registry-lookalike names.
  // Random-label .icu with no legitimate service behind it. Single-source
  // (Datadog); the entries above corroborate the write-up's other indicators.
  "awqhnjewqjkl.icu",
  // The public Ethereum RPC endpoints the stage-2 payload calls to read the
  // resolver contract (eth-mainnet.nodereal[.]io, go.getblock[.]io,
  // eth.llamarpc[.]com) are deliberately NOT listed. They are shared, legitimate
  // infrastructure used by ordinary web3 projects, and blocking them would flag
  // every Ethereum repository on sight - the contract address in
  // KNOWN_C2_WALLETS is the indicator that actually distinguishes this campaign.

  // Flooding Dropper / WEL1DROPPER npm slopsquatting campaign (OpenSourceMalware +
  // Sonatype + Unit 42, August 7 2026). ~850 AI-generated typosquat packages published
  // from disposable npm accounts (the "bigops" / "bnpl" / "dolyame" name families, 35.x.y
  // versions) whose README talks the developer into running them. Stage 1 pulls a
  // platform-specific RAT over HTTPS from these Cloudflare Worker hosts, and falls back to
  // reassembling the binary from base64 chunks in DNS TXT records under dl[.]wel1[.]ru.
  // Specific attacker sub-hosts only - never the shared workers[.]dev apex.
  "oob-worker.cf103-070.workers.dev",
  "oob-worker.cf102-baf.workers.dev",
  "oob-worker.cf99-9b3.workers.dev",
  "package-proxy.cf5oobworker.workers.dev",
  "package-proxy.cf6oobworker.workers.dev",
  "package-proxy.cf7oobworker.workers.dev",
  "package-proxy.cf8oobworker.workers.dev",
  "package-proxy.cf11oobworker.workers.dev",
  // Attacker-registered download host, no legitimate service behind it. Listed at the
  // dl[.] label rather than as four separate rows: matching here is an unanchored
  // substring test, so this one entry already covers the published platform subdomains
  // (sdk[.] / ext[.] / pkg[.] / net[.]) without each of them double-reporting.
  "dl.wel1.ru",
  // The TXT-record control channel sits on a sibling label rather than under dl[.], so
  // the entry above does not reach it. Single-source (The Hacker News): the Sonatype and
  // OpenSourceMalware write-ups describe the fallback only as "platform-specific
  // subdomains of wel1[.]ru", which is the dl[.] set. Same attacker-registered apex, no
  // legitimate service behind it.
  "c.wel1.ru",
  // The write-up also lists nexus[.]tcsbank[.]ru, repo-linux[.]tcsbank[.]ru and
  // alertmanager[.]cloudpayments[.]ru, embedded in the sample with an explicitly
  // UNCLEAR role (health check, decoy, or compromised third party). Those are real
  // Russian financial-services hosts, not confirmed attacker infrastructure, so they
  // are deliberately NOT listed - blocking a possible victim on an unresolved
  // attribution is exactly the false positive that gets a scanner switched off.

  // axios maintainer account takeover - UNC1069 / "Sapphire Sleet" cross-platform RAT
  // (Aikido + LevelBlue, March 31 2026). Extends coverage that previously only pinned
  // axios@1.14.1 / @0.30.4 and plain-crypto-js@4.2.1: this is the dropper's C2, reached
  // at hxxp://sfrclak[.]com:8000/6202033. Attacker-registered, no legitimate use.
  "sfrclak.com",

  // spellcheckpy / spellcheckerpy PyPI RAT (Aikido, January 2026). Backfill of a campaign
  // that was never ingested. Stage 2 is pulled from hxxps://updatenet[.]work/settings/
  // history.php and the implant beacons to hxxps://updatenet[.]work/update1.php.
  // Attacker-registered lookalike of a software-update host. Single-source.
  "updatenet.work",

  // GlassWASM / GlassWorm successor - trojanized Open VSX extensions (Socket + Corgea,
  // June 2026). Two impersonation clones of verified VS Code Marketplace extensions were
  // republished on Open VSX carrying a TinyGo-compiled WebAssembly stager. The WASM blob
  // ChaCha20-decrypts this host and pulls the platform-specific stage-2 installer from it.
  // Attacker-registered domain with no legitimate use, so the apex is safe to list; the
  // Solana JSON-RPC endpoint the stager polls for its dead-drop memos is a public network
  // service and is deliberately NOT listed.
  "dodod.lat",

  // TeamPCP telnyx / LiteLLM PyPI wave - infrastructure beyond models[.]litellm[.]cloud
  // and checkmarx[.]zone, which are already listed above.
  // Sources: Datadog Security Labs, Endor Labs, Hexastrike, JFrog, OX Security,
  // Akamai and Trend Micro (March 19-27, 2026).
  // Typosquat of the real "aquasecurity" brand, registered by the actor to slip past
  // DNS allowlists the same way the checkmarx[.]zone lookalike does. The apex is
  // attacker-owned, so both it and the observed scan[.] host are listed.
  "aquasecurtiy.org",
  "scan.aquasecurtiy.org",
  // Internet Computer canister serving the payload. ONLY this canister subdomain is
  // listed; the raw[.]icp0[.]io gateway apex fronts every ICP canister and is
  // deliberately NOT listed.
  "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io",
  // Three attacker quick-tunnels. Single-source (Datadog), so the matching feed
  // entries carry confidence 0.85. The trycloudflare[.]com apex is a shared
  // Cloudflare tunnel host and is deliberately NOT listed.
  "championships-peoples-point-cassette.trycloudflare.com",
  "investigation-launches-hearings-copying.trycloudflare.com",
  "souls-entire-defined-routes.trycloudflare.com",

  // Vellia / Guangnao / lodash-js npm malware cluster (OpenSSF malicious-packages
  // via amazon-inspector, August 2026). Single-source, so the matching feed entries
  // carry confidence 0.85.
  // WebSocket command hub for @guangnao/agent-proxy. Reconstructed at runtime via
  // XOR+base64, so the host never appears as a plaintext string in the tarball.
  "hub.client-llm.com",
  // Cryptojacking pool/wallet config endpoint for @lodash-js/lodash-js. Only the
  // attacker's specific worker subdomain is listed; the workers[.]dev apex is a
  // shared Cloudflare host and is deliberately NOT listed.
  "analytics.baskirill-an.workers.dev",
  // Lookalike of registry[.]npmjs[.]org, used by @polymarkets/clob-client-v2 to
  // serve a trojanized inquirer tarball through a direct dependency URL.
  "registrynpmjs.to",
  // arrayref / proc-macro1 crates.io build-time dropper (August 2026). The VPS
  // hostname that served the stage-2 binary while `cargo build` ran. Only this
  // specific attacker host is listed; the hostwindsdns[.]com apex is a shared
  // hosting-provider domain and is deliberately NOT listed.
  "hwsrv-798836.hostwindsdns.com",
];

// ---------------------------------------------------------------------------
// Known malicious C2 IPs
// ---------------------------------------------------------------------------

export const KNOWN_C2_IPS: string[] = [
  // GhostSocks C2 (Claude Code leak campaign, April 2026)
  "147.45.197.92",
  "94.228.161.88",

  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  "94.154.172.43",
  "91.195.240.123",

  // EtherRAT fallback C2 (April 2026)
  "135.125.255.55",

  // Beagle backdoor / fake Claude AI website (May 2026)
  "8.217.190.58",

  // TCLBANKER Brazilian banking trojan (May 2026)
  "191.96.224.96",

  // Mini Shai-Hulud Worm / TeamPCP - TanStack/UiPath/Mistral/OpenSearch/Guardrails (May 2026)
  "83.142.209.194",

  // node-ipc credential stealer DNS exfiltration endpoint (May 2026)
  "37.16.75.69",

  // Phantom Bot DDoS C2 (deadcode09284814 npm infostealer, May 2026)
  "80.200.28.28",

  // Megalodon GitHub Actions workflow injection campaign (May 22, 2026)
  // C2 receives base64-encoded CI secrets / cloud creds / SSH keys / OIDC tokens on port 8443
  "216.126.225.129",

  // DPRK OtterCookie Node.js stealer (SANS ISC diary 33006, May 22, 2026)
  // Ports 8085 (browser creds), 8086 (file uploads), 8087/api/notify (WebSocket reverse shell)
  // Same /24 subnet as Megalodon C2 (216.126.225.0/24) - likely shared DPRK infrastructure
  "216.126.225.243",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // easy-day-js@1.11.22 postinstall dropper -> cross-platform Node.js crypto-stealer RAT.
  // Dropper C2 on :8000 (/update/49890878); RAT C2 on :443 (/49890878). Both Hostwinds-hosted.
  "23.254.164.92",
  "23.254.164.123",

  // Contagious Interview Rollup polyfill npm packages (Lazarus, DPRK) (July 2026)
  // JFrog: attacker-uploaded npm packages masquerading as Rollup polyfill tooling
  // facilitate remote access + developer-secret theft. Same 216.126.x range as the
  // OtterCookie / Megalodon DPRK infrastructure (216.126.225.0/24). JSONKeeper (a
  // legitimate JSON-paste service) is abused as a dead-drop resolver and is
  // intentionally NOT listed here to avoid mass false positives.
  "216.126.236.244",

  // ChocoPoC RAT / fake PoC exploit repos targeting vulnerability researchers (July 2026)
  // Data-stealing trojan hidden in fake Python PoC repositories on GitHub; this server
  // receives the larger file uploads. Mapbox (a legitimate mapping API) is abused as a
  // DNS-over-HTTPS dead drop and is intentionally NOT listed to avoid false positives.
  "91.132.163.78",

  // Pepesoft NuGet game-cheat surveillance (Socket, July 14, 2026) - authenticated
  // HTTP proxy the surveillance payload speaks to (port 9528 in the report; host only).
  "196.16.3.71",

  // NadMesh botnet (XLab via The Hacker News, July 2026). Go-based botnet hunting
  // exposed AI services + CI/CD hosts for AWS keys / Kubernetes tokens. Confirmed
  // command-and-control IP per XLab's published indicators.
  "209.99.186.235",

  // cPanel/WHM GitHub Actions abuse campaign (Socket, July 23, 2026). C2 that
  // serves the arch-specific Linux exploitation payload (/api/dl/amd64|arm|arm64|386)
  // and receives base64-encoded harvested credentials on /api/github-results, with
  // /api/github-heartbeat beaconing. Reached over port 80. CVE-2026-41940 (cPanel/WHM
  // auth bypass) is the exploited flaw; the compromised maintainer account is a
  // legitimate victim and is intentionally NOT added to the malicious-accounts list.
  "43.228.157.68",

  // FakeAgent campaign / SectopRAT via fake Claude Desktop app (Huntress, July 21-22, 2026).
  // Huntress published ~21 staging/C2 IPs (a rotating BuyVM/FranTech VPS pool plus outliers).
  // A representative subset of the dedicated-VPS C2 hosts is recorded here; the Akamai CDN edge
  // 2.24.131.246 is intentionally omitted (shared CDN, false-positive risk), and the remaining
  // rotating-pool addresses are left out as ephemeral. Durable coverage comes from the domains,
  // file hashes and EtherHiding C2 addresses recorded for this campaign.
  "107.189.24.67",
  "104.194.133.210",
  "45.59.124.17",
  "107.189.17.143",
  "195.110.58.222",
  "191.101.80.211",

  // AsyncAPI npm compromise (Socket + StepSecurity, July 14, 2026). Single host
  // carrying the whole botnet control plane on three ports: :8080 command
  // channel, :8081 credential upload, :8091 proxy management. The package
  // versions were already pinned in v5.x; this is the C2 infrastructure the
  // advisory databases never publish. The campaign's Nostr relays
  // (relay.damus[.]io), BitTorrent DHT bootstrap nodes (router.bittorrent[.]com)
  // and the ipfs[.]io gateway are shared public infrastructure and are
  // intentionally NOT listed - only the campaign-specific CID paths are.
  "85.137.53.71",

  // NeoShadow npm supply-chain attack (Aikido, 2026-01-05). Static fallback C2 used when the
  // Ethereum contract lookup that normally hands out the live address fails. Single-source.
  "80.78.22.206",

  // Joyfill npm compromise / DEV#POPPER (Socket + StepSecurity, July 28 2026).
  // Stage-3/4 hosts for the Socket.IO RAT and the staged Python credential
  // stealer; :443 and :80 on the first. The blockchain RPC endpoints the loader
  // reads its C2 address from (api.trongrid[.]io, fullnode.mainnet.aptoslabs[.]com,
  // bsc-dataseed.binance[.]org, bsc-rpc.publicnode[.]com) and the ip-api[.]com
  // geolocation lookup are shared public infrastructure and are intentionally
  // NOT listed - blocking them would flag every legitimate web3 repository.
  "166.88.134.62",
  "23.27.13.43",
  "198.105.127.210",
  "23.27.202.27",

  // axios maintainer account takeover - UNC1069 / "Sapphire Sleet" (Aikido + LevelBlue,
  // March 31 2026). Resolver for sfrclak[.]com, which serves the RAT stage on :8000.
  "142.11.206.73",

  // spellcheckpy / spellcheckerpy PyPI RAT (Aikido, January 2026). Host behind
  // updatenet[.]work. Single-source. The Cloudflare edge address published for the
  // ChainDrop router (104[.]21[.]35[.]216) is deliberately NOT listed anywhere here -
  // it is a shared anycast address fronting millions of sites.
  "172.86.73.139",

  // TeamPCP telnyx wave (March 27, 2026): serves the WAV-disguised stage 2 on :8080.
  // Same /24 as the Mini Shai-Hulud host 83[.]142[.]209[.]194 listed above. Only the
  // two addresses corroborated by two independent write-ups are listed; the /24 itself
  // is NOT blocked, and two further addresses the sources disagree on are left out.
  "83.142.209.203",
  "83.142.209.11",
  // arrayref / proc-macro1 crates.io build-time dropper (August 2026). The
  // poisoned build.rs pulled stage 2 from :9089 and beaconed to :443 on the
  // first address; the other two served stage-2 C2. Corroborated by
  // StepSecurity, Wiz and safedep. The maintainer whose crates.io account was
  // abused to publish arrayref 0.3.10, internment 0.8.7 and append-only-vec
  // 0.1.9 is a VICTIM and is not listed anywhere in this file.
  "23.254.165.112",
  "23.254.167.107",
  "23.254.167.216",
  // Same campaign, reported by Wiz only - single-source, so the matching feed
  // entry carries confidence 0.85 rather than 1.0.
  "23.254.167.13",
];

// ---------------------------------------------------------------------------
// Known dead-drop resolver URLs
// ---------------------------------------------------------------------------

export const KNOWN_DEAD_DROPS: string[] = [
  // mgc npm account takeover - UNC1069 / "Sapphire Sleet" WAVESHAPER.V2 (safedep,
  // April 2026). Same actor as the axios takeover already covered here: the dropped
  // implant paths safedep reports (/tmp/ld.py, /Library/Caches/com.apple.act.mond,
  // %PROGRAMDATA%\wt.exe) are character-for-character the ones the axios hashes below
  // are described by, which is what corroborates an otherwise single-source write-up.
  // Only the attacker's own gist path and C2 endpoint are listed. The gist is hosted
  // under the MAINTAINER'S OWN account (admondtamang) and the C2 runs on his personal
  // domain, both taken over rather than attacker-registered - so gist.github.com,
  // gist.githubusercontent.com and the bare admondtamang[.]com[.]np apex are
  // deliberately NOT listed, and the account is NOT in KNOWN_MALICIOUS_GITHUB_ACCOUNTS.
  // He is a victim; flagging the person is the false positive that gets a scanner
  // switched off.
  "admondtamang.com.np/gate",
  "gist.githubusercontent.com/admondtamang/814132e794e5d007e9b8ebd223a9494f/raw/1c5d51c2002f452a4dd58a1a73a9dd90a7fe0297/linux.payload",
  "gist.githubusercontent.com/admondtamang/814132e794e5d007e9b8ebd223a9494f/raw/1c5d51c2002f452a4dd58a1a73a9dd90a7fe0297/window.payload",
  "gist.github.com/admondtamang/814132e794e5d007e9b8ebd223a9494f",

  // Vidar dead-drop resolvers (Claude Code leak campaign)
  "steamcommunity.com/profiles/76561198721263282",
  "telegram.me/g1n3sss",
  "t.me/g1n3sss",

  // AsyncAPI npm compromise (July 2026)
  // Second-stage loader was fetched from the IPFS peer-to-peer network. The
  // specific malicious CID path is matched, NOT the ipfs.io gateway host, so
  // legitimate IPFS usage is not flagged.
  "ipfs.io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9",
  // Second payload CID, serving the @asyncapi/specs branch of the same campaign
  // (single-source: StepSecurity; Socket's write-up lists only the generator CID).
  "ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf",

  // PhantomSync npm crypto stealer (Xygeni, July 15, 2026). Config dead-drop is a
  // specific GitHub gist raw path; the three IPFS CIDs are config fallbacks (bare
  // CID strings, matched by content, never the ipfs.io/pinata gateway hosts).
  "gist.githubusercontent.com/juang55/b298754cb72942b1cdcf02ccd45cde2f/raw/cfg.txt",
  "Qmcqz3w8j4qFQXDAXAxnrdc2oSX3nzBT4NqtpTqL8mr1ga",
  "QmdTXoqVmTHY1i4ZWLdLkoQ9YChp5TXPh5cWXwnAYZt5iF",
  "QmfJkLU5gdCpqbbqEjWYC2anXW9FmuEeSLLeLiHVJKYUjp",

  // Pepesoft NuGet game-cheat surveillance (Socket, July 14, 2026). Specific
  // path/handle values only - never the discord.com / t.me / github.com /
  // huggingface.co parent hosts.
  "t.me/pepesoft777",
  "github.com/pepegit666/123f53y45ysdf34",
  "huggingface.co/buckets/pepegit666",
  "discord.com/api/webhooks/1156474517871403078/zuHl6xQzdMcFjNrmm9jTiHvCzNbCiQhkYAIGWNUfj7X4KUIpEATekKlSNna6OvyCKaRw",
  "discord.com/api/webhooks/1156474527874818088/qS5cJuxEbyIA1s3tZX_A2u6YsKtLUARVPvN77_6fK5QHGdGFHb3JSuCUSDhtouEsyJgk",

  // Alibaba developer toolchain RAT (Socket, July 2026). Staging buckets serving the
  // config, the Electron app.asar and the native second stage. Full bucket paths only -
  // oss-cn-beijing.aliyuncs.com is Alibaba Cloud OSS, shared infrastructure used by
  // countless legitimate projects, so the gateway host is deliberately NOT listed.
  "aone-cli-next.oss-cn-beijing.aliyuncs.com/config/setting.js",
  "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli.js",
  "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli-deps.tar.gz",
  "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli",
  "aone-ai-cli.oss-cn-beijing.aliyuncs.com/app/release/aone-cli.zip",
  "aone-kit.oss-cn-beijing.aliyuncs.com/plugins/crypto.js",
  "aone-kit.oss-cn-beijing.aliyuncs.com/aone-kit-update/aone-kit.js",
  "aone-kit.oss-cn-beijing.aliyuncs.com/aone-kit-update/app.asar",
  "aone-kit.oss-cn-beijing.aliyuncs.com/aone-kit-update/aone-kit-update",
  // Config dead-drops under the attacker GitHub account, saved locally as
  // .cloud-preferences.json and then evaluated by local-config-parser. Specific
  // account/repo paths only - never the github.com apex.
  "github.com/smi1e2u/fast-transform-pipeline",
  "github.com/smi1e2u/smart-config-manager",
  // The live raw path the chain actually fetches, rather than the repo page.
  // Full path only - raw.githubusercontent[.]com serves every public repository
  // on GitHub, so the host must never be listed. Single-source (Corgea), but the
  // owning repository is confirmed attacker-created by Socket above.
  "raw.githubusercontent.com/smi1e2u/smart-config-manager/main/defaults/preferences.json",

  // ChainDrop npm worm / "Mini Shai-Hulud" (Microsoft + Datadog, August 4 2026).
  // Exfiltration dead drops are GitHub repositories the worm creates under each
  // victim account, identified by a fixed marker name rather than a URL, so the
  // bare marker string is what a payload or an incident artefact contains. Both
  // are long random-word constructions with no other use; "thebeautifulsnadsoftime"
  // is single-source (Datadog), "thebeautifulmarchoftime" is confirmed by
  // Microsoft as well. The two long taunt strings the same write-ups list are
  // payload description text, not locators, and belong to the campaign rules in
  // patterns.ts rather than here. These two are deliberately blocklist-only and
  // have no bundled-feed counterpart: a bare repository name is not URL-shaped,
  // and IOC_VALUE_SHAPES.url in threat-intel.ts rejects it by design.
  "thebeautifulmarchoftime",
  "thebeautifulsnadsoftime",

  // Miasma "Hades" PyPI wave (Socket + StepSecurity + Orca, August 2026). The
  // stealer creates one exfiltration repository per victim, named from a fixed
  // underworld-themed prefix plus a counter (stygian-cerberus-1,
  // tartarean-charon-2, ...). All three write-ups list the same two prefixes, so
  // the prefix is the stable locator and the trailing digits are not.
  //
  // Only the HYPHENATED COMPOUND prefixes are listed. The same write-ups also
  // name the bare component words the payload draws on - stygian, tartarean,
  // cerberus, charon, styx, lethe, thanatos, persephone - and several of those
  // are ordinary open-source project names (cerberus is a widely used Python
  // validation library). Listing a bare component word here would substring-match
  // every project that uses it and is deliberately avoided.
  //
  // Blocklist-only, like the two markers above: a bare repository-name prefix is
  // not URL-shaped, so IOC_VALUE_SHAPES.url in threat-intel.ts rejects it.
  "stygian-cerberus-",
  "tartarean-charon-",

  // Fake Corepack install site (Socket + Gurucul, July 2026). The fake VPN landing page
  // the "Download Free" button redirects into, serving
  // vpnsetup_d9gfqvs3dsic73fcvi90.exe. Path-scoped on purpose: the campaign path is
  // listed, never the freevpn[.]win host on its own.
  "freevpn.win/lps/gbox-lp/index.html",

  // mrmustard PyPI compromise (StepSecurity + safedep, July 2026). The CI workflow the
  // attacker pushed from the breached maintainer account dumped the repository secrets,
  // including the PyPI publishing token, to this collector. Scoped to the single attacker
  // bin: webhook[.]site is a legitimate request-inspection service used constantly in
  // ordinary development, so the apex is deliberately NOT listed - only this bin id.
  "webhook.site/710babde-6ace-47fe-83f4-9688e6548df9",

  // GlassWASM trojanized Open VSX extensions (Socket + Corgea, June 2026). Per-platform
  // stage-2 installer paths the WASM stager pipes into bash / iex once it has decrypted
  // the host. Path-scoped alongside the dodod[.]lat entry above so a mention of the host
  // in an incident note and a real fetch URL are both caught.
  "dodod.lat/darwin/i/_",
  "dodod.lat/linux/i/_",
  "dodod.lat/win32/i/_",

  // TeamPCP telnyx wave (March 27, 2026): stage-2 credential harvester hidden inside
  // WAV audio files, fetched on `import telnyx` (Endor Labs + Hexastrike).
  "83.142.209.203:8080/ringtone.wav",
  "83.142.209.203:8080/hangup.wav",

  // Vellia / Guangnao / lodash-js npm malware cluster (OpenSSF malicious-packages
  // via amazon-inspector, August 2026). Single-source, so the matching feed entries
  // carry confidence 0.85.
  // Mining pool + wallet config fetched at runtime by @lodash-js/lodash-js.
  "analytics.baskirill-an.workers.dev/configs/boostydownloader",
  // Trojanized inquirer tarball, pulled in as a direct dependency URL.
  "registrynpmjs.to/inquirer-14.0.2.tgz",
  // @velliajs/discord runtime allow-list / kill-switch. Path-scoped to the
  // attacker's repository: api[.]github[.]com is a legitimate shared host and is
  // deliberately NOT listed.
  "api.github.com/repos/Vellia-Elyvia/mydb/contents/db.json",
];

// ---------------------------------------------------------------------------
// Known malicious file hashes (MD5)
// ---------------------------------------------------------------------------

export const KNOWN_MALICIOUS_HASHES: Record<string, string> = {
  // mgc npm account takeover - UNC1069 / "Sapphire Sleet" WAVESHAPER.V2 (safedep,
  // April 2026). Tarball digest shared by all four trojanized versions. Single-source,
  // but round-tripped as a well-formed 64-char digest across two independent fetches
  // before ingestion.
  "40aa5d412a50db79a814ac5ad65237745727cb4777843d66a760f64285a5a3e6": "mgc 1.2.1-1.2.4 trojanized npm tarball, UNC1069 dropper (SHA256)",

  // Claude Code leak campaign (April 2026)
  "d8256fbc62e85dae85eb8d4b49613774": "Claude Code malware archive",
  "8660646bbc6bb7dc8f59a764e25fe1fd": "Claude Code malware archive (variant)",
  "77c73bd5e7625b7f691bc00a1b561a0f": "ClaudeCode_x64.exe Rust dropper",
  "81fb210ba148fd39e999ee9cdc085dfc": "ClaudeCode_x64.exe Rust dropper (variant)",
  "9a6ea91491ccb1068b0592402029527f": "Vidar v18.7 stealer",
  "3388b415610f4ae018d124ea4dc99189": "GhostSocks proxy malware",

  // MacSync Stealer / malicious Homebrew ad (May 2026)
  "a4fcfecc5ac8fa57614b23928a0e9b7aa4f4a3b2b3a8c1772487b46277125571": "MacSync Stealer payload (SHA256)",
  "0d58616c750fc8530a7e90eee18398ddedd08cc0f4908c863ab650673b9819dd": "MacSync Stealer variant (SHA256)",
  "86d0c50cab4f394c58976c44d6d7b67a7dfbbb813fbcf622236e183d94fd944f": "MacSync Stealer variant (SHA256)",

  // TCLBANKER Brazilian banking trojan (May 2026) - REF3076 / trojanized Logitech AI Prompt Builder
  "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626": "TCLBANKER component (SHA256)",
  "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059": "TCLBANKER component (SHA256)",
  "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40": "TCLBANKER component (SHA256)",
  "63beb7372098c03baab77e0dfc8e5dca5e0a7420f382708a4df79bed2d900394": "TCLBANKER component (SHA256)",

  // MacSync Stealer Claude.ai/Google ads variant (May 2026) - loader.sh + payload
  "ed5ed79a674972d1506dd8d68e8e13658125267ade86bfcb1ab794e2b49e50ac": "MacSync Stealer Claude.ai variant payload (SHA256)",
  "a833ad989b68dad582a1b591b8cf63466e79c850ff72916cf5d4c4a7f6bc650e": "MacSync Stealer Claude.ai variant loader (SHA256)",

  // node-ipc credential stealer via maintainer email hijack (May 2026) - obfuscated CJS bundle
  "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144": "node-ipc.cjs credential stealer payload (SHA256)",

  // Mini Shai-Hulud TanStack wave router_init.js payload (May 2026)
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c": "Mini Shai-Hulud router_init.js TanStack payload (SHA256)",

  // Mini Shai-Hulud @antv wave - 498KB obfuscated Bun index.js payload (May 19, 2026)
  "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c": "Mini Shai-Hulud @antv index.js Bun payload (SHA256)",

  // Nx Console nrwl.angular-console 18.95.0 compromise (May 18, 2026)
  "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8": "Nx Console 18.95.0 malicious VSIX (SHA256)",
  "b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74": "Nx Console 18.95.0 main.js (SHA256)",
  "e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1": "Nx Console 18.95.0 obfuscated index.js payload (SHA256)",
  "43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd8": "Nx Console 18.95.0 dropper package.json (SHA256)",

  // Nx Console malicious orphan commit SHA - referenced in VS Code globalState key (May 2026)
  "558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2": "Nx Console malicious orphan commit (Git SHA)",

  // DPRK OtterCookie Node.js stealer (SANS ISC diary 33006, May 22, 2026)
  // Obfuscator.io-style obfuscation; 41 crypto-wallet extension IDs; 200+ file patterns; uses
  // hardcoded HMAC-SHA256 key "SuperStr0ngSecret@)@^"; WSL/macOS/Linux scanning
  "049300aa5dd774d6c984779a0570f59610399c71864b5d5c2605906db46ddeb9": "DPRK OtterCookie Node.js stealer payload (SHA256)",

  // Laravel-Lang DebugElevator PHP credential stealer (May 23, 2026)
  // Hijacked Composer packages laravel-lang/{lang,http-statuses,attributes,actions}; ~700 versions
  // republished with malicious src/helpers.php exfiltrating to flipboxstudio.info/exfil
  "f0d912c1a72e533417d5e158bb9755f848ec678b6448ae7c8fb6e87da78a3053": "DebugElevator src/helpers.php PHP stealer (SHA256)",
  "23e779555c21beaed6ae8f1f298daf9b00d603f1a6716ce329332aadcb80fbe2": "DebugElevator src/helpers.php PHP stealer variant (SHA256)",

  // ACR Stealer fake Claude page / Google Search malvertising (SANS ISC diary 33018, May 26, 2026)
  // Corrupted zip -> PowerShell loader -> ACR Stealer infection chain.
  "70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2": "ACR Stealer fake-Claude page component (SHA256)",
  "a14c3ecf5eb3d2543358482e43dc765dbf9ee7a4bec7571f5ecb8829ca719692": "ACR Stealer fake-Claude page component (SHA256)",
  "47fa746422f1bf6b7712dc6803378e6a995488007193a7441d790f70d204728f": "ACR Stealer fake-Claude page component (SHA256)",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // Only the malicious easy-day-js@1.11.22 tarball + stage-2 RAT are recorded; the clean
  // precursor easy-day-js@1.11.21 is intentionally NOT listed to avoid false positives.
  "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf": "Mastra attack easy-day-js stage-2 Node.js crypto-stealer RAT (SHA256)",
  "4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417": "easy-day-js@1.11.22 malicious npm tarball (SHA256)",

  // Injective Labs SDK npm compromise (July 8-10, 2026) - infostealer files
  // bundled inside @injectivelabs/sdk-ts@1.20.21 that capture wallet private
  // keys / mnemonic seed phrases and exfiltrate via fake telemetry.
  "103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0": "Injective sdk-ts@1.20.21 infostealer accounts-Cy0p4lLW.cjs (SHA256)",
  "9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9": "Injective sdk-ts@1.20.21 infostealer accounts-jQ1GSgaW.js (SHA256)",

  // Pepesoft NuGet game-cheat surveillance (Socket, July 14, 2026) - 31 SHA-256
  // payload hashes (11 downloader assemblies + 20 second-stage native/pyc/PyArmor).
  "d5385526f2f3e52c7d96087611c6cd4e479bf61828400efdb3ca09406d981609": "Pepesoft albion.dll (SHA256)",
  "9a2091e6625fc11cfd8f39c17aa271604e66322ee045028946274b988103e35b": "Pepesoft amazingrp.dll (SHA256)",
  "900ddb81d27e03967209fee4d17d13deb68eef0e1f10936eb520ca10575cb49e": "Pepesoft calculator.dll (SHA256)",
  "ab58a90eb3682c6dc3389cd700a64f68a19c0dac3d0fa8e3df97ae041f96d4e1": "Pepesoft grandrp.dll (SHA256)",
  "e6e1049158ceb1971c61388349c81fa6047a7aecb4ff2089ef54a50dcc35dbc0": "Pepesoft gta5rp.dll (SHA256)",
  "d9f7ca9f93a7d188d51db308877b15d0beae932ca0bf4705384fbedf54b454c1": "Pepesoft lineage2.dll (SHA256)",
  "4d13f1136b13c871c65141b77ec7208488334ac4be511800196adcd328666305": "Pepesoft majestic.dll (SHA256)",
  "011926de3d0cc2b970627b9bf0de003e731f8576602dff756d2ab54a9de61972": "Pepesoft rmrp.dll (SHA256)",
  "79c09e1ffb4804c14ff27d41ec08d4390455c92d65717be0aeeec2697297d76a": "Pepesoft rusfish4.dll (SHA256)",
  "5f3a9ebf7039097b3cdbca8609b5b68af07eeb1dbf716ba2817a97fc7c543854": "Pepesoft setup.dll (throne) (SHA256)",
  "23808e7638f7a00b1ef9b9f4ca524f8a46cf63be6f6b79fec8e4a3fd1cc82a1e": "Pepesoft trigger.dll (SHA256)",
  "e8c2618565aa31d7ffe909ebc99040bafcc0ea8df7f5d92fa673bb7ffacb14c9": "Pepesoft Amazing RP native (SHA256)",
  "6eefe9d5f030d403c72bd4e4caf5bbb9dbc2bd5e15ebb07de153494f458e5eb9": "Pepesoft GrandRP native (SHA256)",
  "8ab256dd839aec6638cd46374f4a6664e534b9341bbcdfd9b763e5a27c51ddb7": "Pepesoft GTA5RP native (SHA256)",
  "6c1f828e4d8395dde8293868c65ba8d86b3b9672ebbbb16e932624706d37d832": "Pepesoft Lineage 2 native (SHA256)",
  "6cbd4bc491deb11040e2b2f91b0b4e129af551a802fc78cb42e0e985297ef44c": "Pepesoft Majestic native (SHA256)",
  "5d9843126db4223dc2a8a9cd4a627286fe1a6345e33b28e9c98b5fe56fe89da6": "Pepesoft RMRP native (SHA256)",
  "c9f3e7766dbe728d84a1243447faa5f5eba0645bf13089074d128ea7663e7f5b": "Pepesoft Russian Fishing 4 native (SHA256)",
  "a2a5e473dba85959b21b7e8a184bc255d5f2dacdf7411b91d212fb1217d2518b": "Pepesoft Trigger native (SHA256)",
  "ba7fc544994f126cb7485ce52d265d2f32e93c4f1ea1fcd6fcdee3918f271979": "Pepesoft charset_normalizer mypyc (SHA256)",
  "567952daf0ab7b36b017aac9963791188dea0fbf2e99c7cc6f6652ee540f4840": "Pepesoft gtaobus.pyc (Albion) (SHA256)",
  "cc853b3e4504c890d275ac2327f18acd7e4c5b99ca056181f3f5694781f2cf45": "Pepesoft gtaobus.pyc (Calculator) (SHA256)",
  "476c6f36a22156e53548a87291989a21d6c905dcbd9e1bf68ff5bc12e5c8bb07": "Pepesoft gtaobus.pyc (Throne) (SHA256)",
  "774e40046f353e3f916f39e3d13d6499da35705a479cfb89288c21017aaf5461": "Pepesoft PyArmor Amazing RP (SHA256)",
  "23e4d8af5425dae022793450190c8d30809b2986dd879eb4bff557cdacf49c86": "Pepesoft PyArmor GrandRP (SHA256)",
  "95577498d23fe750221a5badfc25b5e9f020dcf4d80c79a019b090e3c3b0a32a": "Pepesoft PyArmor GTA5RP (SHA256)",
  "2a4fed04d792b9c2fdf9c1456a08ca23eda5fef50c0b409ab294ad489e12d801": "Pepesoft PyArmor Lineage 2 (SHA256)",
  "7e42d25e707d29d5d185a4c5dc71019f744e88a30b66bbf06949194ff32dbc48": "Pepesoft PyArmor Majestic (SHA256)",
  "d59e1914d76499fa51bf861f418c84bda0b48913dc39bd2e73756e326e4ccbb0": "Pepesoft PyArmor RMRP (SHA256)",
  "17b1d836c2f15a97be0350879943b04e14bc076cf09e31df0d73258ee10f7e7c": "Pepesoft PyArmor Russian Fishing 4 (SHA256)",
  "01d2afea0f2201a3b59765a1a60ba324ff4b8fdd25f23a0e05824b97f195b27c": "Pepesoft PyArmor Trigger (SHA256)",

  // NadMesh botnet (XLab via The Hacker News, July 2026) - Go-based botnet agent
  // sample. XLab published a SHA1 (not MD5/SHA256) for the sample; stored as a
  // content-reference indicator (the hash matcher is a substring check, so the
  // digest length is irrelevant to matching, same as the Nx Console Git-SHA entry).
  "31c69b3e12936abca770d430066f379ec1d997ec": "NadMesh botnet Go agent sample (SHA1)",

  // cPanel/WHM GitHub Actions abuse campaign (Socket, July 23, 2026) - the Linux
  // scanner/exploitation payload downloaded by the injected workflows from
  // 43.228.157.68 and run on ephemeral GitHub-hosted runners.
  "22f721fd3a81d2e27cbf90a122bb977f630c50b79daa98350f0e57b04dfa81f1": "cPanel/WHM GitHub Actions campaign Linux exploit payload (SHA256)",

  // jscrambler npm supply-chain compromise (Socket / The Hacker News / OX / StepSecurity,
  // July 11, 2026) - native Rust infostealer dropped by the malicious preinstall hook
  // (8.14.0-8.17.0) and self-executing dropper (8.18.0+) across Windows/macOS/Linux;
  // targets AWS/GCP/Azure creds, crypto wallets, browser data, AI tool configs. Hashes
  // per Rescana's IOC set.
  "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60": "jscrambler compromise infostealer payload (SHA256)",
  "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86": "jscrambler compromise infostealer payload (SHA256)",
  "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd": "jscrambler compromise infostealer payload (SHA256)",
  "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903": "jscrambler compromise infostealer payload (SHA256)",
  "c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd": "jscrambler compromise infostealer payload (SHA256)",
  // Manifest of the malicious jscrambler@8.20.0 release (the dropper-in-dist stage,
  // which carries no preinstall hook). Catches a vendored or mirrored copy of that
  // release where the version metadata is gone. Single-source (Socket only; Rescana's
  // IOC set lists the five payload hashes above but not this one).
  "bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0": "jscrambler compromise: package.json of malicious jscrambler@8.20.0 (SHA256)",

  // FakeAgent campaign / SectopRAT via fake Claude Desktop app (Huntress / BleepingComputer,
  // July 21-22, 2026) - the trojanized ClaudeDesktop.exe (JetBrains Chromium binary sideloading
  // a malicious libcef.dll) and related SectopRAT / ArechClient2 payload files per Huntress's IOC set.
  "1cd58cfba596da296ab1878d74023e00c399345a1b6c2a0e5446c53563f4e3bb": "FakeAgent SectopRAT payload (SHA256)",
  "26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a": "FakeAgent SectopRAT payload (SHA256)",
  "1fe3646d27d286db8123297e06ae7badf3e26f352a04f91b6d82c28869a91664": "FakeAgent SectopRAT payload (SHA256)",
  "f8acb8f5cf88b77a4c27d7fd6856aa299bb178e85f9963c2fbd447d818da3ed0": "FakeAgent SectopRAT payload (SHA256)",
  "fd826215add30c1319eefa291b6eaf8ddfa7720cfe816c49aef6fe8a88de7939": "FakeAgent SectopRAT payload (SHA256)",

  // AsyncAPI npm supply-chain compromise (Socket, July 14, 2026) - SHA-256 of the
  // five malicious registry tarballs. The package@version pins already cover an
  // install from npm; these catch a vendored or mirrored copy of the same artifact
  // where the version metadata is gone. Single-source (Socket published the hash
  // set; StepSecurity's write-up corroborates the same five artifacts by version).
  "34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1": "AsyncAPI compromise: @asyncapi/generator-helpers@1.1.1 tarball (SHA256)",
  "082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab": "AsyncAPI compromise: @asyncapi/generator-components@0.7.1 tarball (SHA256)",
  "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4": "AsyncAPI compromise: @asyncapi/generator@3.3.1 tarball (SHA256)",
  "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b": "AsyncAPI compromise: @asyncapi/specs@6.11.2 tarball (SHA256)",
  "d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7": "AsyncAPI compromise: @asyncapi/specs@6.11.2-alpha.1 tarball (SHA256)",

  // NeoShadow npm supply-chain attack (Aikido, 2026-01-05). Windows native stage dropped by
  // the JavaScript loader and side-loaded through MSBuild. Single-source.
  "012dfb89ebabcb8918efb0952f4a91515048fd3b87558e90fa45a7ded6656c07": "NeoShadow analytics.node Windows backdoor (SHA256)",

  // SANDWORM_MODE / "Echoes of Shai-Hulud" npm worm (Socket, 2026-02-20). Stage-2 payload
  // fetched by the installed package. Socket also published the stage-2 AES-256-GCM key, IV
  // and auth tag; those are decryption material, not file digests, so they are deliberately
  // NOT ingested here - a key in the hash map would misreport as "this file is malware".
  "5440e1a424631192dff1162eebc8af5dc2389e3d3b23bd26e9c012279ae116e4": "SANDWORM_MODE stage-2 worm payload (SHA256)",

  // Alibaba developer toolchain RAT (Socket, July 2026). SHA-256 of the loader and
  // native second-stage artifacts staged in the attacker OSS buckets. Socket published
  // the digests as a flat set without mapping each one to a package@version, so they
  // are labelled by campaign only rather than inventing an attribution. Single-source.
  "84a6ccaaab1596139d28e822f40cc99c68d337d4c81d1c6d9692c1d6bb22e4af": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "6044974c633b3a319c31bb32110411520c425e89722a64806528553227e7a50a": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "0910ecfa049738ef3f2540855341a380df89224ff71da94b4c21689fd66f62e3": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "b8b81af76163bdcc5b4f7d8fe6795f164991f8a62678c971db031b9e90a27813": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "ef9a1896eeaae929800eade768276e2240ef252d26d0d96c1950a1a5e1aadb34": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "e5d8350f1540fe91145dc262c455bca7748ad97dafb2d9facd5adebed9f66d2d": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "41957bd0ba2d9c07af2e069f10780fdf6b2102c065bebe0db2136dfe07d67a28": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",
  "33b58598eb317553942e27545982d4c25ce6120eae10e42393746eb0e02ecae9": "Alibaba developer toolchain RAT: staged payload artifact (SHA256)",

  // Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 2026). SHA-256 of the
  // malicious entry points: 52 npm index.js (13 packages x versions 1.0.0-1.0.3) and
  // 4 PyPI __init__.py. The package@version pins already cover a registry install;
  // these catch a vendored or mirrored copy where the version metadata is gone.
  // Socket published the digests as one flat list per file name without a per-package
  // mapping, so they are labelled by campaign and file name only. Corroborated by
  // gbhackers for the campaign and C2; the hash set itself is single-source (Socket).
  "ce09810adca70ebec87bc455380ef629ceaa2a0d926149d9115604060167682c": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "b2ea8d69f6792a87327ffde2ee4551bb6b99617f53e1ba71bf9a70f45dbc57ea": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "8a70a5c1075f2dea4db94633ddc64b0d03d0385fdeda7c226acc944331febf43": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "c8b4d17c1f0aa7c50f2fa23d7c328482a4ad2c4da4d600f358ebdf200cbefd83": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "9fd06d823d54183cc91625fdc6decffe8db2863f6499a955656ebdcc089792cf": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "615805652b2f006e69512b90d0d63883d7ae1ede69d86384fd77bd46235b2369": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "6dc672e3bab8bcf80c66b2f95150067fb47429d4cf65eb95215e5f3abc7cade5": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "4a4b5c1bc1e948c853cb0978c07c7b8d1540c7b1ded95f8d5ad25c126cb6c7b0": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "9727c804c4354e481d2ff9d4934bd1b2518293a9ca34a14f5c7ae9d0cd30ce94": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "313853a82bce61052c00e6a6af85b5069e007a76122c727f31661bc636b12f14": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "2cbfc4e4b1de5e68ab81fba7e1b0c711b4d26197b48ea4db6819c9cea223b0ed": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "a0313822513f9b89479f666888a4784a3fc99b4cc4566213dcda66b03b47120c": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "3a0dd3479eaf85b65e5abd63d6451f98506faddee47cf4bebd9f91296abb29f0": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "39371ac7061168dd3d890061267b3875bc4b30dca5e28d40dbc27a4396439ff1": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "c51c0b6c7817443b021aff44d4416c09fd039849db81860b9b5144e789fa3987": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "6e251c3d2bde8fff0487c1eecd359c4a544a09fd708755020e4b1c53ad6b8dd1": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "cd7255730b6a7a3895d622d37d0e8f984d2d280689acef56ff195d663e7723ad": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "5c4faef80c83c7ec0925a4aacb4bddabe82b91066ac41305907ba277cd7b3b85": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "50cb7550224d8d227a0625e7f53be86924d8e057e403b6b91b83ea20df834048": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "1bae9f2fb9866422f07345501fa2cb4c3a99f2652c8c9decdc27ffbf9714e7bc": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "1df8c579ffcbf5527b1856bd1774601a5188b380e442c5a0fbd400bd86a4501b": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "b29973eda4d0c090608c15a976688cad0b2114fdc0dcb89ad37515287ba13aad": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "9e9655f54bfac8a937d78ac506722bae1468ead4cc9ee95b35e0f8ef17ee13d9": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "67e4d6a4f53098e48bfa6ecceeaa754592bc249b83404fcfb8542977ae36dac4": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "1bfa32548676d32b7639d3171e2f9feefba5026dc336968c91f4ae2b152c5410": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "2bc8af4bd2f539630f7800f3491b64c7e2bffe12e955d0d4f03a4f6a4b0018bd": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "eae055c5736366811d2a4b1f78ff206486e7f7445040122efbe023ecd2d20bcc": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "d4ed2d87942fbefa5d7b7f19fb6f2e9bc293c96bf577bb97ed3ca56185abcf25": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "447484c76a06918d7f6f6c6f95ee2bced6dd2e9b282c6f5b92b2b7c0976381d5": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "f43cb68850a2506805d60ff466f54eba331e1cc2a513b329f5121e0c39104418": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "1314fc888ca5b3ea91a04e1f5b63039ffc7fc3832b8d809a28ad549c6f9d4f23": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "af66bc2b516d1ef71af9b6ee9f8f5af0a99fed562b34809cd55071b94c2d1304": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "b157a66826d27512c3618817fee924e53d14cabb2c4c7f454affde37350f55f0": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "2303a74a5fac917279f1078e03a4bfd6afbb89462f97d7344ed10e6e9e9e92b7": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "5242c5086d75a492d14e474de7c8f34b18ec0a8a9ce6d77eec8675a9572d9d23": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "1d567795a366b9edcfef7f1fa2d398b7cb41890dd3b2f3f1f9803de0cdba0c89": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "c2e4483abea830ba8b8230540ace51788d0712bed9006697ddddb9cbf133c151": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "390bca9d70efa42cb792f7f677189821a24527cd4298ab2acb954df0abb5c1c3": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "f7d9865ea3874d2b135eeee0aa0d12fc108d89e1dd706e4e40eb7605b76d35ca": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "2b7696575278e6e223cc44553c687e45afd04df7eb32efbf49b39da64b795982": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "2edb3f162f9676196e818d9b795d599ba119a961ffe98c4866351735980d213d": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "727fe9c1dfa39d6590012e0593c9837c628fc2cd22aa0f4e486b7ed1aec02697": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "8a58e3ed713c1c70f421ab56a18cfb6a120c960d227e495b511c2552f25f188b": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "67eb3bd505ebfffbd73fc3ef0b2976c375df732f0bd0496ed6653c3e2be5a0e5": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "616b41657e9afaa9354fc1a106393373dcbf8aac8455b7d2cbbb44463434528e": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "52a57c502e40b3f9897d0ca32bba6f844b4113f5c017627ea9eba660eb47f405": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "d1889d81cfa99d52017732da9dc52127d03893037874c8671943cede4b8d1bb2": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "a677c02e545941e43f8b21a5761b035e911b53e2c065fea219e0f3462f282fd8": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "e076e13a7e112d364f03bd1ead7abaa83249d544491621254860ab0a73adc9b9": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "c2a69a33b086364ca51b030b6b15e99be46ce8255ddf62839a4fc7f2b34023de": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "5cd62e708ae4393c99579ec1433571998299bf7e2fde9bafeb9a79f8bdf065e9": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "61b61dd25cd8dcc43cd78418f3e3eb3fd9002d9e49961eefb12c1022ce4c3b63": "Fake Payment SDK typosquat: malicious npm index.js (SHA256)",
  "c6af37a6739f0d919ab7049caf3a85831cab44bdbea27e0d9de7adec80334e2b": "Fake Payment SDK typosquat: malicious PyPI __init__.py (SHA256)",
  "b04daeacd1d1c9020cce2a97fa7af83dbedf4e6d17dd12c0f337f32240399785": "Fake Payment SDK typosquat: malicious PyPI __init__.py (SHA256)",
  "dabb47d75f2efa6a5540661484efa989ccb338f24938b23152f14f3e424b0cb5": "Fake Payment SDK typosquat: malicious PyPI __init__.py (SHA256)",
  "c2a361a7d8feb95be97c957fc7652d348f4fa9a987bde5f09883f46b65c460f1": "Fake Payment SDK typosquat: malicious PyPI __init__.py (SHA256)",

  // AsyncAPI npm compromise (Unit 42, July 2026). Two further artifacts beyond the five
  // registry tarballs already pinned above. Unit 42 published them in the campaign IOC
  // table without naming the individual file, so they carry a campaign-level label.
  // Single-source (Unit 42; Socket/StepSecurity published only the five tarballs).
  "73b44b8724d31f80859018c988e9b033155c5fd8225205a914eda1a11b78a841": "AsyncAPI compromise: additional campaign artifact (SHA256)",
  "f7367ce5509f536a406deecdbb577c60e8585cb2ab77058a86bde6188a609cfd": "AsyncAPI compromise: additional campaign artifact (SHA256)",

  // Joyfill npm compromise / DEV#POPPER, PolinRider family (Socket + StepSecurity,
  // July 28 2026). Five-stage chain: in-bundle obfuscated loader -> blockchain C2
  // resolver -> two staged downloaders -> Socket.IO RAT plus a staged Python
  // credential stealer. Only the two stages StepSecurity named individually carry
  // a specific label; the rest are the campaign artifact set Socket published
  // without per-file names, so they get a campaign-level description.
  "26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18": "Joyfill compromise: Socket.IO RAT final stage (SHA256)",
  "36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c": "Joyfill compromise: staged Python credential stealer (SHA256)",
  "adc4af90540d33cd1e98f44b51482ae9250fbeb97d6f8d7841c81b618cb2c6e6": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "8e8b90dedd456ded0c5748119836e1ca1066112bc569c1b41ca70eb931d1d4dc": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "5f6a92006ca2ea4b464d66fb41af777edce7296939a7c6ee491e2b3cbfe09848": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "bcc93dc55bc7daedf4ca57254f0e7a7f1c40e09851eab98fe10cde801982db17": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "1352ad22c99983d91e600348b7cbf58235131b1ee34cea9f09623206d5b7dea7": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "67c6ef602cc850f10d935fee53fa40440df841adf081563bf4fc2631a71249ce": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "c5742ea1875ecd2360022624149994909cd0546e221e4203dffd01f48de45469": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "f452f9cfa539f4a1fe25187a99a484391290d5dbaa422ba455edf6b04f81b7d1": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "78f0de8682e0e894a5784eb7e95db4da6088f528918ca3107dd1e76f80a561d8": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "ae7565109fd01b88d82acf7f73ab20709cbc2c9f26fdea13e429ccc87a55d4fb": "Joyfill compromise: DEV#POPPER decoded detached bootstrap (SHA256)",
  "26e679eaf1e9baeb7c55eb48db482301171d4d26e1728544b23734a90dc70e1b": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",
  "2cfede38fb121a71a2f3607474aa8cd588a99f51b37e5e6f0d8cb789fa275032": "Joyfill compromise: DEV#POPPER campaign artifact (SHA256)",

  // mrmustard PyPI compromise (safedep, July 2026). The two poisoned 0.7.4 artifacts. The
  // malicious code was injected into the published artifacts only - the GitHub source was
  // left clean - so the release hash is the indicator that the repository cannot give you.
  // Both were checked against every artifact of every mrmustard release still on PyPI (24
  // files, 13 versions) and collide with none, so a clean install cannot trip these.
  "0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb": "mrmustard 0.7.4 poisoned sdist (SHA256)",
  "81f0d1291a975d012d1b892cf9967557fdbb1ad4e1ac0545702ad235ace1cac5": "mrmustard 0.7.4 poisoned wheel (SHA256)",

  // ChainDrop npm worm / "Mini Shai-Hulud" (August 4 2026). The two dropper hashes are the
  // setup.mjs run by the injected `"preinstall": "node setup.mjs"` hook - one per wave, the
  // second appearing once the worm started republishing from other accounts. The stage-2
  // hash covers the 727,680-byte payload shipped under two names (Math_Symbol.js and
  // math_init.js), which are byte-identical, so one hash catches both. All three were
  // published identically by StepSecurity, Aikido, Socket and Endor Labs.
  "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668": "ChainDrop setup.mjs preinstall dropper, wave 1 (SHA256)",
  "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb": "ChainDrop setup.mjs preinstall dropper, later waves (SHA256)",
  "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc": "ChainDrop stage-2 credential stealer, Math_Symbol.js / math_init.js (SHA256)",
  // A third dropper variant, catalogued by Unit 42 as "setup.mjs.malicious" - the
  // quarantined copy of the same preinstall dropper, distinct from both waves above.
  // Single-source (Unit 42): no other vendor has published it, so the feed entry
  // carries a reduced confidence. The digest round-tripped as a well-formed 64-char
  // hex string and was re-confirmed by exact-string search before ingest, which is
  // what a fetched hash needs before it can be trusted.
  "b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678": "ChainDrop setup.mjs preinstall dropper, third variant / setup.mjs.malicious (SHA256)",
  // Later re-obfuscation waves and the two auxiliary components, published by
  // Datadog and corroborated one by one via exact-string search (op-c.net's
  // ChainDrop IOC list carries the first three; the runner memory dumper also
  // appears in the Aikido/Snyk SAP write-ups and the FBI FLASH-20260702-01, and
  // the zZ.bin loader in SlowMist's @redhat-cloud-services analysis). The worm
  // re-obfuscates between waves, so these complement rather than replace the
  // behavioural rules.
  "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f": "ChainDrop IDE persistence hook dropped as .vscode/tasks.json (SHA256)",
  "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128": "ChainDrop stage-2 credential stealer, re-obfuscated wave (SHA256)",
  "3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7": "ChainDrop deobfuscating loader, zZ.bin (SHA256)",
  "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7": "ChainDrop embedded GitHub Actions Runner.Worker memory dumper (SHA256)",
  // Distribution artefact rather than a payload file: the hash of the published
  // keyv-6.0.0.tgz itself. keyv@6.0.0 is already version-pinned in
  // KNOWN_BAD_NPM_VERSIONS, so this only adds a second detection path for the
  // same release - it fires where the tarball digest is recorded as text (mirror
  // manifests, vendoring scripts, incident notes). Single-source: only Snyk
  // published it, and the two hashes above round-tripped byte-identical from the
  // same write-up, which is what corroborates the fetch.
  "d584f9b6af48b7ed1f93713944f033783bf149e1c25e1643eb8c0e9df5dc7782": "ChainDrop poisoned keyv-6.0.0.tgz distribution tarball (SHA256)",

  // GlassWASM trojanized Open VSX extensions (June 2026). One hash for the TinyGo WASM
  // stager (shipped under two random 16-letter names, snqpkebiwrxmoivl.wasm and
  // orybbbdsuqmaapel.wasm, which are byte-identical, so one hash catches both) and one
  // per published VSIX. Single-source: only Socket published the hashes, and Corgea
  // corroborates every other indicator of the campaign; each round-tripped as a well-formed
  // 64-char digest and the stager hash was re-confirmed by exact-string search.
  "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f": "GlassWASM TinyGo WebAssembly stager, snqpkebiwrxmoivl.wasm / orybbbdsuqmaapel.wasm (SHA256)",
  "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58": "GlassWASM trojanized noellee-doc.flint-debug 0.1.1 VSIX (SHA256)",
  "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25": "GlassWASM trojanized ExarGD.vsblack 0.0.1 VSIX (SHA256)",

  // Flooding Dropper / WEL1DROPPER stage-2 RAT binaries (OpenSourceMalware, August 7 2026).
  // Single-source for the hashes themselves; the campaign's package families and Worker
  // hosts are corroborated by Sonatype and Unit 42. Both round-tripped as well-formed
  // 64-char digests and the Linux one was re-confirmed by exact-string search.
  "7e486657f30594afda379b97030252a09a19fe8055e25c9e371544f59bd8e9e3": "Flooding Dropper WEL1DROPPER stage-2 payload, Linux x86-64 (SHA256)",
  "c214746c74cae8ece8bdaf69aa05da4db6ce013f9e77452d1eed1a002fd9ba00": "Flooding Dropper WEL1DROPPER stage-2 payload, macOS universal (SHA256)",

  // axios maintainer account takeover - UNC1069 / "Sapphire Sleet" cross-platform RAT
  // (Aikido + LevelBlue, March 31 2026). The axios and plain-crypto-js versions were
  // already pinned; these are the dropped per-platform implants, which the advisory
  // databases never publish. Each round-tripped as a well-formed 64-char digest and the
  // macOS one was re-confirmed by exact-string search.
  "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a": "axios/UNC1069 RAT, macOS /Library/Caches/com.apple.act.mond (SHA256)",
  "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101": "axios/UNC1069 RAT, Windows %PROGRAMDATA%\\wt.exe (SHA256)",
  "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf": "axios/UNC1069 RAT, Linux /tmp/ld.py (SHA256)",

  // TeamPCP telnyx wave (March 27, 2026). Every hash below was reproduced
  // character-for-character by two independent write-ups (Endor Labs and Hexastrike)
  // before ingestion.
  "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9": "TeamPCP telnyx 4.87.1 wheel, telnyx-4.87.1-py3-none-any.whl (SHA256)",
  "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3": "TeamPCP telnyx 4.87.2 wheel, telnyx-4.87.2-py3-none-any.whl (SHA256)",
  "23b1ec58649170650110ecad96e5a9490d98146e105226a16d898fbe108139e5": "TeamPCP telnyx backdoored telnyx/_client.py, version 4.87.1 (SHA256)",
  "ab4c4aebb52027bf3d2f6b2dcef593a1a2cff415774ea4711f7d6e0aa1451d4e": "TeamPCP telnyx backdoored telnyx/_client.py, version 4.87.2 (SHA256)",

  // Mini Shai-Hulud / Miasma "Hades" PyPI wave (Socket, June 8, 2026). Digests of the
  // langchain-core-mcp artifacts: the distributed wheel and the langchain_core-setup.pth
  // startup hook it installs. Both were re-verified as exact strings against the source
  // before ingestion, but the two extractions of that page disagreed about which digest
  // belongs to which of the two files, so they are labelled by campaign rather than
  // asserting a per-file mapping that only one reading supports. The package@version
  // pins already cover a registry install; these catch a vendored or mirrored copy.
  "6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9": "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: langchain-core-mcp 1.4.2 artifact, wheel or .pth startup hook (SHA256)",
  "6506d31707a39949f89534bf9705bcf889f1ecae3dbc6f4ff88d67a8be3d01b2": "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: langchain-core-mcp 1.4.2 artifact, wheel or .pth startup hook (SHA256)",
  // arrayref / proc-macro1 crates.io build-time dropper (August 2026). The .crate
  // artifacts themselves. The cargo: package@version pins already cover a registry
  // install, so these catch a vendored, mirrored or offline copy. Each digest was
  // re-verified character-for-character against two independent write-ups
  // (StepSecurity, Wiz) after a third extraction returned a corrupted, non-hex
  // rendering of the 1.0.106 digest.
  "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae": "arrayref 0.3.10 poisoned .crate artifact, build-time dropper (SHA256)",
  "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4": "proc-macro1 1.0.107 .crate artifact, build-time dropper (SHA256)",
  "b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436": "proc-macro1 1.0.106 .crate artifact, build-time dropper (SHA256)",
};

// ---------------------------------------------------------------------------
// Known malicious GitHub accounts
// ---------------------------------------------------------------------------

export const KNOWN_MALICIOUS_GITHUB_ACCOUNTS: string[] = [
  "idbzoomh",
  "idbzoomh1",
  "my3jie",

  // BufferZoneCorp sleeper Go modules / poisoned Ruby gems (May 2026)
  "BufferZoneCorp",

  // TeamPCP / Mr_Rot13 - Checkmarx Jenkins AST plugin compromise + cPanel CVE-2026-41940 (May 2026)
  "Mr_Rot13",
  "TeamPCP",

  // Mini Shai-Hulud TanStack wave staging forks (May 2026)
  "voicproducoes",
  "zblgg",

  // Phantom Bot DDoS + Shai-Hulud clone npm infostealer publisher (May 2026)
  "deadcode09284814",

  // Packagist 8-package Linux binary supply-chain attack (May 23, 2026)
  // Attacker pushed dev-branch commits to 8 Composer packages whose package.json
  // postinstall scripts pull a Linux ELF binary (gvfsd-network) from this account's
  // GitHub Releases to /tmp/.sshd. Account removed but still referenced in package
  // manifests of compromised dev branches.
  "parikhpreyash4",

  // TrapDoor cross-ecosystem credential stealer (May 25, 2026)
  // Single actor maintaining 34+ malicious packages across npm/PyPI/Crates.io
  // and a GitHub Pages dead-drop at ddjidd564.github.io.
  "ddjidd564",

  // Polymarket impersonation npm publisher (May 22, 2026)
  // 9 typosquats of Polymarket SDK with wallet-key exfiltration.
  "polymarketdev",

  // Megalodon GitHub Actions workflow injection throwaways (May 22, 2026)
  // Throwaway accounts pushed 5,718 workflow-injection commits to 5,561 repos in
  // ~6 hours, forging author identities like build-bot / auto-ci / ci-bot / pipeline-bot.
  "rkb8el9r",
  "bhlru9nr",
  "lo6wt4t6",

  // Malware-Slop npm infostealer mouse5212-super-formatter (OX Security via THN, May 27, 2026)
  // Throwaway account created May 26, 2026 (hours before first malicious publish); the npm
  // package authenticates to GitHub and recursively uploads /mnt/user-data (Claude AI user
  // directory) files into attacker-created repos under this account. Account now removed.
  "unplowed3584",

  // codexui-android npm token stealer publisher (Aikido, May 27, 2026)
  // GitHub identity behind the malicious codex-mobile / codexui-android project. Also
  // operates under the "BrutalStrike" handle (5M+ install Android FPS game uses shared
  // infrastructure). Listed for source-code references to the project repo.
  "friuns2",
  "BrutalStrike",

  // Sicoob.Sdk NuGet impersonation + vpmdhaj npm cloud-secret stealers (Socket via THN, May 28-29, 2026)
  // Sicoob-Cooperativa is a GitHub org spun up to lend legitimacy to the fake Sicoob
  // banking SDK NuGet package; joaobcdev is the listed contributor; the 14 sibling
  // npm packages were published under the npm account "vpmdhaj" (a39155771@gmail.com)
  // and used the X-Secret HTTP header "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1" for C2 auth.
  "Sicoob-Cooperativa",
  "joaobcdev",

  // SStar Agent fake "smart contract engineer" job lure (THN ThreatsDay Bulletin, June 11, 2026)
  // Social-engineering / contagious-interview style lure: a GitHub repo
  // star45674/smart-contract-engineer-role poses as a coding assignment whose
  // npm dependency tw-style-utils deploys the cross-platform SStar Agent RAT
  // (Windows + macOS). Account tracked for repo references in lure assignments.
  "star45674",

  // Malicious Android APK host (THN ThreatsDay Bulletin, June 11, 2026)
  // GitHub account antoniocastaldo1998 hosts a malicious Android APK in its
  // app-scuola repository, pulled down by a separate dropper chain.
  "antoniocastaldo1998",

  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // Compromised npm maintainer account "ehindero" (forgotten contributor with publish
  // rights across the @mastra scope) republished 141 packages with the malicious
  // easy-day-js dependency; "sergey2016" is the linked attacker-controlled account.
  // npm publisher handles, tracked here for source-reference matching.
  "ehindero",
  "sergey2016",

  // Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026)
  // "czirker" is the compromised LeoPlatform npm maintainer account used to republish the
  // leo-* / rstreams-* / serverless-leo / hexo-* packages with a preinstall stealer. npm
  // publisher handle tracked here for source-reference matching (github.com/czirker).
  "czirker",

  // PolinRider DPRK supply-chain campaign (Socket / The Hacker News / SecurityWeek, July 2026)
  // North-Korea-linked cluster (Contagious Interview / Famous Chollima) that poisoned 108
  // packages/extensions (162 release artifacts) across npm, Packagist, Go modules and Chrome
  // to deliver the DEV#POPPER RAT + OmniStealer via obfuscated JS loaders (fake .woff2 fonts
  // run from VS Code tasks; second stages fetched over TRON/Aptos/BNB RPC + XOR-decrypted eval).
  // "Xpos587" is the compromised GitHub account behind the malicious Go module git2md; tracked
  // here for source-reference matching. The broader "7span"/"sevenspan" and "Artiffusion-Inc"
  // accounts are NOT blocked to avoid false positives on their legitimate, non-weaponized repos.
  "Xpos587",

  // NeoShadow npm supply-chain attack (Aikido, 2026-01-05)
  // "cjh97123" is the npm publisher account that shipped all four typosquats (viem-js,
  // cyrpto, tailwin, supabase-js). Account is attacker-created, not a compromised victim.
  // npm publisher handle, tracked here for source-reference matching.
  "cjh97123",

  // SANDWORM_MODE / "Echoes of Shai-Hulud" npm worm (Socket + OX Security, 2026-02-20)
  // "official334" is both the npm publisher alias and the Cloudflare Workers account behind
  // the C2 subdomain; "javaorg" is the second publisher alias. "ci-quality" is the
  // attacker-created GitHub account whose ci-quality/code-quality-check@v1 Action is injected
  // into victim workflows to re-steal CI secrets. All three are attacker-created, not victims.
  "official334",
  "javaorg",
  "ci-quality",

  // Alibaba developer toolchain RAT (Socket, July 2026)
  // "smi1e2u" is the attacker-created GitHub account hosting the config the dependency
  // chain fetches and saves as .cloud-preferences.json, in the repositories
  // fast-transform-pipeline and smart-config-manager (both also published as npm
  // packages in the same campaign). Attacker-created, not a compromised victim.
  "smi1e2u",

  // GlassWASM trojanized Open VSX extensions (Socket + Corgea, June 2026)
  // "zaitoona43" is the single Open VSX publisher account that uploaded both trojanized
  // clones (ExarGD.vsblack 0.0.1 on 2026-06-09, noellee-doc.flint-debug 0.1.1 on
  // 2026-06-10); the matching GitHub account was three days old at publication time.
  // Attacker-created, not a compromised victim. The impersonated upstream publishers
  // "ExarGD" and "noellee-doc" are the VICTIMS here and are deliberately NOT listed.
  "zaitoona43",

  // TeamPCP - account used to create and delete a ghost branch on
  // aquasecurity/trivy-plugin-aqua, then to deface the aquasec-com org about seven
  // hours later; the pivot that preceded the litellm and telnyx pushes.
  // The compromised upstream maintainers are VICTIMS and are not listed.
  "Argon-DevOps-Mgt",

  // @velliajs/discord npm malware (OpenSSF malicious-packages via amazon-inspector,
  // August 2026). "navaLinh" hosts the unpinned private git repository the package
  // installs its `sysframe` dependency from; "Vellia-Elyvia" hosts the remote
  // allow-list that gates the bot at runtime. Both accounts are attacker-created,
  // not compromised victims. Single-source, so the matching feed entries carry
  // confidence 0.85.
  "navaLinh",
  "Vellia-Elyvia",
];

// ---------------------------------------------------------------------------
// Known C2 / operator blockchain wallet and contract addresses
// ---------------------------------------------------------------------------

/**
 * Blockchain addresses used as malware command-and-control or as the operator
 * wallet of a campaign.
 *
 * MATCHING IS EXACT-LITERAL, DELIBERATELY. There is no shape or prefix matcher
 * here and there must never be one: a bare "0x" followed by 64 hex characters
 * is indistinguishable from an Ethereum transaction hash, a keccak256 digest,
 * or a Hardhat/Foundry test fixture, so a shape rule would flag legitimate web3
 * repositories on sight. Only addresses actually published by a threat report
 * belong in here.
 *
 * Aptos addresses are stored WITHOUT the "0x" prefix so that a source file
 * building one by concatenation ("0x" + hex) still matches on the hex body.
 */
export const KNOWN_C2_WALLETS: Record<string, string> = {
  // ViteVenom / ChainVeil - four-tier blockchain C2 (Checkmarx Zero, June-July 2026).
  // Tier-2 addresses shared between both waves of the campaign; OpenSourceMalware
  // ties them to the DPRK/Lazarus PolinRider cluster via matching XOR keys.
  TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP:
    "ViteVenom/ChainVeil Tron tier-2 C2 wallet (July 2026)",
  TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG:
    "ViteVenom/ChainVeil Tron tier-2 C2 wallet (July 2026)",
  be037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e:
    "ViteVenom/ChainVeil Aptos tier-2 C2 account (July 2026)",

  // Joyfill npm compromise / DEV#POPPER (Socket + StepSecurity, July 28 2026).
  // Socket designates this wave PolinRider-family and it re-uses the two Tron
  // tier-2 wallets already pinned above, which independently corroborates the
  // ViteVenom/ChainVeil linkage. These are the addresses that wave added. The
  // loader reads its live C2 address out of transactions against them, so the
  // addresses are the durable indicator while the C2 IPs rotate.
  TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v:
    "Joyfill/DEV#POPPER Tron C2 resolver wallet (July 2026)",
  "3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3":
    "Joyfill/DEV#POPPER Aptos C2 resolver account (July 2026)",
  "533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1":
    "Joyfill/DEV#POPPER Aptos C2 resolver account (July 2026)",
  "18a8420f727f2405f9d1805ad887b31029b584b2ff5a7ec0f57c72635183e99d":
    "Joyfill/DEV#POPPER Aptos C2 resolver account (July 2026)",
  "7ffb4efddd96e20aec90724be2ac9a71c138a9af697b9fb8224bbf80ea4f22be":
    "Joyfill/DEV#POPPER Aptos C2 resolver account (July 2026)",
  b6c725890be6890fd2c735eedc47e24b85a350301f6c19a3864e43c35e470968:
    "Joyfill/DEV#POPPER Aptos C2 resolver account (July 2026)",
  "9bc1355344b54dedf3e44296916ed15653844509":
    "Joyfill/DEV#POPPER BNB Smart Chain C2 resolver contract (July 2026)",

  // ChainDrop npm worm / "Mini Shai-Hulud" (August 4 2026). Ethereum mainnet contract the
  // stage-2 payload reads (function selector 0x53ed5143) to resolve its current exfil
  // domain, so the C2 host can be rotated without republishing the package. The RPC
  // provider the payload reaches it through is a legitimate public Ethereum endpoint and is
  // deliberately NOT listed - only the attacker's own contract is.
  "0xE1f2395ee43e45A1556EC6438a88c31B83493103":
    "ChainDrop Ethereum mainnet dead-drop C2 resolver contract (August 2026)",

  // GlassWASM trojanized Open VSX extensions (Socket + Corgea, June 2026). The WASM stager
  // polls Solana mainnet for transactions sent to this attacker-controlled address and reads
  // its commands out of the SPL Memo field, so the blockchain is the dead-drop. Only the
  // attacker address is listed: the two SPL Memo program ids the transactions carry are
  // Solana system programs used by every legitimate memo on the network, and the public
  // mainnet JSON-RPC endpoint is shared infrastructure - listing either would flag ordinary
  // Solana code.
  "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz":
    "GlassWASM Solana dead-drop C2 wallet, commands carried in SPL Memo (June 2026)",

  // NullReceiver / DPRK "Contagious Interview" npm wave (OpenSourceMalware,
  // 2026-08-05; corroborated by Sonatype Research Labs, 2026-08-10). The loader
  // queries Ethereum for the attacker wallet's latest OUTBOUND transfer and reads
  // the C2 IP straight out of the recipient address of a zero-value, zero-data
  // transaction, so nothing is ever written to transaction data and there is no
  // contract to look at. Both halves of that pair are listed: the wallet is what
  // the payload hardcodes, the recipient is what the technique is named for.
  //
  // The recipient address self-verifies against the C2 IP already pinned in
  // KNOWN_C2_IPS: its first four bytes a6-58-86-3e decode to 166[.]88[.]134[.]62,
  // and the trailing bytes 68656c6c6f6970626f742121 are ASCII "helloipbot!!".
  //
  // The two public Ethereum RPC endpoints the payload reads through (1rpc[.]io and
  // eth[.]drpc[.]org) are shared infrastructure and are deliberately NOT listed, for
  // the same reason as the ChainDrop entry above.
  "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a":
    "NullReceiver DPRK npm wave: hardcoded attacker wallet whose outbound transfer carries the C2 address (August 2026)",
  "0xa658863ea658863e68656c6c6f6970626f742121":
    "NullReceiver DPRK npm wave: dead-drop recipient address encoding C2 IP 166.88.134.62 plus the ASCII tag helloipbot!! (August 2026)",
};

/**
 * Runtime floor on wallet entries.
 *
 * This is enforced at module load rather than only in a unit test, because the
 * realistic ingest mistake is a SHORT address: Aptos renders its framework
 * accounts as "0x1" / "0x3", and a 1-to-3 character literal substring-matched
 * against every scanned file would flag essentially every repository. A test
 * asserting "at least 12 distinct characters" does not catch a 3-char value
 * that was never added to the test's fixture list.
 */
for (const [address, description] of Object.entries(KNOWN_C2_WALLETS)) {
  const body = address.startsWith("0x") ? address.slice(2) : address;
  if (body.length < 32) {
    throw new Error(
      `KNOWN_C2_WALLETS entry "${address}" is too short (${body.length} chars, minimum 32). ` +
        "Short-form addresses substring-match almost every file and must never be ingested.",
    );
  }
  if (new Set(body).size < 12) {
    throw new Error(
      `KNOWN_C2_WALLETS entry "${address}" has too few distinct characters and looks like a padded placeholder.`,
    );
  }
  if (!description) {
    throw new Error(`KNOWN_C2_WALLETS entry "${address}" is missing a description.`);
  }
  // A bare 64-hex address that is also a known malware hash would emit two
  // separate critical findings for a single string, since checkIOCBlocklist
  // runs its loops independently with no cross-loop dedupe.
  if (Object.prototype.hasOwnProperty.call(KNOWN_MALICIOUS_HASHES, body.toLowerCase())) {
    throw new Error(
      `KNOWN_C2_WALLETS entry "${address}" collides with a KNOWN_MALICIOUS_HASHES entry and would double-report.`,
    );
  }
}

/**
 * Lowercased lookup set for KNOWN_MALICIOUS_GITHUB_ACCOUNTS.
 *
 * The array above deliberately stores handles exactly as the reporting vendor
 * published them, because the content matcher prints them back in its finding
 * description. Every COMPARISON, though, must be case-insensitive: GitHub
 * logins are case-insensitive, so "TeamPCP" and "teampcp" are the same account.
 */
const MALICIOUS_ACCOUNT_SET: ReadonlySet<string> = new Set(
  KNOWN_MALICIOUS_GITHUB_ACCOUNTS.map((a) => a.toLowerCase()),
);

/**
 * Case-insensitive membership test for the malicious-account blocklist.
 *
 * This is the single normalization point. Comparing a lowercased owner against
 * the raw mixed-case array silently missed every mixed-case entry, so callers
 * must use this helper rather than `.includes()`.
 */
export function isKnownMaliciousAccount(owner: string): boolean {
  return MALICIOUS_ACCOUNT_SET.has(owner.trim().toLowerCase());
}

/**
 * Normalize a package name to its registry's own equivalence rule.
 *
 * PyPI treats names case-insensitively and collapses runs of "-", "_" and "."
 * into a single "-" (PEP 503), so "LiteLLM", "litellm" and "lite_llm" are one
 * project. Looking the raw parsed name up in the blocklist therefore missed
 * `LiteLLM==1.82.7` entirely.
 *
 * npm is deliberately NOT normalized: npm package names are case-sensitive at
 * the registry level, so lowercasing there could flag a legitimate package that
 * differs from a blocked one only by case. Widening a match is only safe when
 * the registry itself considers the two names identical.
 */
function normalizePackageName(
  name: string,
  ecosystem: "npm" | "pypi" | "ruby" | "composer" | "nuget" | "cargo" | "go" | "jenkins",
): string {
  if (ecosystem === "pypi") {
    return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
  }
  return name;
}

// ---------------------------------------------------------------------------
// Known compromised npm package versions
// ---------------------------------------------------------------------------

export const KNOWN_BAD_NPM_VERSIONS: Record<string, { versions: string[]; description: string }> = {
  // mgc npm account takeover - UNC1069 / "Sapphire Sleet" WAVESHAPER.V2 (safedep,
  // April 2026). A real CLI tool with three legitimate 2023 releases (1.0.0, 1.1.0,
  // 1.2.0) whose maintainer account was taken over, so this is version-pinned to the
  // four trojanized publishes only and the name is NOT added to any pattern table.
  // npm has since replaced the package with a security-holding stub, but a lockfile
  // pinned before the takedown still resolves to the malicious tarball.
  "mgc": {
    versions: ["1.2.1", "1.2.2", "1.2.3", "1.2.4"],
    description: "mgc account takeover: UNC1069 cross-platform RAT dropper (Apr 2026)",
  },

  // Second still-installable IOC recovered by hand from the 2026-08-14 advisory
  // backfill, this one from outside what --limit 250 can reach before it ages out.
  // A live package with 41 published versions and a real purpose; six of them are
  // flagged, so this is version-pinned and 1.2.35, 1.2.37 and 1.2.40 are not listed.
  "@zinley/orion": {
    versions: ["1.2.31", "1.2.32", "1.2.34", "1.2.36", "1.2.38", "1.2.39"],
    description: "@zinley/orion: malicious npm package versions (GHSA-jf8m-fw34-6mg8, Aug 2026)",
  },

  // Second detection path for the one still-installable IOC recovered by hand from the
  // 2026-08-14 advisory-backfill tail - see the matching feed entries in threat-intel.ts.
  // Pinned to the two versions the advisory names; 1.0.0, 1.0.1 and 1.1.0 are not flagged.
  "dakumangalsingh": {
    versions: ["1.2.0", "2.0.1"],
    description: "dakumangalsingh: malicious npm package versions (GHSA-h2fc-hhv7-4596, Aug 2026)",
  },

  // NullReceiver / DPRK "Contagious Interview" npm wave (Sonatype Research Labs,
  // 2026-08-10). A real multi-agent ACP client with 1,110 published versions whose
  // publisher was compromised, so this is version-pinned to the single trojanized
  // release and the name is NOT added to any pattern table. 1.0.1127 happens to be
  // the current `latest` tag, which is exactly why a name block would be wrong: the
  // 1,109 releases before it are clean and still resolve for anyone on a range.
  "agentgui": {
    versions: ["1.0.1127"],
    description: "agentgui publisher compromise: NullReceiver Ethereum-resolved C2 loader (Aug 2026)",
  },
  "ua-parser-js": {
    versions: ["0.7.29", "0.8.0", "1.0.0"],
    description: "ua-parser-js hijack: crypto miner + credential stealer (Oct 2021)",
  },
  "coa": {
    versions: ["2.0.3", "2.0.4"],
    description: "coa npm hijack: sdd.dll trojan payload (Nov 2021)",
  },
  "rc": {
    versions: ["1.2.9", "1.3.9", "2.3.9"],
    description: "rc npm hijack: sdd.dll trojan payload (Nov 2021)",
  },
  "event-stream": {
    versions: ["3.3.6"],
    description: "event-stream: flatmap-stream backdoor targeting copay wallet (Nov 2018)",
  },
  "axios": {
    versions: ["1.14.1", "0.30.4"],
    description: "axios hijack: embedded RAT (plain-crypto-js) (March 2026)",
  },
  "colors": {
    versions: ["1.4.1", "1.4.2"],
    description: "colors.js protestware: infinite loop (Jan 2022)",
  },
  "faker": {
    versions: ["6.6.6"],
    description: "faker.js protestware: infinite loop + data wipe (Jan 2022)",
  },
  "node-ipc": {
    versions: ["9.1.6", "9.2.3", "10.1.1", "10.1.2", "10.1.3", "12.0.1"],
    description: "node-ipc supply chain attacks: 9.1.6/9.2.3/12.0.1 credential stealer via maintainer email hijack with DNS exfiltration (May 2026); 10.1.x protestware (Mar 2022)",
  },
  "@bitwarden/cli": {
    versions: ["2026.4.0"],
    description: "Bitwarden CLI hijack: bw_setup.js/bw1.js credential stealer linked to Checkmarx KICS breach (April 2026)",
  },
  "@cap-js/sqlite": {
    versions: ["2.2.2"],
    description: "Mini Shai-Hulud / TeamPCP: SAP CAP npm hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "@cap-js/postgres": {
    versions: ["2.2.2"],
    description: "Mini Shai-Hulud / TeamPCP: SAP CAP npm hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "@cap-js/db-service": {
    versions: ["2.10.1"],
    description: "Mini Shai-Hulud / TeamPCP: SAP CAP npm hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "mbt": {
    versions: ["1.2.48"],
    description: "Mini Shai-Hulud / TeamPCP: SAP MTA build tool hijack with preinstall hook + Bun-based credential stealer (April 2026)",
  },
  "intercom-client": {
    versions: ["7.0.4"],
    description: "Mini Shai-Hulud / TeamPCP: intercom-client npm hijack with preinstall hook + credential stealer (April 2026)",
  },
  "@opensearch-project/opensearch": {
    versions: ["3.5.3", "3.6.2", "3.7.0", "3.8.0"],
    description: "Mini Shai-Hulud / TeamPCP: OpenSearch npm client hijack with worm payload (May 2026)",
  },
  "@squawk/mcp": {
    versions: ["0.9.5"],
    description: "Mini Shai-Hulud / TeamPCP: Squawk MCP server hijack with worm payload (May 2026)",
  },
  "@squawk/weather": {
    versions: ["0.5.10"],
    description: "Mini Shai-Hulud / TeamPCP: Squawk weather hijack with worm payload (May 2026)",
  },
  "@squawk/flightplan": {
    versions: ["0.5.6"],
    description: "Mini Shai-Hulud / TeamPCP: Squawk flightplan hijack with worm payload (May 2026)",
  },
  "@tallyui/connector-medusa": {
    versions: ["1.0.1", "1.0.2", "1.0.3"],
    description: "Mini Shai-Hulud / TeamPCP: TallyUI Medusa connector hijack (May 2026)",
  },
  "@tallyui/connector-vendure": {
    versions: ["1.0.1", "1.0.2", "1.0.3"],
    description: "Mini Shai-Hulud / TeamPCP: TallyUI Vendure connector hijack (May 2026)",
  },
  "postmark-mcp": {
    versions: ["1.0.16"],
    description: "postmark-mcp hostile MCP server: developer-introduced hidden BCC of every outbound email to attacker-controlled address; 1.0.15 and earlier are clean (Sep 2025)",
  },
  // --- Mini Shai-Hulud @antv wave (May 19, 2026) -------------------------------
  // Compromised npm maintainer account "atool"; 637 versions across 317 packages
  // published 01:39-02:18 UTC on 2026-05-19. Payload: 498KB obfuscated Bun index.js
  // exfiltrating to t.m-kosche.com. Versions below per Aikido + Snyk analysis.
  "@antv/g2": {
    versions: ["5.5.8", "5.6.8"],
    description: "Mini Shai-Hulud / TeamPCP: @antv ecosystem npm hijack via atool maintainer account (May 2026)",
  },
  "@antv/g6": {
    versions: ["5.2.1", "5.3.1"],
    description: "Mini Shai-Hulud / TeamPCP: @antv ecosystem npm hijack via atool maintainer account (May 2026)",
  },
  "echarts-for-react": {
    versions: ["3.1.7", "3.2.7"],
    description: "Mini Shai-Hulud / TeamPCP: echarts-for-react hijack via atool maintainer account (May 2026)",
  },
  "timeago.js": {
    versions: ["4.1.2", "4.2.2"],
    description: "Mini Shai-Hulud / TeamPCP: timeago.js hijack via atool maintainer account (May 2026)",
  },
  "codexui-android": {
    versions: ["0.1.82", "0.1.83", "0.1.84", "0.1.85", "0.1.86", "0.1.87", "0.1.88", "0.1.89", "0.1.90"],
    description: "codexui-android: OpenAI Codex auth-token stealer; XOR (key 'anyclaw2026') + base64 POST to sentry.anyclaw.store/startlog (Aikido, disclosed May 2026)",
  },
  // --- Miasma / @redhat-cloud-services Mini Shai-Hulud variant (June 1, 2026) -----
  // 32 packages, 96 versions trojanized via compromised Red Hat employee GitHub
  // account abusing a GitHub Actions workflow. Payload "Miasma: The Spreading
  // Blight" - preinstall runs ~4.2 MB index.js, exfils CI/cloud creds to ~309
  // attacker-controlled GitHub repos. Only the package@version pair confirmed by
  // Socket is recorded here; the @redhat-cloud-services namespace itself is NOT
  // blocked, the clean upstream versions remain legitimate.
  "@redhat-cloud-services/chrome": {
    versions: ["2.3.1"],
    description: "Mini Shai-Hulud variant 'Miasma: The Spreading Blight': trojanized @redhat-cloud-services/chrome with preinstall credential stealer; Red Hat employee GitHub account compromise + GitHub Actions abuse (BleepingComputer + Socket.dev, June 2026)",
  },
  // --- Arch Linux AUR mass hijack npm dropper (June 12, 2026) ---------------------
  // 400+ Arch User Repository packages had their build scripts rewritten to pull and run
  // the malicious npm package atomic-lockfile, which installs a credential stealer + eBPF
  // rootkit on any machine that builds them. Version 1.4.2 was published 2026-06-10 and
  // removed by npm security 2026-06-12 (superseded by the 0.0.1-security holding
  // placeholder). Confirmed by The Hacker News + BleepingComputer and the npm registry.
  "atomic-lockfile": {
    versions: ["1.4.2"],
    description: "Arch Linux AUR mass-hijack npm dropper: atomic-lockfile@1.4.2 installs a credential stealer + eBPF rootkit via AUR build-script preinstall hooks; pulled by npm security 2026-06-12 (The Hacker News + BleepingComputer, June 2026)",
  },
  // --- Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026) ----
  // Forgotten-contributor npm account "ehindero" was compromised and used to republish
  // 141 packages across the @mastra scope (01:12-02:36 UTC, 2026-06-17), each gaining a
  // single new dependency: easy-day-js, a dayjs clone whose postinstall hook disables TLS
  // verification, contacts attacker C2 (23.254.164.92:8000), downloads and detaches a
  // cross-platform Node.js crypto-stealer RAT (166 wallet-extension inventory + browser
  // history harvest). Microsoft attributes to Sapphire Sleet/BlueNoroff (also behind the
  // April 2026 axios hijack). easy-day-js@1.11.21 is the clean precursor; only 1.11.22 is
  // malicious. Representative subset of the 143 compromised package@version pairs recorded.
  "easy-day-js": {
    versions: ["1.11.22"],
    description: "Mastra npm scope takeover (Sapphire Sleet/BlueNoroff, DPRK): dayjs clone whose postinstall hook drops a cross-platform Node.js crypto-stealer RAT (disables TLS verify, C2 23.254.164.92); injected as a dependency into 143 republished @mastra packages via compromised maintainer 'ehindero' (June 2026)",
  },
  "@mastra/core": {
    versions: ["1.42.1"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/agent-builder": {
    versions: ["1.0.42"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/auth": {
    versions: ["1.0.3"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/claude": {
    versions: ["1.0.3"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/express": {
    versions: ["1.3.31"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "@mastra/openai": {
    versions: ["1.0.2"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "mastra": {
    versions: ["1.13.1"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  "create-mastra": {
    versions: ["1.13.1"],
    description: "Mastra npm scope takeover (Sapphire Sleet, DPRK): republished with malicious easy-day-js dependency dropping a crypto-stealer RAT (June 2026)",
  },
  // --- NastyC2 npm framework (THN ThreatsDay Bulletin, June 18, 2026) ------------------
  // Three fully malicious npm packages bundling NastyC2, a Rust post-exploitation implant
  // implementing 80+ commands (credential harvesting, Active Directory attacks, container
  // escape, cloud-metadata theft, fileless execution).
  "node-ci-utils": {
    versions: ["2.1.4"],
    description: "NastyC2 npm framework: Rust post-exploitation implant (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata theft, fileless execution) (THN ThreatsDay, June 2026)",
  },
  "win-env-setup": {
    versions: ["3.0.6"],
    description: "NastyC2 npm framework: Rust post-exploitation implant (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata theft, fileless execution) (THN ThreatsDay, June 2026)",
  },
  "macos-ci-utils": {
    versions: ["1.0.0"],
    description: "NastyC2 npm framework: Rust post-exploitation implant (80+ commands: credential harvesting, AD attacks, container escape, cloud-metadata theft, fileless execution) (THN ThreatsDay, June 2026)",
  },
  // --- crypto-javascript cross-ecosystem worm (THN ThreatsDay Bulletin, June 18, 2026) -
  // Self-propagating supply-chain worm spreading across Rust/Cargo, Python, CMake, and npm
  // ecosystems; drops a Monero cryptominer and the "Dirty Frag" Linux kernel LPE exploit.
  // GCC build timestamp 2026-04-30. Version-pinned (common-sounding name).
  "crypto-javascript": {
    versions: ["4.2.5"],
    description: "Cross-ecosystem supply-chain worm (Rust/Cargo/Python/CMake/npm): bundles a Monero cryptominer + 'Dirty Frag' Linux kernel LPE exploit (THN ThreatsDay, June 2026)",
  },
  // --- Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026) ---
  // Latest evolution of the Mini Shai-Hulud / Miasma / Hades worm family. The compromised
  // npm maintainer account "czirker" (LeoPlatform) republished the LeoPlatform / RStreams
  // SDK packages plus hexo-* plugins with a preinstall stealer; the worm also propagated to
  // the Go ecosystem (github.com/verana-labs/verana-blockchain@v0.10.1-dev.20, recorded in
  // BUNDLED_FEED) and abused the codfish/semantic-release-action GitHub Action. Exfil into
  // ~559 dead-drop repos with description "Alright Lets See If This Works"; token-relay
  // marker "RevokeAndItGoesKaboom". Only the confirmed package@version pairs are pinned;
  // the clean upstream versions of these packages remain legitimate.
  "leo-sdk": {
    versions: ["6.0.19"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-sdk republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-streams": {
    versions: ["2.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-streams republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-auth": {
    versions: ["4.0.6"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-auth republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-aws": {
    versions: ["2.0.4"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-aws republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cache": {
    versions: ["1.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cache republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cdk-lib": {
    versions: ["0.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cdk-lib republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cli": {
    versions: ["3.0.3"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cli republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-config": {
    versions: ["1.1.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-config republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-elasticsearch": {
    versions: ["2.0.6"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-elasticsearch republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-mongo": {
    versions: ["3.0.8"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-mongo republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-mysql": {
    versions: ["3.0.3"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-mysql republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-oracle": {
    versions: ["2.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-oracle republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-connector-redshift": {
    versions: ["3.0.6"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-connector-redshift republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-cron": {
    versions: ["2.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-cron republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "leo-logger": {
    versions: ["1.0.8"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): leo-logger republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "rstreams-metrics": {
    versions: ["2.0.2"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): rstreams-metrics republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "rstreams-shard-util": {
    versions: ["1.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): rstreams-shard-util republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "serverless-leo": {
    versions: ["3.0.14"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): serverless-leo republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "serverless-convention": {
    versions: ["2.0.4"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): serverless-convention republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "prism-silq": {
    versions: ["1.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): prism-silq republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "solo-nav": {
    versions: ["1.0.1"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): solo-nav republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "hexo-deployer-wrangler": {
    versions: ["1.0.4"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): hexo-deployer-wrangler republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  "hexo-shoka-swiper": {
    versions: ["0.1.10"],
    description: "Miasma LeoPlatform wave (Mini Shai-Hulud variant): hexo-shoka-swiper republished with preinstall credential stealer via compromised maintainer 'czirker' (The Hacker News, June 2026)",
  },
  // --- Injective Labs SDK npm compromise (July 8, 2026) ---------------------------
  // The Injective Labs SDK GitHub repo was compromised and its trusted-publisher
  // (OIDC) pipeline abused to publish @injectivelabs/sdk-ts@1.20.21 with "fake
  // telemetry" that captures wallet private keys + mnemonic seed phrases when SDK
  // key-generation/import functions run, base64-encodes them, and HTTPS-POSTs to
  // testnet.archival.chain.grpc-web.injective.network. Version 1.20.21 was also
  // pinned across 17 dependent @injectivelabs scoped packages (18 total; ~310
  // downloads before deprecation). Clean version: 1.20.23. All entries are
  // version-pinned - these are legitimate packages, only 1.20.21 is malicious.
  // Sources: The Hacker News, BleepingComputer, Socket, Aikido (July 2026).
  "@injectivelabs/sdk-ts": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: sdk-ts@1.20.21 captures wallet private keys + mnemonic seed phrases via fake telemetry, exfiltrates to testnet.archival.chain.grpc-web.injective.network; GitHub repo + OIDC trusted-publisher abuse. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/utils": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/networks": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/ts-types": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/exceptions": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-base": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-core": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-cosmos": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-private-key": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-evm": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-trezor": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-cosmostation": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-ledger": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-wallet-connect": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-magic": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-strategy": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-turnkey": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  "@injectivelabs/wallet-cosmos-strategy": {
    versions: ["1.20.21"],
    description: "Injective Labs SDK npm compromise: republished pinning the malicious @injectivelabs/sdk-ts@1.20.21 wallet-key stealer as a dependency. Clean: 1.20.23 (July 2026)",
  },
  // --- AsyncAPI npm supply-chain compromise (July 14, 2026) -----------------------
  // Five malicious versions across four packages in the @asyncapi namespace were
  // published to npm during a ~4h window on 2026-07-14 (07:10-11:18 UTC), delivering
  // a credential-stealing multi-stage botnet loader. The loader pulls a second stage
  // from IPFS and supports C2 over HTTP, Nostr relays, IPFS, BitTorrent DHT, libp2p
  // GossipSub, and an Ethereum smart contract. Reported by OX Security, SafeDep,
  // Socket, StepSecurity, Microsoft, Wiz and Aikido; all five versions have since
  // been unpublished. All entries are version-pinned - these are legitimate packages,
  // only the listed versions are malicious. Do NOT block the bare names.
  // Sources: The Hacker News, BleepingComputer (July 15, 2026).
  "@asyncapi/generator": {
    versions: ["3.3.1"],
    description: "AsyncAPI npm compromise: generator@3.3.1 delivers a credential-stealing multi-stage botnet loader (second stage from IPFS; multi-channel C2). Legitimate package - only 3.3.1 is malicious (July 2026)",
  },
  "@asyncapi/generator-helpers": {
    versions: ["1.1.1"],
    description: "AsyncAPI npm compromise: generator-helpers@1.1.1 delivers a credential-stealing multi-stage botnet loader (second stage from IPFS; multi-channel C2). Legitimate package - only 1.1.1 is malicious (July 2026)",
  },
  "@asyncapi/generator-components": {
    versions: ["0.7.1"],
    description: "AsyncAPI npm compromise: generator-components@0.7.1 delivers a credential-stealing multi-stage botnet loader (second stage from IPFS; multi-channel C2). Legitimate package - only 0.7.1 is malicious (July 2026)",
  },
  "@asyncapi/specs": {
    versions: ["6.11.2", "6.11.2-alpha.1"],
    description: "AsyncAPI npm compromise: specs@6.11.2 / 6.11.2-alpha.1 deliver a credential-stealing multi-stage botnet loader (second stage from IPFS; multi-channel C2). Legitimate package - only these versions are malicious (July 2026)",
  },

  // --- PhantomSync npm crypto-wallet stealer (Xygeni, July 15, 2026) -----------
  // SINGLE-SOURCE (Xygeni only). Generic blockchain-util names published by
  // solbuilder_io, each malicious at specific versions only (name-squat takeover
  // risk), so version-pinned. Steals ETH/BTC/Solana keys + BIP-39 seeds, exfil to
  // IPFS via Pinata, persists via cron/schtasks/launchd. IMPORTANT: base58-utils
  // 1.0.2 is NOT malicious - only 1.0.0/1.0.1/1.0.3 are.
  "base58-utils": {
    versions: ["1.0.0", "1.0.1", "1.0.3"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata. Malicious versions 1.0.0/1.0.1/1.0.3 (NOT 1.0.2)",
  },
  "abi-encode": {
    versions: ["1.0.0", "1.0.1", "1.0.2"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  "eth-dev": {
    versions: ["1.0.0", "1.0.1", "1.0.2"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  "arb-kit": {
    versions: ["1.0.0", "1.0.1"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  "layer2-sdk": {
    versions: ["1.0.0", "1.0.1"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  "solana-key-utils": {
    versions: ["1.0.0"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  "eth-wallet-helpers": {
    versions: ["1.0.0"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  "crypto-validate-lib": {
    versions: ["1.0.0"],
    description: "PhantomSync npm crypto-wallet stealer (single-source: Xygeni, July 2026): steals wallet keys + BIP-39 seeds, exfil to IPFS/Pinata",
  },
  // --- jscrambler npm supply-chain compromise (July 11, 2026) ---------------------
  // The jscrambler npm package (~15,800 weekly downloads) and four companion build
  // plugins were hijacked and republished with a native Rust infostealer. Versions
  // 8.14.0/8.16.0/8.17.0 carry a malicious preinstall hook; from 8.18.0 the attackers
  // dropped the hook and embedded a self-executing dropper in dist/index.js and
  // dist/bin/jscrambler.js. Payload runs on Windows/macOS/Linux, harvesting AWS/GCP/
  // Azure creds, crypto wallets, browser data and AI-tool configs, with persistence on
  // Windows/macOS. Socket flagged 8.14.0 within 6 minutes of publish; corroborated by
  // The Hacker News, OX Security and StepSecurity. All entries are version-pinned -
  // these are legitimate packages; last clean release is 8.13.0, fixed in 8.22.0.
  "jscrambler": {
    versions: ["8.14.0", "8.16.0", "8.17.0", "8.18.0", "8.20.0"],
    description: "jscrambler npm compromise: hijacked releases drop a native Rust infostealer via preinstall hook (8.14.0-8.17.0) or self-executing dropper in dist/ (8.18.0+); steals AWS/GCP/Azure creds, wallets, browser data, AI configs. Clean: 8.13.0 / 8.22.0 (Socket + The Hacker News, July 2026)",
  },
  "jscrambler-webpack-plugin": {
    versions: ["8.6.2"],
    description: "jscrambler npm compromise: companion build plugin republished with the same native infostealer chain as jscrambler@8.14.0+. Legitimate package - only 8.6.2 is malicious (July 2026)",
  },
  "gulp-jscrambler": {
    versions: ["8.6.2"],
    description: "jscrambler npm compromise: companion build plugin republished with the same native infostealer chain as jscrambler@8.14.0+. Legitimate package - only 8.6.2 is malicious (July 2026)",
  },
  "grunt-jscrambler": {
    versions: ["8.5.2"],
    description: "jscrambler npm compromise: companion build plugin republished with the same native infostealer chain as jscrambler@8.14.0+. Legitimate package - only 8.5.2 is malicious (July 2026)",
  },
  "jscrambler-metro-plugin": {
    versions: ["9.0.2"],
    description: "jscrambler npm compromise: companion build plugin republished with the same native infostealer chain as jscrambler@8.14.0+. Legitimate package - only 9.0.2 is malicious (July 2026)",
  },
  "@joyfill/components": {
    versions: ["4.0.0-rc24-2773-beta.4", "4.0.0-rc24-2773-beta.5", "4.0.0-rc24-2773-beta.6"],
    description: "Joyfill npm compromise / DEV#POPPER: malicious beta releases ship a five-stage chain ending in a Socket.IO RAT and a Python credential stealer; the loader runs on import, so --ignore-scripts does not stop it. Legitimate package - only these three 2773 betas are malicious (July 28, 2026)",
  },
  "@joyfill/layouts": {
    versions: ["0.1.2-2773.beta.0", "0.1.2-2773.beta.1", "0.1.2-2773.beta.2"],
    description: "Joyfill npm compromise / DEV#POPPER: malicious beta releases ship a five-stage chain ending in a Socket.IO RAT and a Python credential stealer; the loader runs on import, so --ignore-scripts does not stop it. Legitimate package - only these three 2773 betas are malicious (July 28, 2026)",
  },

  // ChainDrop npm worm / "Mini Shai-Hulud" (August 4 2026). Every package below is a
  // LEGITIMATE, long-standing project whose maintainer account was taken over, so each is
  // version-pinned to the single hijacked release rather than blocked by name. All of these
  // versions were published inside one 75-minute burst (09:31-10:45 UTC on 2026-08-04),
  // which is the worm's propagation window; each was confirmed to exist on the registry
  // with that publish timestamp before being ingested. Note keyv's "latest" tag still
  // points at 5.6.0 - the malicious 6.0.0 was never the default install.
  "keyv": {
    versions: ["6.0.0"],
    description: "ChainDrop npm worm: preinstall dropper fetches a Bun runtime and runs a 727KB credential stealer targeting npm/GitHub/AWS/Vault tokens, kubeconfigs and crypto wallets. Legitimate package (127M+ weekly downloads) - only 6.0.0 is malicious, latest remains 5.6.0 (August 4, 2026)",
  },
  "@keyv/redis": {
    versions: ["6.0.0"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 6.0.0 is malicious (August 4, 2026)",
  },
  "@keyv/sqlite": {
    versions: ["6.0.0"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 6.0.0 is malicious (August 4, 2026)",
  },
  "@keyv/mongo": {
    versions: ["6.0.0"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 6.0.0 is malicious (August 4, 2026)",
  },
  "cacheable": {
    versions: ["2.5.1"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 2.5.1 is malicious (August 4, 2026)",
  },
  "cacheable-request": {
    versions: ["13.0.20"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 13.0.20 is malicious (August 4, 2026)",
  },
  "cache-manager": {
    versions: ["7.2.10"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 7.2.10 is malicious (August 4, 2026)",
  },
  "@cacheable/memory": {
    versions: ["2.2.1"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 2.2.1 is malicious (August 4, 2026)",
  },
  "@cacheable/node-cache": {
    versions: ["3.1.2"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 3.1.2 is malicious (August 4, 2026)",
  },
  "@cacheable/utils": {
    versions: ["2.5.1"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 2.5.1 is malicious (August 4, 2026)",
  },
  "@cacheable/net": {
    versions: ["2.1.1"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 2.1.1 is malicious (August 4, 2026)",
  },
  "flat-cache": {
    versions: ["6.1.24"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 6.1.24 is malicious (August 4, 2026)",
  },
  "file-entry-cache": {
    versions: ["11.1.6"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 11.1.6 is malicious; one vendor reported 11.1.7, which does not exist on the registry (August 4, 2026)",
  },
  "ecto": {
    versions: ["5.0.1"],
    description: "ChainDrop npm worm: same preinstall dropper as keyv@6.0.0, published from the compromised maintainer account. Legitimate package - only 5.0.1 is malicious (August 4, 2026)",
  },
  "@thiennq/docs-viewer": {
    versions: ["1.6.2"],
    description: "ChainDrop npm worm: republished by the worm from a second compromised publisher account. Legitimate package - only 1.6.2 is malicious (August 4, 2026)",
  },
  "@deliveroo/reevent": {
    versions: ["1.0.1"],
    description: "ChainDrop npm worm: republished by the worm from a second compromised publisher account. Legitimate package - only 1.0.1 is malicious (August 4, 2026)",
  },
  "@or-sdk/invitations": {
    versions: ["1.4.9"],
    description: "ChainDrop npm worm: republished by the worm from a second compromised publisher account. Legitimate package - only 1.4.9 is malicious (August 4, 2026)",
  },
  "@picsart/ai-sdk": {
    versions: ["3.32.2"],
    description: "ChainDrop npm worm: republished by the worm from a second compromised publisher account. Legitimate package - only 3.32.2 is malicious (August 4, 2026)",
  },

  // Alibaba developer toolchain RAT (Corgea, August 2026). Nineteenth package of
  // the cluster, missed by the eighteen the advisory databases published and by
  // Socket's original write-up. Version-pinned rather than blocked by name: the
  // name is generic enough that a future unrelated publisher could claim it, and
  // 1.0.1 is the only version that has ever existed (published 2026-04-27, still
  // live). Single-source (Corgea), which is also why this is a pin and not a
  // MALICIOUS_PACKAGE_PATTERNS entry.
  "node-data-utils": {
    versions: ["1.0.1"],
    description: "Alibaba developer toolchain RAT: staging artifact of the lib-mtop / aone-kit cluster that delivers a cross-platform RAT via a config dead-drop (Corgea, August 2026)",
  },

  // TeamPCP npm wave (March 19-27, 2026). Legitimate packages whose publishing
  // credentials the actor used; only the listed versions are malicious, so every entry
  // is version pinned and no package is blocked by name.
  //
  // Version sets are derived from three signals, not one: the GitHub Advisory Database,
  // the vendor package list, and the npm registry `time` map. The advisory ranges are
  // NARROWER than the real set - @teale.io/eslint-config is advised as 1.8.9-1.8.10 while
  // all of 1.8.9-1.8.16 were published 2026-03-20 and later unpublished, with 1.8.8
  // (2026-02-17) still live. A version therefore qualifies when an advisory covers it, or
  // when it was published inside the campaign window and has since been unpublished from a
  // package this campaign is known to have hit.
  // Sources: Datadog Security Labs, Endor Labs, Hexastrike, JFrog, OX Security,
  // Akamai and Trend Micro (March 19-27, 2026), plus registry.npmjs.org.
  "@airtm/uuid-base32": {
    versions: ["1.0.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-86xp-4fvm-qm2p + registry, March 2026)",
  },
  "@emilgroup/account-sdk": {
    versions: ["1.41.1", "1.41.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-79wc-g29x-jj3q + registry, March 2026)",
  },
  "@emilgroup/account-sdk-node": {
    versions: ["1.40.1", "1.40.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-2phg-9x97-9759 + registry, March 2026)",
  },
  "@emilgroup/accounting-sdk": {
    versions: ["1.27.1", "1.27.2", "1.27.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-cjxf-3qww-qv9w + registry, March 2026)",
  },
  "@emilgroup/accounting-sdk-node": {
    versions: ["1.26.1", "1.26.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-qx4v-wwj4-8xmh + registry, March 2026)",
  },
  "@emilgroup/api-documentation": {
    versions: ["1.19.1", "1.19.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-wq88-f86r-hgrh + registry, March 2026)",
  },
  "@emilgroup/auth-sdk": {
    versions: ["1.25.1", "1.25.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-gj2w-92fr-m7c2 + registry, March 2026)",
  },
  "@emilgroup/auth-sdk-node": {
    versions: ["1.21.1", "1.21.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-8328-7r2v-2fq6 + registry, March 2026)",
  },
  "@emilgroup/billing-sdk": {
    versions: ["1.56.1", "1.56.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-m26r-hvqm-73ff + registry, March 2026)",
  },
  "@emilgroup/billing-sdk-node": {
    versions: ["1.57.1", "1.57.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-mw23-j5r9-c8vj + registry, March 2026)",
  },
  "@emilgroup/changelog-sdk-node": {
    versions: ["1.0.2", "1.0.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-wcrr-xhm3-j3x9 + registry, March 2026)",
  },
  "@emilgroup/claim-sdk": {
    versions: ["1.41.1", "1.41.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-mjwm-77q5-mrxr + registry, March 2026)",
  },
  "@emilgroup/claim-sdk-node": {
    versions: ["1.39.1", "1.39.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-38x3-f5vr-mvpw + registry, March 2026)",
  },
  "@emilgroup/commission-sdk-node": {
    versions: ["1.0.1", "1.0.2", "1.0.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-cmfv-mmcw-jpw3 + registry, March 2026)",
  },
  "@emilgroup/customer-sdk": {
    versions: ["1.54.1", "1.54.2", "1.54.3", "1.54.4", "1.54.5"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-rgf4-gx75-xrv2 + registry, March 2026)",
  },
  "@emilgroup/customer-sdk-node": {
    versions: ["1.55.1", "1.55.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-jfwq-4fm4-wwpw + registry, March 2026)",
  },
  "@emilgroup/discount-sdk": {
    versions: ["1.5.2", "1.5.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-3fjh-jjvh-r58h + registry, March 2026)",
  },
  "@emilgroup/document-sdk": {
    versions: ["1.45.1", "1.45.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-74q8-chvf-xjp2 + registry, March 2026)",
  },
  "@emilgroup/document-sdk-node": {
    versions: ["1.43.1", "1.43.2", "1.43.3", "1.43.4", "1.43.5", "1.43.6"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-5q3v-cjxm-6cgm + registry, March 2026)",
  },
  "@emilgroup/document-uploader": {
    versions: ["0.0.11", "0.0.12"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-jrpm-f5xg-3frj + registry, March 2026)",
  },
  "@emilgroup/docxtemplater-util": {
    versions: ["1.1.3", "1.1.4"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-f9m8-w27f-mxr3 + registry, March 2026)",
  },
  "@emilgroup/gdv-sdk": {
    versions: ["2.6.1", "2.6.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-8vmq-w85q-4q4j + registry, March 2026)",
  },
  "@emilgroup/gdv-sdk-node": {
    versions: ["2.6.1", "2.6.2", "2.6.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-gqwm-qw26-8g59 + registry, March 2026)",
  },
  "@emilgroup/insurance-sdk": {
    versions: ["1.97.1", "1.97.2", "1.97.3", "1.97.4", "1.97.5", "1.97.6"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-c9rj-gq4m-f5wq + registry, March 2026)",
  },
  "@emilgroup/insurance-sdk-node": {
    versions: ["1.95.1", "1.95.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-h5jq-7px8-v446 + registry, March 2026)",
  },
  "@emilgroup/notification-sdk-node": {
    versions: ["1.4.1", "1.4.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-9538-fpmw-hjpr + registry, March 2026)",
  },
  "@emilgroup/partner-portal-sdk": {
    versions: ["1.1.1", "1.1.2", "1.1.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-hpqp-f9r8-f725 + registry, March 2026)",
  },
  "@emilgroup/partner-portal-sdk-node": {
    versions: ["1.1.1", "1.1.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-cxm8-rrjm-28jf + registry, March 2026)",
  },
  "@emilgroup/partner-sdk-node": {
    versions: ["1.19.1", "1.19.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-39vv-2g62-pp83 + registry, March 2026)",
  },
  "@emilgroup/payment-sdk": {
    versions: ["1.15.1", "1.15.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-96qx-5379-wp39 + registry, March 2026)",
  },
  "@emilgroup/payment-sdk-node": {
    versions: ["1.23.1", "1.23.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-4r42-c7jf-m8rf + registry, March 2026)",
  },
  "@emilgroup/public-api-sdk": {
    versions: ["1.33.1", "1.33.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-qf6c-xv4h-gxw5 + registry, March 2026)",
  },
  "@emilgroup/public-api-sdk-node": {
    versions: ["1.35.1", "1.35.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-mvrx-3fqg-4hvh + registry, March 2026)",
  },
  "@emilgroup/setting-sdk-node": {
    versions: ["0.2.1", "0.2.2", "0.2.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-h7pp-f3cj-j5vh + registry, March 2026)",
  },
  "@emilgroup/task-sdk": {
    versions: ["1.0.3", "1.0.4"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-f568-m9rh-p7xj + registry, March 2026)",
  },
  "@emilgroup/task-sdk-node": {
    versions: ["1.0.4"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-r27q-f5jw-j5jp + registry, March 2026)",
  },
  "@emilgroup/tenant-sdk": {
    versions: ["1.34.1", "1.34.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-6w74-x38v-9ffj + registry, March 2026)",
  },
  "@emilgroup/tenant-sdk-node": {
    versions: ["1.33.1", "1.33.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-gmxq-2g92-63xv + registry, March 2026)",
  },
  "@leafnoise/mirage": {
    versions: ["2.0.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-24fv-r862-wg4c + registry, March 2026)",
  },
  "@opengov/form-builder": {
    versions: ["0.12.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (single-source, no advisory and no registry data, March 2026)",
  },
  "@opengov/form-renderer": {
    versions: ["0.2.20"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-j3x7-94xp-wf43, March 2026)",
  },
  "@opengov/form-utils": {
    versions: ["0.7.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-q4j2-j63f-5vqx, March 2026)",
  },
  "@opengov/ppf-backend-types": {
    versions: ["1.141.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-4xcw-mhqm-x332 + registry, March 2026)",
  },
  "@opengov/ppf-eslint-config": {
    versions: ["0.1.11"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-gc99-m8qp-xm33, March 2026)",
  },
  "@opengov/qa-record-types-api": {
    versions: ["1.0.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (single-source, no advisory and no registry data, March 2026)",
  },
  "@pypestream/floating-ui-dom": {
    versions: ["2.15.1"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-5h9j-3cr5-f9xj, March 2026)",
  },
  "@teale.io/eslint-config": {
    versions: ["1.8.9", "1.8.10", "1.8.11", "1.8.12", "1.8.13", "1.8.14", "1.8.15", "1.8.16"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-7h5g-m989-54j2 + registry, March 2026)",
  },
  "@virtahealth/substrate-root": {
    versions: ["1.0.1"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (single-source, no advisory and no registry data, March 2026)",
  },
  "babel-plugin-react-pure-component": {
    versions: ["0.1.6"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-f9q8-fcvg-876p + registry, March 2026)",
  },
  "cit-playwright-tests": {
    versions: ["1.0.1"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-64p5-3wp7-v4c9 + registry, March 2026)",
  },
  "eslint-config-ppf": {
    versions: ["0.128.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-29gm-cwfm-376h + registry, March 2026)",
  },
  "eslint-config-service-users": {
    versions: ["0.0.3"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-9h8j-g652-xrg8 + registry, March 2026)",
  },
  "jest-preset-ppf": {
    versions: ["0.0.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-8999-rqc4-rjrh + registry, March 2026)",
  },
  "opengov-k6-core": {
    versions: ["1.0.2"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-h38m-4w8q-55j2 + registry, March 2026)",
  },
  "react-autolink-text": {
    versions: ["2.0.1"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (registry-corroborated, no advisory, March 2026)",
  },
  "react-leaflet-cluster-layer": {
    versions: ["0.0.4"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-jrfv-73x8-f24x + registry, March 2026)",
  },
  "react-leaflet-heatmap-layer": {
    versions: ["2.0.1"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (GHSA-v4gc-5jfp-x5rj + registry, March 2026)",
  },
  "react-leaflet-marker-layer": {
    versions: ["0.1.5"],
    description: "TeamPCP npm wave: trojanized release of a legitimate package published with stolen credentials (registry-corroborated, no advisory, March 2026)",
  },
};

// ---------------------------------------------------------------------------
// Known compromised PyPI package versions
// ---------------------------------------------------------------------------

export const KNOWN_BAD_PYPI_VERSIONS: Record<string, { versions: string[]; description: string }> = {
  "ctx": {
    versions: ["0.1.2", "0.2.6"],
    description: "ctx PyPI hijack: steals environment variables (May 2022)",
  },
  "lightning": {
    versions: ["2.6.2", "2.6.3"],
    description: "Mini Shai-Hulud / TeamPCP: PyTorch Lightning PyPI hijack with credential stealer payload (April 2026)",
  },
  "xinference": {
    versions: ["2.6.0", "2.6.1", "2.6.2"],
    description: "TeamPCP Update 008: xinference PyPI hijack with '# hacked by teampcp' marker + credential stealer (April 2026)",
  },
  "guardrails-ai": {
    versions: ["0.10.1"],
    description: "Mini Shai-Hulud / TeamPCP: Guardrails AI PyPI hijack with worm payload (May 2026)",
  },
  "mistralai": {
    versions: ["2.4.6"],
    description: "Mini Shai-Hulud / TeamPCP: Mistral AI PyPI client hijack with worm payload (May 2026)",
  },
  "durabletask": {
    versions: ["1.4.1", "1.4.2", "1.4.3"],
    description: "Mini Shai-Hulud / TeamPCP: officially Microsoft-published durabletask Python SDK trojanized (SANS ISC diary 33016, May 24, 2026)",
  },
  "litellm": {
    versions: ["1.82.7", "1.82.8"],
    description: "LiteLLM PyPI compromise (TeamPCP): litellm_init.pth auto-runs on Python startup; RSA-4096+AES-256 credential exfil to models.litellm.cloud; persistent backdoor polling checkmarx.zone every 50min (March 24, 2026; Trail of Bits write-up May 22, 2026)",
  },
  "mrmustard": {
    versions: ["0.7.4"],
    description: "mrmustard PyPI compromise: XanaduAI photonic quantum library; a breached maintainer GitHub account was used to steal the PyPI token via the project's self-hosted CI runners and publish a poisoned 0.7.4. A 258-line _check_tf_compatibility() in __init__.py runs on every import, steals SSH keys, AWS credentials, Kubernetes configs, SLURM queues and GPU inventories to metrics.femboy.energy, and installs three persistence mechanisms (a mmcompat.pth site-packages hook, a 15-minute cron entry and a shell rc hook) that survive pip uninstall. Legitimate package - only 0.7.4 is malicious; 0.7.3 and earlier and the 1.0.0a pre-releases are clean (StepSecurity + safedep, July 2026)",
  },

  "telnyx": {
    versions: ["4.87.1", "4.87.2"],
    description: "telnyx PyPI compromise (TeamPCP): the sibling of the litellm push three days earlier. A backdoored telnyx/_client.py, absent from the upstream GitHub repository, fires on `import telnyx`: on Windows it drops a persistent msbuild.exe into the Startup folder, on Linux and macOS it downloads a credential harvester hidden inside a WAV file from 83[.]142[.]209[.]203:8080. Legitimate package - only 4.87.1 and 4.87.2 are malicious (Endor Labs, OX Security, JFrog, Trend Micro, Akamai and Hexastrike, March 27, 2026)",
  },

  // --- Mini Shai-Hulud / Miasma "Hades" PyPI wave (June 8, 2026) ------------------
  // The PyPI branch of the Miasma / Mini Shai-Hulud family already tracked above on the
  // npm side, attributed to TeamPCP. Stolen maintainer tokens were used to publish one
  // trojanized release per project; the payload abuses a .pth site-packages hook so it
  // runs on every Python startup rather than only at install, then pulls a Bun-based
  // stage 2 that harvests developer, cloud and CI credentials and republishes onward.
  // Reported by Socket, corroborated by Endor Labs, O3 Security and Snyk.
  //
  // Every version below was checked against the live PyPI registry before ingestion:
  // all 23 are gone from the releases map, and for each package that still exists the
  // malicious version is exactly one increment above the surviving "latest". Only that
  // one release is pinned - the packages themselves stay usable, which matters here
  // because most are academic genomics and graph-ML libraries with years of history
  // (pyphetools has 201 clean releases, ensmallen 120, embiggen 116).
  "dreamgen": {
    versions: ["1.8.1"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 1.8.1 is malicious; 1.8.0 remains the clean latest (Socket, June 8, 2026)",
  },
  "embiggen": {
    versions: ["0.11.97"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate graph-ML package - only 0.11.97 is malicious; 0.11.96 remains the clean latest (Socket + Endor Labs, June 8, 2026)",
  },
  "ensmallen": {
    versions: ["0.8.101"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate graph-processing package - only 0.8.101 is malicious; 0.8.100 remains the clean latest (Socket + Endor Labs, June 8, 2026)",
  },
  "gpsea": {
    versions: ["0.9.14"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate genotype-phenotype package - only 0.9.14 is malicious; 0.9.13 remains the clean latest (Socket + Endor Labs, June 8, 2026)",
  },
  "mem8": {
    versions: ["6.0.1"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 6.0.1 is malicious; 6.0.0 remains the clean latest (Socket, June 8, 2026)",
  },
  "mflux-streamlit": {
    versions: ["0.0.3", "0.0.4"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 0.0.3 and 0.0.4 are malicious; 0.0.2 remains the clean latest (Socket, June 8, 2026)",
  },
  "phenopacket-store-toolkit": {
    versions: ["0.1.7"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate GA4GH phenopacket package - only 0.1.7 is malicious; 0.1.6 remains the clean latest (Socket + Endor Labs, June 8, 2026)",
  },
  "ppkt2synergy": {
    versions: ["0.1.1"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate HPO annotation package - only 0.1.1 is malicious; 0.1.0 remains the clean latest (Socket + Endor Labs + Snyk, June 8, 2026)",
  },
  "pyphetools": {
    versions: ["0.9.120"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate GA4GH phenopacket package - only 0.9.120 is malicious; 0.9.119 remains the clean latest (Socket + Endor Labs, June 8, 2026)",
  },
  "ray-mcp-server": {
    versions: ["0.2.1"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate Ray MCP server package - only 0.2.1 is malicious; 0.2.0 remains the clean latest (Socket, June 8, 2026)",
  },
  // The eight names below are gone from PyPI entirely, not just the bad release. That
  // removal is consistent with a name that was always attacker-controlled, but the
  // registry no longer holds the history that would prove it, so they are version-pinned
  // like the rest rather than blocked by bare name: a name-level rule here would rest on
  // an inference, and it would fire on any future project that reclaims the name.
  "instructor-mcp": {
    versions: ["1.15.2", "1.15.3"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: MCP-developer-targeted package carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },
  "langchain-core-mcp": {
    versions: ["1.4.2", "1.4.3"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: LangChain-impersonating MCP package carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },
  "openai-mcp": {
    versions: ["2.41.1", "2.41.2"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: OpenAI-impersonating MCP package carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },
  "orchestr8-platform": {
    versions: ["3.3.2"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },
  "rlask": {
    versions: ["3.1.4", "3.1.5", "3.1.6", "3.1.7"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: Flask typosquat carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI. The full malicious set is 3.1.4 through 3.1.7, not 3.1.7 alone (Socket, June 8, 2026; range extended per StepSecurity, August 2026)",
  },
  "rsquests": {
    versions: ["2.34.3"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: requests typosquat carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },
  "tiktoken-mcp": {
    versions: ["0.13.1", "0.13.2"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: tiktoken-impersonating MCP package carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },
  "tlask": {
    versions: ["3.1.4"],
    description: "Mini Shai-Hulud / Miasma 'Hades' PyPI wave: Flask typosquat carrying the .pth startup hook and Bun-based credential stealer; removed from PyPI (Socket, June 8, 2026)",
  },

  // --- Miasma "Hades" PyPI wave, developer-tooling cluster (August 2026) -------
  // The June 8 block above covers the bioinformatics/graph-ML cluster. Socket,
  // StepSecurity and Orca each published a second, larger cluster of the same
  // campaign: 37 malicious wheel artifacts across 19 further projects, all
  // carrying the same *-setup.pth startup hook that downloads Bun and runs an
  // obfuscated _index.js credential stealer.
  //
  // Every one of these is a LEGITIMATE package whose maintainer was compromised,
  // so each is version-pinned and never blocked by name. The pins are confirmed
  // twice over: all three write-ups list the same version sets, and the PyPI
  // registry shows exactly those versions removed, with the highest surviving
  // release sitting one below the first malicious one in every case.
  //
  // The write-ups also name api.anthropic.com as an exfiltration endpoint. That
  // is Anthropic's real API being abused as a courier, not attacker
  // infrastructure, so it is deliberately NOT listed here.
  "bramin": {
    versions: ["0.0.2", "0.0.3", "0.0.4"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 0.0.2 through 0.0.4 are malicious; 0.0.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "cmd2func": {
    versions: ["0.2.2", "0.2.3"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate command-wrapping package - only 0.2.2 and 0.2.3 are malicious; 0.2.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "coolbox": {
    versions: ["0.4.1", "0.4.2"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate genomics visualisation package - only 0.4.1 and 0.4.2 are malicious; 0.4.0 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "dynamo-release": {
    versions: ["1.5.4"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate single-cell RNA analysis package - only 1.5.4 is malicious; 1.5.3 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "executor-engine": {
    versions: ["0.3.4", "0.3.5"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate task-execution package - only 0.3.4 and 0.3.5 are malicious; 0.3.3 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "executor-http": {
    versions: ["0.1.3", "0.1.4"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate task-execution HTTP frontend - only 0.1.3 and 0.1.4 are malicious; 0.1.2 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "funcdesc": {
    versions: ["0.2.2", "0.2.3"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate function-description package - only 0.2.2 and 0.2.3 are malicious; 0.2.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "magique": {
    versions: ["0.6.8", "0.6.9"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate agent-communication package - only 0.6.8 and 0.6.9 are malicious; 0.6.7 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "magique-ai": {
    versions: ["0.4.4", "0.4.5"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate agent-communication package - only 0.4.4 and 0.4.5 are malicious; 0.4.3 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "mrbios": {
    versions: ["0.1.1", "0.1.2"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate bioinformatics workflow package - only 0.1.1 and 0.1.2 are malicious; 0.1.0 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "napari-ufish": {
    versions: ["0.0.2", "0.0.3"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate napari plugin - only 0.0.2 and 0.0.3 are malicious; 0.0.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "nhmpy": {
    versions: ["2.4.7"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Version-pinned to 2.4.7, the only release the write-ups name; the whole project has since been removed from PyPI (StepSecurity + Orca, August 2026)",
  },
  "nucbox": {
    versions: ["0.1.2", "0.1.3"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 0.1.2 and 0.1.3 are malicious; 0.1.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "okite": {
    versions: ["0.0.7", "0.0.8"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 0.0.7 and 0.0.8 are malicious; 0.0.6 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "pantheon-agents": {
    versions: ["0.6.1", "0.6.2"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate agent-framework package - only 0.6.1 and 0.6.2 are malicious; 0.6.0 is the clean predecessor and 0.6.4 the clean re-release (Socket + StepSecurity + Orca, August 2026)",
  },
  "pantheon-toolsets": {
    versions: ["0.5.5", "0.5.6"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate agent-toolset package - only 0.5.5 and 0.5.6 are malicious; 0.5.4 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "spateo-release": {
    versions: ["1.1.2"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate spatial-transcriptomics package - only 1.1.2 is malicious; 1.1.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "synago": {
    versions: ["0.1.1", "0.1.2"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 0.1.1 and 0.1.2 are malicious; 0.1.0 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "ufish": {
    versions: ["0.1.2", "0.1.3"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate spot-detection package - only 0.1.2 and 0.1.3 are malicious; 0.1.1 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
  "uprobe": {
    versions: ["0.1.3", "0.1.4"],
    description: "Miasma 'Hades' PyPI wave: .pth startup hook drops a Bun-based credential stealer. Legitimate package - only 0.1.3 and 0.1.4 are malicious; 0.1.2 remains the clean latest (Socket + StepSecurity + Orca, August 2026)",
  },
};

// ---------------------------------------------------------------------------
// Utility: check if a string contains any known IOC
// ---------------------------------------------------------------------------

import { createHash } from "node:crypto";
import type { Finding } from "./types.js";

/**
 * Check content against known IOC blocklists.
 */
// v5.2.21: documentation files (.md/.markdown/.txt/.rst) legitimately discuss
// malware IOCs in threat-intel write-ups, changelog entries, and blog posts.
// The IOC blocklist exists to flag actual references in source code, not to
// hit research discussion. Same rationale as patterns.ts BENIGN_DOC_FILES.
const BENIGN_DOC_FILES = /\.(md|markdown|txt|rst)$/i;

export function checkIOCBlocklist(
  content: string,
  relativePath: string,
): Finding[] {
  const findings: Finding[] = [];
  // Skip documentation files - IOCs there are discussion, not exploitation.
  if (BENIGN_DOC_FILES.test(relativePath)) return findings;
  const contentLower = content.toLowerCase();

  // Check known C2 domains
  for (const domain of KNOWN_C2_DOMAINS) {
    const domainPattern = domain.replace(/\./g, "\\.").replace(/\*/g, "\\w+");
    const regex = new RegExp(domainPattern, "i");
    if (regex.test(content)) {
      findings.push({
        rule: "IOC_KNOWN_C2_DOMAIN",
        description: `Known malicious C2 domain detected: ${domain}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This domain is a known command-and-control server. Quarantine this code immediately.",
      });
    }
  }

  // Check known C2 IPs
  for (const ip of KNOWN_C2_IPS) {
    if (content.includes(ip)) {
      findings.push({
        rule: "IOC_KNOWN_C2_IP",
        description: `Known malicious C2 IP address detected: ${ip}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This IP is a known command-and-control server. Quarantine this code immediately.",
      });
    }
  }

  // Check known dead-drop resolvers
  for (const url of KNOWN_DEAD_DROPS) {
    if (contentLower.includes(url.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_DEAD_DROP",
        description: `Known dead-drop resolver URL detected: ${url}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This URL is used as a dead-drop resolver to retrieve C2 addresses. This is a strong malware indicator.",
      });
    }
  }

  // Check known malicious hashes
  for (const [hash, desc] of Object.entries(KNOWN_MALICIOUS_HASHES)) {
    if (contentLower.includes(hash.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_MALWARE_HASH",
        description: `Known malware hash detected: ${hash} (${desc})`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This hash matches known malware. Do not execute any associated files.",
      });
    }
  }

  // Check known C2 / operator blockchain wallets. Exact-literal substring only
  // (see the KNOWN_C2_WALLETS doc comment for why a shape matcher is banned).
  for (const [address, desc] of Object.entries(KNOWN_C2_WALLETS)) {
    if (contentLower.includes(address.toLowerCase())) {
      findings.push({
        rule: "IOC_KNOWN_C2_WALLET",
        description: `Known C2 blockchain address detected: ${address} (${desc})`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This blockchain address is used for malware command-and-control. Treat any code referencing it as malicious and audit how it entered the dependency tree.",
      });
    }
  }

  // Check known malicious GitHub accounts
  for (const account of KNOWN_MALICIOUS_GITHUB_ACCOUNTS) {
    const pattern = new RegExp(`github\\.com/${account}\\b`, "i");
    if (pattern.test(content)) {
      findings.push({
        rule: "IOC_KNOWN_MALICIOUS_ACCOUNT",
        description: `Reference to known malicious GitHub account: ${account}`,
        severity: "critical",
        file: relativePath,
        recommendation:
          "This GitHub account is known to distribute malware. Do not clone or use code from this source.",
      });
    }
  }

  return findings;
}

/**
 * Check a package name + version against the known-bad blocklist.
 */
export function checkBadVersion(
  name: string,
  version: string,
  ecosystem: "npm" | "pypi" | "ruby" | "composer" | "nuget" | "cargo" | "go" | "jenkins",
): Finding | null {
  // ruby/composer/nuget/cargo have no pinned entries yet (their curated IOCs
  // live in threat-intel.ts as ecosystem-prefixed package entries); the union
  // is open so future BAD_VERSIONS entries can target them without an API change.
  const blocklist: Record<string, { versions: string[]; description: string }> =
    ecosystem === "npm"
      ? KNOWN_BAD_NPM_VERSIONS
      : ecosystem === "pypi"
        ? KNOWN_BAD_PYPI_VERSIONS
        : {};

  // Look the name up under the registry's own equivalence rule (PEP 503 for
  // PyPI, exact for everything else). The direct hit is tried first so the
  // common path stays a single property access.
  let entry = blocklist[name];
  if (!entry && ecosystem === "pypi") {
    const normalized = normalizePackageName(name, ecosystem);
    for (const [key, value] of Object.entries(blocklist)) {
      if (normalizePackageName(key, ecosystem) === normalized) {
        entry = value;
        break;
      }
    }
  }
  if (!entry) return null;

  if (entry.versions.includes(version)) {
    return {
      rule: "IOC_KNOWN_BAD_VERSION",
      description: `Known compromised package version: ${name}@${version} - ${entry.description}`,
      severity: "critical",
      recommendation: `Remove ${name}@${version} immediately. This version contains known malware. Upgrade to a clean version.`,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// File-digest matching
// ---------------------------------------------------------------------------

/**
 * Algorithms whose digests in KNOWN_MALICIOUS_HASHES are unambiguously digests
 * OF FILE BYTES, keyed by the hex length that identifies them.
 *
 * Length 40 is deliberately absent. The collection holds two different things
 * at that length: a Git object id ("Nx Console malicious orphan commit (Git
 * SHA)"), which is a hash of a commit object and never of file bytes, and a
 * genuine file SHA-1 ("NadMesh botnet Go agent sample (SHA1)"). Nothing in the
 * data distinguishes them, so matching either would risk telling a user their
 * file is malware on the strength of a commit id. That is a data-modelling gap
 * to fix by typing the collection, not something to guess at here.
 */
const FILE_DIGEST_ALGORITHMS = [
  { algorithm: "sha256", hexLength: 64 },
  { algorithm: "md5", hexLength: 32 },
] as const;

/** Lowercased digest -> description. Built once, not per file (cf. T-017). */
let fileDigestIndex: Map<string, string> | null = null;

function getFileDigestIndex(): Map<string, string> {
  if (fileDigestIndex) return fileDigestIndex;
  const usableLengths = new Set<number>(FILE_DIGEST_ALGORITHMS.map((a) => a.hexLength));
  const index = new Map<string, string>();
  for (const [hash, description] of Object.entries(KNOWN_MALICIOUS_HASHES)) {
    if (usableLengths.has(hash.length)) index.set(hash.toLowerCase(), description);
  }
  fileDigestIndex = index;
  return index;
}

/**
 * Match a scanned file BY ITS OWN DIGEST against KNOWN_MALICIOUS_HASHES.
 *
 * Deliberately separate from the digest handling inside checkIOCBlocklist,
 * which substring-searches the digest TEXT inside file content. That text match
 * answers "does this file quote a known-bad digest", which is a real signal in
 * a lockfile, manifest or advisory, and it is kept unchanged. It cannot answer
 * "is this file the malware", because a payload never contains its own digest.
 *
 * Until this matcher existed, every entry describing a dropped artefact was
 * unreachable by the thing it names: the ChainDrop hook "dropped as
 * .vscode/tasks.json", the WEL1DROPPER stage-2 payload binaries, and the
 * ChainDrop preinstall droppers could only have fired on a file that happened
 * to contain their own hex digest as text.
 *
 * Do not name the ChainDrop loader filenames in this comment. TypeScript copies
 * JSDoc into the generated .d.ts, `notFilePattern: SCANNER_SRC_OR_DOCS` exempts
 * src/ but not dist/*.d.ts, and MINI_SHAI_HULUD_LOADER matches those filenames
 * after any whitespace. Naming them here turns the repo's own build output into
 * a high-severity self-scan finding, which is how this was found.
 *
 * No BENIGN_DOC_FILES skip here, unlike the text matcher. That skip exists
 * because documentation legitimately DISCUSSES indicators; a byte-for-byte
 * digest match is not discussion, so a .md file that is exactly a known
 * payload should still be reported.
 *
 * Takes the raw bytes rather than decoded text on purpose: a digest must be
 * computed over the file as it exists on disk. Hashing a UTF-8 decoded string
 * would not reproduce the published digest for any binary payload, which is
 * most of what this collection describes.
 */
export function checkFileDigest(
  bytes: Buffer,
  relativePath: string,
  // Injectable only so a test can assert the matching behaviour itself. A real
  // digest has no computable preimage, so a test cannot build a file that
  // matches a shipped entry; it supplies its own index instead.
  index: Map<string, string> = getFileDigestIndex(),
): Finding[] {
  const findings: Finding[] = [];
  // The bytes are already in memory, so each extra algorithm is CPU only and
  // costs no additional I/O.
  for (const { algorithm } of FILE_DIGEST_ALGORITHMS) {
    const digest = createHash(algorithm).update(bytes).digest("hex");
    const description = index.get(digest);
    if (!description) continue;
    findings.push({
      rule: "IOC_KNOWN_MALWARE_FILE_DIGEST",
      description: `File content matches a known malware digest: ${algorithm} ${digest} (${description})`,
      severity: "critical",
      file: relativePath,
      recommendation: `Remove ${relativePath}. Its contents are byte-for-byte identical to a known malicious artefact.`,
    });
  }
  return findings;
}
