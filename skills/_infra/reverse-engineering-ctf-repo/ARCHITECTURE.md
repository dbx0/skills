# System Architecture Diagrams

## Full Behavior Chain Flowchart

```mermaid
flowchart TD
    Start([User raises a security/reversing task]) --> Detect{Trigger keyword match?}
    Detect -->|Yes| ReadRouting[Read SKILL.md + routing.md]
    Detect -->|No| Normal([Normal conversation])
    
    ReadRouting --> RouteMatch{Routing matrix match?}
    RouteMatch -->|No match| ProposeNew[Propose a new skill<br/>following CONTRIBUTING.md]
    RouteMatch -->|Match| CheckJournal[Check field-journal<br/>for comparable experience]
    
    CheckJournal --> CheckTools[Read tool-index.md<br/>confirm tool status]
    CheckTools --> ToolOK{Tool available?}
    
    ToolOK -->|Missing| Bootstrap[Call bootstrap-reverse.ps1<br/>install automatically]
    ToolOK -->|Available| Execute[Enter the skill workflow]
    
    Bootstrap --> BootOK{Installation succeeded?}
    BootOK -->|Success| Execute
    BootOK -->|Failure| Guide[Print structured guidance<br/>wait for the user to handle it]
    Guide --> UserConfirm([User confirms it is installed])
    UserConfirm --> Execute
    
    Execute --> TaskDone{Task complete?}
    TaskDone -->|No| Execute
    TaskDone -->|Yes| GenReport[Call docs-generator<br/>produce report + diagrams]
    
    GenReport --> WriteJournal[Write back to field-journal<br/>capture the experience]
    WriteJournal --> UpdateIndex[Update index/routing/manifest]
    UpdateIndex --> Output([Output the final result])
```

## Skills Module Relationship Diagram

```mermaid
flowchart LR
    subgraph RoutingLayer[Routing layer]
        SKILL[SKILL.md<br/>master entry point]
        Routing[routing.md<br/>routing matrix]
    end

    subgraph ReverseAnalysis[Reverse engineering analysis]
        APK[apk-reverse<br/>APK reversing]
        IDA[ida-reverse<br/>IDA Pro]
        R2[radare2<br/>CLI analysis]
        RE[reverse-engineering<br/>general methodology]
        BinDiff[binary-diff<br/>symbol migration]
        PatchDiff[patch-diff-exploit<br/>N-day weaponization]
    end

    subgraph Exploitation[Exploitation]
        Pwn[pwn-chain<br/>RE→exploit]
        Firmware[firmware-pentest<br/>full firmware chain]
    end

    subgraph PenetrationTesting[Penetration testing]
        Pentest[pentest-tools<br/>toolchain + loop framework]
        SrcHunter[src-hunter<br/>19 playbooks]
        EDR[edr-bypass-re<br/>EDR bypass]
    end

    subgraph WebBrowser[Web/browser]
        JS[js-reverse<br/>JS signature reversing]
        Browser[browser-automation<br/>Playwright+OpenReverse]
    end

    subgraph Infrastructure[Infrastructure]
        Bootstrap[bootstrap-reverse.ps1<br/>on-demand bootstrap]
        Discovery[ToolDiscovery.ps1<br/>tool discovery]
        ToolIndex[tool-index<br/>status index]
    end

    subgraph OutputLayer[Output layer]
        Docs[docs-generator<br/>report generation]
        Diagram[diagram-generator<br/>diagram generation]
        Journal[field-journal<br/>automatic evolution]
    end

    subgraph External[External]
        CTF[CTF-Sandbox-Orchestrator<br/>40+ sub-skills]
    end

    SKILL --> Routing
    Routing --> APK & IDA & R2 & RE & BinDiff & PatchDiff
    Routing --> Pentest & JS & Browser & Pwn & Firmware & EDR
    Routing --> CTF

    Pentest --> SrcHunter
    APK -->|.so handoff| IDA
    APK -->|.so handoff| R2
    PatchDiff -->|writes the PoC| Pwn
    Firmware -->|crash found| Pwn
    Pwn -->|integration| Pentest
    EDR -->|delivery stage| Pentest
    JS -->|browser operations| Browser
    
    Bootstrap --> Discovery --> ToolIndex
    
    APK & IDA & R2 & Pentest & JS -->|task complete| Docs
    Docs --> Diagram
    Docs --> Journal
```

## Bootstrap Self-Provisioning Flow

```mermaid
flowchart TD
    Need[Missing tool detected] --> ReadManifest[Read bootstrap-manifest.json]
    ReadManifest --> Kind{Installation type?}
    
    Kind -->|github-release-zip| GH[Download the ZIP from<br/>a GitHub Release and extract it]
    Kind -->|pip-package| Pip[pip install]
    Kind -->|npm-mcp| NPM[Start with npx + register the MCP]
    Kind -->|npm-global| Global[npm install -g<br/>+ postInstall]
    Kind -->|winget-package| Winget[winget install]
    Kind -->|local-http-mcp| HTTP[Register the URL + start the service]
    
    GH & Pip & NPM & Global & Winget & HTTP --> Verify{Verified working?}
    Verify -->|Success| AddPath[Add to PATH<br/>refresh tool-index]
    Verify -->|Failure| Manual[Print manual installation guidance]
    
    AddPath --> Continue([Continue with the task])
    Manual --> Wait([Wait for user confirmation])
```

## Penetration Testing Loop

```mermaid
flowchart TD
    Init[Initialization: define target/scope/tools] --> Loop

    subgraph Loop[Core loop]
        Align[1. Realign on the objective] --> Review[2. Review known findings]
        Review --> Decide[3. Decide the next action]
        Decide --> Risk{4. Risk gate}
        Risk -->|Low/medium/high| Exec[5. Execute the action]
        Risk -->|Critical| Ask[Request user approval]
        Ask -->|Approved| Exec
        Exec --> Record[6. Record the result]
        Record --> Check{7. Self-check}
        Check -->|Continue| Align
        Check -->|Done| Done
    end

    Done[8. Completion check] --> Report([Produce the final report])
```

## Automatic Evolution Mechanism

```mermaid
flowchart LR
    Task([Task complete]) --> WriteLog[Write to field-journal<br/>pitfalls + solutions + code]
    WriteLog --> UpdateIdx[Update _index.md<br/>categorized by scenario]
    UpdateIdx --> CheckUpdate{Does the system need updating?}
    
    CheckUpdate -->|Routing gap| FixRoute[Update routing.md]
    CheckUpdate -->|Tool changes| FixTool[Refresh tool-index]
    CheckUpdate -->|New tool| FixManifest[Update bootstrap-manifest]
    CheckUpdate -->|No update needed| Done([Done])
    
    FixRoute & FixTool & FixManifest --> Done

    NewTask([Next comparable task]) --> ReadIdx[Read _index.md]
    ReadIdx --> Reuse[Reuse existing experience<br/>avoid repeating pitfalls]
```

## Multi-Platform Support Architecture

```mermaid
flowchart TD
    subgraph SharedLayer["Shared layer (platform independent)"]
        Skills[skills/<br/>SKILL.md + routing.md + references]
        CTF[CTF-Sandbox-Orchestrator/<br/>40+ sub-skills]
        Journal[field-journal/<br/>experience capture]
        Docs[docs-generator + diagram-generator]
    end

    subgraph Windows["Windows platform layer"]
        WinScripts[skills/scripts/*.ps1<br/>PowerShell scripts]
        WinManifest[bootstrap-manifest.json<br/>winget + GitHub ZIP]
        WinRules[RULES.md<br/>Windows edition rules]
    end

    subgraph Kali["Kali Linux platform layer"]
        KaliScripts[kali/scripts/*.sh<br/>Bash scripts]
        KaliManifest[kali/scripts/bootstrap-manifest.json<br/>apt + pip + GitHub tar]
        KaliRules[kali/RULES-kali.md<br/>Kali edition rules]
    end

    Skills --> WinScripts & KaliScripts
    CTF --> WinScripts & KaliScripts
    Journal --> WinScripts & KaliScripts

    WinScripts --> WinManifest
    KaliScripts --> KaliManifest

    WinRules --> Skills
    KaliRules --> Skills
```

### Platform Selection Logic

| Environment | Rules file used | Scripts used | Package management |
|------|--------------|-----------|--------|
| Windows | `RULES.md` | `skills/scripts/*.ps1` | winget / GitHub Release ZIP |
| Kali Linux | `kali/RULES-kali.md` | `kali/scripts/*.sh` | apt / pip / npm / GitHub tar.gz |

### Characteristics of the Kali Edition

- **Many preinstalled tools**: nmap, sqlmap, hashcat, hydra, metasploit, radare2, binwalk, burpsuite and others need no bootstrap
- **Unified apt management**: no winget, no manual ZIP extraction
- **Native bash**: simpler scripts with no PowerShell dependency
- **Clean paths**: `/usr/bin/`, `/opt/`, `~/tools/`, no drive letters and no space-in-path issues

## File Read Sequence Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant AI as AI client
    participant R as RULES.md / RULES-kali.md
    participant SK as SKILL.md
    participant RT as routing.md
    participant TI as tool-index.md
    participant FJ as field-journal
    participant SUB as sub-skill
    participant BS as bootstrap
    participant DOC as docs-generator

    U->>AI: Raise a security task
    AI->>R: Read the routing rules
    AI->>SK: Read the master entry point
    AI->>RT: Route matching
    AI->>FJ: Look up comparable experience
    AI->>TI: Confirm tool status
    alt Tool missing
        AI->>BS: Install automatically (.ps1 or .sh)
        BS-->>AI: Result
    end
    AI->>SUB: Enter the workflow
    AI-->>U: Task result
    AI->>DOC: Produce the report
    AI->>FJ: Write back the experience
    AI-->>U: Done
```
