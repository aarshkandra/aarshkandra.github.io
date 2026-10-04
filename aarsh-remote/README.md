# Aarsh Remote

Personal, self-hosted remote workstation system: wake a Windows desktop from anywhere, then use it
(Revit/BIM) from a low-spec laptop. Built on **RustDesk OSS** for the remote-desktop engine; this
project adds the control plane (auth, device registry, Wake-on-LAN via a LAN Wake Agent, power
management, monitoring, audit).

**Status: Phases 2–3 implemented (backend, protocol, Windows agent). The agent is tested end-to-end against the backend on Linux; the Windows-only parts still need the on-PC checklist. Phase 4 (Wake-on-LAN / Wake Agent) is next.**

| Doc | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Components, diagrams, decisions, state machine, security model, risks |
| [docs/rustdesk.md](docs/rustdesk.md) | RustDesk research, integration choice, licensing, verification checklist |
| [docs/database-schema.md](docs/database-schema.md) | PostgreSQL schema |
| [docs/api-spec.md](docs/api-spec.md) | REST + WebSocket + signed command envelope |
| [docs/implementation-plan.md](docs/implementation-plan.md) | Phase 0–9 plan and exit criteria |
| [docs/backend.md](docs/backend.md) | Running, configuring, testing and deploying the backend |
| [docs/windows-agent.md](docs/windows-agent.md) | The Windows service: behaviour, security properties, install, verification checklist |
| [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) | Dependency licenses (draft) |

Remaining spec-listed docs (installation, security, wake-on-lan, networking, windows-agent,
troubleshooting, deployment) are written alongside the phase that implements them.
