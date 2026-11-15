# AIX for Google AI Studio

Chrome extension and a direct local file and command agent for Google AI Studio.
The current bundle connects over loopback. Build with `./build.ps1` on Windows.
Ready files are written to `bin/aix`. The agent uses the `aistudio` build tag and
always starts in local mode, including when Gate environment variables are present.
Gate and previous integrations remain in the repository for future work.

See [installation and update instructions](README.ru.md).
On Windows, `build-agent.bat` compiles only the local agent and `start-agent.bat` runs it.
