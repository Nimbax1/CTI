# Portfolio Cyber Threat Intelligence

<!-- TABELLA_START -->

## TTP & Malware

| File Malware | Dest Countries | Origin | Date detection | Threat Actor | MainBranch | Capabilities |
|---|---|---|---|---|---|---|
| [Coruna](./TTP_&_Malware/Coruna.md) | Ukraine | N/A | 2025-11-01 | [UNC6353](./Actors/UNC6353.md) | N/A | N/A |
| [DarkSword](./TTP_&_Malware/DarkSword.md) | N/A | N/A | N/A | N/A | N/A | N/A |
| [GHOSTBLADE](./TTP_&_Malware/GHOSTBLADE.md) | Ukraine | N/A | 2025-12-01 | [UNC6353](./Actors/UNC6353.md) | [DarkSword](./TTP_&_Malware/DarkSword.md) | Exfiltration |
| [GHOSTKNIFE](./TTP_&_Malware/GHOSTKNIFE.md) | Saudi Arabia | N/A | 2025-12-01 | [UNC6748](./Actors/UNC6748.md) | [DarkSword](./TTP_&_Malware/DarkSword.md) | Exfiltration, Screen Capture, Audio Recording |
| [GHOSTSABER](./TTP_&_Malware/GHOSTSABER.md) | Turkey, Malasya | PARS Defense, Turkey | 2025-11-01 | [PARS_Defense](./Actors/PARS_Defense.md) | [DarkSword](./TTP_&_Malware/DarkSword.md) | account enumeration, Exfiltration, file listing |

---

## Actors Activity by Country

### Malasya

| Actor | Activity | Date | MainBranch | Target |
|---|---|---|---|---|
| [PARS_Defense](./Actors/PARS_Defense.md) | [GHOSTSABER](./TTP_&_Malware/GHOSTSABER.md) | 2025-11-01 | [DarkSword](./TTP_&_Malware/DarkSword.md) | Users |

### Saudi Arabia

| Actor | Activity | Date | MainBranch | Target |
|---|---|---|---|---|
| [UNC6748](./Actors/UNC6748.md) | [GHOSTKNIFE](./TTP_&_Malware/GHOSTKNIFE.md) | 2025-12-01 | [DarkSword](./TTP_&_Malware/DarkSword.md) | Users |

### Turkey

| Actor | Activity | Date | MainBranch | Target |
|---|---|---|---|---|
| [PARS_Defense](./Actors/PARS_Defense.md) | [GHOSTSABER](./TTP_&_Malware/GHOSTSABER.md) | 2025-11-01 | [DarkSword](./TTP_&_Malware/DarkSword.md) | Users |

### Ukraine

| Actor | Activity | Date | MainBranch | Target |
|---|---|---|---|---|
| [UNC6353](./Actors/UNC6353.md) | [Coruna](./TTP_&_Malware/Coruna.md)<br>[GHOSTBLADE](./TTP_&_Malware/GHOSTBLADE.md) | 2025-11-01<br>2025-12-01 | N/A<br>[DarkSword](./TTP_&_Malware/DarkSword.md) | Users<br>Users |

<!-- TABELLA_END -->