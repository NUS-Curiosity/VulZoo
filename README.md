<p align="center">
  <img src="images/vulzoo.png" alt="vulzoo-logo" height="250" />
</p>

## Introduction

VulZoo is a vulnerability intelligence dataset that integrates various sources of structured and unstructured data. It is designed to be used by security researchers, penetration testers, and security analysts to get a comprehensive view of vulnerabilities and their associated data.

This dataset is divided into two parts: 

- `raw-data/`: contains the raw data from different sources.
- `vulzoo/`: contains the processed data that is more structured and easier to use.

## How to Use

Pre-requisites:

- Python 3.6+
- Disk space: 15GB+

VulZoo is composed of both git-based and non-git-based sources. The git-based sources are from upstream repositories and organized as git submodules in this repository. The non-git-based sources are crawled and maintained in this repository. To get started, clone the repository with the following command:

```bash
git clone --recurse-submodules https://github.com/brant-ruan/VulZoo
```

VulZoo provides some useful scripts to help you manage the data. As some scripts require specific Python packages, it is recommended to install the required packages first:

```bash
cd VulZoo/
pip install -r requirements.txt
```

You can run the `sync-raw-data.sh` script to incrementally update the local raw data:

```bash
cd VulZoo/
./sync-raw-data.sh
```

TODO: You can run the `sync-vulzoo.sh` script to incrementally update the processed data:

```bash
cd VulZoo/
./sync-vulzoo.sh
```

## Data Sources

### Structural

- [CVE (Common Vulnerabilities and Exposures)](https://github.com/CVEProject/cvelist.git)
- [NVD (National Vulnerability Database)](https://github.com/fkie-cad/nvd-json-data-feeds.git)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [CAPEC (Common Attack Pattern Enumeration and Classification)](https://capec.mitre.org/)
- [CISA KEV (Known Exploited Vulnerabilities)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [ZDI Advisory](https://github.com/delikely/ZDI_Advisories.git)
- [GitHub Advisory](https://github.com/github/advisory-database)
- [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data.git)
- [MITRE D3FEND](https://d3fend.mitre.org/)

### Unstructural

- [Exploit-DB](https://gitlab.com/exploit-database/exploitdb)
- [oss-security mailing list](https://www.openwall.com/lists/oss-security)
- [bugtraq mailing list](https://lists.openwall.net/bugtraq/)

### Hybrid

- [Linux Kernel Vulns](https://git.kernel.org/pub/scm/linux/security/vulns.git)
