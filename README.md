<p align="center">
  <img src="images/vulzoo.png" alt="vulzoo-logo" height="250" />
</p>

## Introduction

VulZoo is a vulnerability intelligence dataset that integrates various sources of structured and unstructured data. It is designed to be used by security researchers, penetration testers, and security analysts to get a comprehensive view of vulnerabilities and their associated data.

## How to Use

VulZoo is composed of both git-based and non-git-based sources. The git-based sources are from upstream repositories and organized as git submodules in this repository. The non-git-based sources are crawled and maintained in this repository. To get started, clone the repository with the following command:

```bash
git clone --recurse-submodules https://github.com/brant-ruan/VulZoo
```

VulZoo provides some useful scripts to help you manage the data. As some scripts require specific Python packages, it is recommended to install the required packages first:

```bash
pip install -r requirements.txt
```

You can run the `update-databases.sh` script to incrementally update the local dataset:

```bash
cd VulZoo/
./update-databases.sh
```

## Integrated Sources

### Structural

- [CVE (Common Vulnerabilities and Exposures)](https://github.com/CVEProject/cvelist.git)
- [NVD](https://github.com/fkie-cad/nvd-json-data-feeds.git)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [CAPEC (Common Attack Pattern Enumeration and Classification)](https://capec.mitre.org/)
- [CISA KEV (Known Exploited Vulnerabilities)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [ZDI Advisory](https://github.com/delikely/ZDI_Advisories.git)
- [GitHub Advisory](https://github.com/github/advisory-database)
- [ATT&CK](https://github.com/mitre-attack/attack-stix-data.git)
- [D3FEND](https://d3fend.mitre.org/)

### Unstructural

- [Exploit-DB](https://gitlab.com/exploit-database/exploitdb)
- [oss-security mailing list](https://www.openwall.com/lists/oss-security)
- [bugtraq mailing list](https://lists.openwall.net/bugtraq/)

### Hybrid

- [Linux Kernel Vulns](https://git.kernel.org/pub/scm/linux/security/vulns.git)

