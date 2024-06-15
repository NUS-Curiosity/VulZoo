#!/usr/bin/env python3

import json
import re
import os

res = {}

processed_dir = "../processed"

# CISA KEV
with open(f"{processed_dir}/cisa-kev-database/kev.json") as f:
    cisa_kev = json.load(f)
    res["cisa_kev"] = {
        "count": cisa_kev['count'],
    }


# AttackerKB
res["attackerkb"] = {
    "assessment_count": 0,
    "topic_count": 0,
    "topic_with_assessment_count": 0,
}
topics_with_assessments = set()
for root, dirs, files in os.walk(f"{processed_dir}/attackerkb-database/assessments"):
    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(root, file), "r") as f:
                data = json.load(f)
                res["attackerkb"]["assessment_count"] += len(data['data'])
                for assessment in data['data']:
                    topics_with_assessments.add(assessment['topicId'])

res["attackerkb"]["topic_with_assessment_count"] = len(topics_with_assessments)

for root, dirs, files in os.walk(f"{processed_dir}/attackerkb-database/topics"):
    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(root, file), "r") as f:
                data = json.load(f)
                res["attackerkb"]["topic_count"] += len(data['data'])


# Exploit-DB
res["exploit-db"] = {
    "exploit_count": 0,
    "cve_with_exploit_count": 0,
}
with open(f"{processed_dir}/exploit-db-database/files_exploits.json") as f:
    exploit_db = json.load(f)
    res["exploit-db"]["exploit_count"] = len(exploit_db)

with open(f"{processed_dir}/exploit-db-database/cve-exploit-links.json") as f:
    exploit_db_cve = json.load(f)
    res["exploit-db"]["cve_with_exploit_count"] = len(exploit_db_cve.keys())


# CAPEC
res["capec"] = {
    "count": 0,
    "draft_count": 0,
    "stable_count": 0,
    "deprecated_count": 0,
}
with open(f"{processed_dir}/capec-database/capec.json") as f:
    capec = json.load(f)
    for attack_pattern in capec['Attack_Pattern_Catalog']['Attack_Patterns']['Attack_Pattern']:
        if attack_pattern['@Status'] == "Draft":
            res["capec"]["draft_count"] += 1
        elif attack_pattern['@Status'] == "Stable":
            res["capec"]["stable_count"] += 1
        elif attack_pattern['@Status'] == "Deprecated":
            res["capec"]["deprecated_count"] += 1
    
    res["capec"]["count"] = len(capec['Attack_Pattern_Catalog']['Attack_Patterns']['Attack_Pattern'])


# CWE
res["cwe"] = {}
with open(f"{processed_dir}/cwe-database/cwec.json") as f:
    cwe = json.load(f)
    for weakness in cwe["Weakness_Catalog"]['Weaknesses']['Weakness']:
        abstract = weakness["@Abstraction"]
        if abstract not in res["cwe"]:
            res["cwe"][abstract] = 0
        res["cwe"][abstract] += 1
    res["cwe"]["count"] = len(cwe["Weakness_Catalog"]['Weaknesses']['Weakness'])


# D3FEND
res["d3fend"] = {
    "ontology_count": 0,
    "tactic_count": 0,
}
with open(f"{processed_dir}/d3fend-database/d3fend.json") as f:
    d3fend = json.load(f)
    res["d3fend"]["tactic_count"] = len(d3fend)
with open(f"{processed_dir}/d3fend-database/d3fend_ontology.json") as f:
    d3fend_ontology = json.load(f)
    res["d3fend"]["ontology_count"] = len(d3fend_ontology["@graph"])


# ATT&CK (enterprise, ics, mobile)
res["mitre-attack"] = {
    "enterprise": 0,
    "ics": 0,
    "mobile": 0,
}
with open(f"{processed_dir}/attack-database/enterprise-attack/enterprise-attack.json") as f:
    enterprise_attack = json.load(f)
    for obj in enterprise_attack["objects"]:
        if obj["type"] == "x-mitre-collection":
            for content in obj["x_mitre_contents"]:
                if content['object_ref'].startswith("attack-pattern--"):
                    res["mitre-attack"]["enterprise"] += 1
            break
with open(f"{processed_dir}/attack-database/ics-attack/ics-attack.json") as f:
    ics_attack = json.load(f)
    for obj in ics_attack["objects"]:
        if obj["type"] == "x-mitre-collection":
            for content in obj["x_mitre_contents"]:
                if content['object_ref'].startswith("attack-pattern--"):
                    res["mitre-attack"]["ics"] += 1
            break
with open(f"{processed_dir}/attack-database/mobile-attack/mobile-attack.json") as f:
    mobile_attack = json.load(f)
    for obj in mobile_attack["objects"]:
        if obj["type"] == "x-mitre-collection":
            for content in obj["x_mitre_contents"]:
                if content['object_ref'].startswith("attack-pattern--"):
                    res["mitre-attack"]["mobile"] += 1
            break


# CVE
res["cve"] = {
    "count": 0,
}
for root, dirs, files in os.walk(f"{processed_dir}/cve-database"):
    for file in files:
        if file.endswith(".json"):
            res["cve"]["count"] += 1


# NVD
res["nvd"] = {
    "count": 0,
    "cvss_v2_count": 0,
    "cvss_v30_count": 0,
    "cvss_v31_count": 0,
    "cve_with_cwe_count": 0,
}
cwe_pattern = re.compile(r"CWE-\d+")
for root, dirs, files in os.walk(f"{processed_dir}/nvd-database"):
    for file in files:
        if file.endswith(".json"):
            res["nvd"]["count"] += 1
            with open(os.path.join(root, file), "r") as f:
                data = json.load(f)
                if "cvssMetricV2" in data["metrics"]:
                    res["nvd"]["cvss_v2_count"] += 1
                if "cvssMetricV30" in data["metrics"]:
                    res["nvd"]["cvss_v30_count"] += 1
                if "cvssMetricV31" in data["metrics"]:
                    res["nvd"]["cvss_v31_count"] += 1
                has_cwe = False
                try:
                    for weakness in data["weaknesses"]:
                        for desc in weakness["description"]:
                            if cwe_pattern.match(desc['value']):
                                has_cwe = True
                                break
                        if has_cwe:
                            break
                    if has_cwe:
                        res["nvd"]["cve_with_cwe_count"] += 1
                except KeyError:
                    continue


# GitHub Advisories
res["github-advisory"] = {
    "count": 0,
}
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
for root, dirs, files in os.walk(f"{processed_dir}/github-advisory-database"):
    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(root, file), "r") as f:
                data = json.load(f)
            try:
                for alias in data['aliases']:
                    if cve_pattern.match(alias):
                        res["github-advisory"]["count"] += 1
                        break
            except KeyError:
                continue


# ZDI Advisories
res["zdi-advisory"] = {
    "count": 0,
}
for root, dirs, files in os.walk(f"{processed_dir}/zdi-advisory-database"):
    for file in files:
        if file.endswith(".json"):
            res["zdi-advisory"]["count"] += 1


# Linux Vulns
res["linux-vulns"] = {
    "published_count": 0,
    "rejected_count": 0,
}
for root, dirs, files in os.walk(f"{processed_dir}/linux-vulns-database/published"):
    for file in files:
        if file.endswith(".json"):
            res["linux-vulns"]["published_count"] += 1

for root, dirs, files in os.walk(f"{processed_dir}/linux-vulns-database/rejected"):
    for file in files:
        if file.endswith(".json"):
            res["linux-vulns"]["rejected_count"] += 1


# Patch
res["patch"] = {
    "count": 0,
    "cve_with_patch_count": 0,
}
with open(f"{processed_dir}/patch-database/patch-manifest.json") as f:
    patch_manifest = json.load(f)
    res["patch"]["cve_with_patch_count"] = len(patch_manifest)
    for cve, patches in patch_manifest.items():
        res["patch"]["count"] += len(patches)


# Mail
res["mail"] = {
    "cve_with_mails_count": 0,
    "bugtraq_count": 0,
    "oss-security_count": 0,
    "full-disclosure_count": 0,
    "linux-cve-announce_count": 0,
}
with open(f"{processed_dir}/bugtraq-database/manifest.txt") as f:
    # skip empty lines
    bugtraq = list(filter(None, f.read().split("\n")))
    res["mail"]["bugtraq_count"] = len(bugtraq)
with open(f"{processed_dir}/oss-security-database/manifest.txt") as f:
    oss_security = list(filter(None, f.read().split("\n")))
    res["mail"]["oss-security_count"] = len(oss_security)
with open(f"{processed_dir}/full-disclosure-database/manifest.txt") as f:
    full_disclosure = list(filter(None, f.read().split("\n")))
    res["mail"]["full-disclosure_count"] = len(full_disclosure)
for root, dirs, files in os.walk(f"{processed_dir}/linux-vulns-database/"):
    for file in files:
        if file.endswith(".mbox"):
            res["mail"]["linux-cve-announce_count"] += 1
with open(f"{processed_dir}/cve-mail-mappings.json") as f:
    cve_mail_mappings = json.load(f)
    res["mail"]["cve_with_mails_count"] = len(cve_mail_mappings.keys())


# Print statistics
print(f"Total MITRE CVEs: {res['cve']['count']}")
print(f"Total NVD CVEs: {res['nvd']['count']}")
print(f"Total NVD CVEs with CVSS v2: {res['nvd']['cvss_v2_count']}")
print(f"Total NVD CVEs with CVSS v3.0: {res['nvd']['cvss_v30_count']}")
print(f"Total NVD CVEs with CVSS v3.1: {res['nvd']['cvss_v31_count']}")
print(f"Total NVD CVEs with CWE: {res['nvd']['cve_with_cwe_count']}")
print(f"Total GitHub Advisories: {res['github-advisory']['count']}")
print(f"Total ZDI Advisories: {res['zdi-advisory']['count']}")
print(f"Total CVEs in linux-cve-announce (Published): {res['linux-vulns']['published_count']}")
print(f"Total CVEs in linux-cve-announce (Rejected): {res['linux-vulns']['rejected_count']}")
print(f"Total CISA KEV: {res['cisa_kev']['count']}")
print(f"Total AttackerKB assessments: {res['attackerkb']['assessment_count']}")
print(f"Total AttackerKB topics: {res['attackerkb']['topic_count']}")
print(f"Total AttackerKB topics with assessments: {res['attackerkb']['topic_with_assessment_count']}")
print(f"Total Exploit-DB exploits: {res['exploit-db']['exploit_count']}")
print(f"Total CVEs with Exploit-DB exploits: {res['exploit-db']['cve_with_exploit_count']}")
print(f"Total CAPEC attack patterns: {res['capec']['count']}")
print(f"Total MITRE ATT&CK (Enterprise) attack patterns: {res['mitre-attack']['enterprise']}")
print(f"Total MITRE ATT&CK (ICS) attack patterns: {res['mitre-attack']['ics']}")
print(f"Total MITRE ATT&CK (Mobile) attack patterns: {res['mitre-attack']['mobile']}")
print(f"Total CWE weaknesses: {res['cwe']['count']}")
res["cwe"].pop("count")
for abstract, count in res["cwe"].items():
    print(f"Total CWE weaknesses (Level: {abstract}): {count}")
print(f"Total D3FEND tactics: {res['d3fend']['tactic_count']}")
print(f"Total D3FEND ontology: {res['d3fend']['ontology_count']}")
print(f"Total patch files: {res['patch']['count']}")
print(f"Total CVEs with patch files: {res['patch']['cve_with_patch_count']}")
print(f"Total Bugtraq mails: {res['mail']['bugtraq_count']}")
print(f"Total OSS-Security mails: {res['mail']['oss-security_count']}")
print(f"Total Full-Disclosure mails: {res['mail']['full-disclosure_count']}")
print(f"Total mails in linux-cve-announce: {res['mail']['linux-cve-announce_count']}")
print(f"Total CVEs with mails: {res['mail']['cve_with_mails_count']}")
