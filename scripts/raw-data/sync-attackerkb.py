#!/usr/bin/env python3

# AttackerKB API key is stored in the environment variable
# API rate limit is 100 requests per 5 minutes

import requests
import time
import os
import json


dest_dir = "../../processed/attackerkb-database"
topic_dir = f"{dest_dir}/topics"
assessment_dir = f"{dest_dir}/assessments"

base_url = "https://api.attackerkb.com"

api_key = os.environ.get("ATTACKERKB_API_KEY")
headers = {
    "Accept": "application/json",
    "Authorization": f"Basic {api_key}"
}


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_topics():
    ensure_dir(topic_dir)
    still_more = True
    cur_req = "/v1/topics?page=0&size=500&sort=created:asc&expand=references"
    cnt = 0
    while still_more:
        r = requests.get(f"{base_url}{cur_req}", headers=headers)
        if r.status_code != 200:
            print(f"Failed to get topic list: {r.text}")
            break  
        
        # get page and size numbers from cur_req
        self_req = r.json()["links"]["self"]["href"]
        page = int(self_req.split("page=")[1].split("&")[0])
        size = int(self_req.split("size=")[1].split("&")[0])
        save_json(r.json(), f"{topic_dir}/topics_{page}_{size}.json")
        cnt += 1
        if cnt == 80:
            time.sleep(5 * 60)
            cnt = 0
        try:
            cur_req = r.json()["links"]['next']['href']
            print(f"Next href: {cur_req}")
        except KeyError:
            break


def get_assessments():
    ensure_dir(assessment_dir)
    still_more = True
    cur_req = "/v1/assessments?page=0&size=100&sort=created:asc&expand=tags"
    cnt = 0
    while still_more:
        r = requests.get(f"{base_url}{cur_req}", headers=headers)
        if r.status_code != 200:
            print(f"Failed to get assessment list: {r.text}")
            break
        
        # get page and size numbers from cur_req
        self_req = r.json()["links"]["self"]["href"]
        page = int(self_req.split("page=")[1].split("&")[0])
        size = int(self_req.split("size=")[1].split("&")[0])
        save_json(r.json(), f"{assessment_dir}/assessments_{page}_{size}.json")
        cnt += 1
        if cnt == 80:
            time.sleep(5 * 60)
            cnt = 0
        try:
            cur_req = r.json()["links"]['next']['href']
            print(f"Next href: {cur_req}")
        except KeyError:
            break


if __name__ == "__main__":
    get_topics()
    get_assessments()
