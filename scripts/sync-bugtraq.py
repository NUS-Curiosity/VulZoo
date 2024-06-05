#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import sys
import os
import time
import json

dest_dir = "../bugtraq-database"
link_index = f"{dest_dir}/bugtraq-msg-links.json"
bugtraq_url = 'https://lists.openwall.net/bugtraq'


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def parse_mail_table_year(html):
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table', class_='cal_brief')
    
    result = {}
    # ugly parsing begins...
    table_lines = str(table).split("\n")
    for line in table_lines:
        if line.startswith("<tr><td><a href="):
            # remove all "<tr>"" and "<td>" appearances
            line = line.replace("<tr>", "").replace("<td>", "")
            # use BeautifulSoup to parse the line and find all "<a>" tags
            line_soup = BeautifulSoup(line, 'html.parser')
            links = line_soup.find_all('a')
            # links[0] is the year number, links[1:] are the msg numbers for each month
            year = links[0].text
            result[year] = {}
            for i in range(1, len(links)):
                month = str(links[i].get('href')).split("/")[1]
                msg_num = int(links[i].text)
                result[year][month] = msg_num
    # ugly parsing ends...
    return result


def parse_mail_table_month(html):
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table', class_='cal_mon')
    result = list()
    # ugly parsing begins...
    table_lines = str(table).split("\n")
    for line in table_lines:
        if line.startswith("<tr><td><sup>") or line.startswith("<tr><td colspan="):
            line = line.replace("<tr>", "").replace("<td>", "")
            line_soup = BeautifulSoup(line, 'html.parser')
            links = line_soup.find_all('a')
            for link in links:
                msg_num = int(link.text)
                date = link.get('href').split("/")[0]
                result.append((date, msg_num))
    # ugly parsing ends...
    return result


def fetch_msg_list_per_month(mail_year, mail_month):
    print(f"[*] Fetching message list for year {mail_year}, month {mail_month}", file=sys.stderr)
    url = f"{bugtraq_url}/{mail_year}/{mail_month}"
    r = requests.get(url)
    if r.status_code != 200:
        print(f"[-] Failed to fetch message list for year {mail_year}, month {mail_month}", file=sys.stderr)
        return None

    data_msg_list = parse_mail_table_month(r.text)
    return data_msg_list


def fetch_msg_links(url, interval=5, print_result=sys.stdout):
    r = requests.get(url)
    if r.status_code != 200:
        print("[-] Failed to fetch bugtraq page", file=sys.stderr)
        return

    mail_table = parse_mail_table_year(r.text)
    if not mail_table:
        print("[-] Failed to parse mail table", file=sys.stderr)
        return

    res = {}
    for year in mail_table:
        print(f"Year: {year}", file=print_result, flush=True)
        res[year] = {}
        for month in mail_table[year]:
            specs = fetch_msg_list_per_month(year, month)
            if not specs:
                print(f"[!] No message list for year {year}, month {month}", file=sys.stderr)
                continue
            res[year][month] = specs
            if print_result:
                print(f"{specs}", file=print_result, flush=True)
            time.sleep(interval)
    return res


def fetch_msg(url, print_result=sys.stdout):
    r = requests.get(url)
    if r.status_code != 200:
        print(f"[-] Failed to fetch message from {url}", file=sys.stderr)
        return None
    # parse the message content (find the content of the `pre` tag)
    # note: only the plain text (there could be <a> but we only need the text)
    soup = BeautifulSoup(r.text, 'html.parser')
    msg = soup.find('pre')
    if not msg:
        print(f"[-] Failed to parse message from {url}", file=sys.stderr)
        return None
    return msg.text


def save_msg(msg, dest):
    with open(dest, 'w') as f:
        f.write(msg)


def download_messages(msg_links, interval=5, print_result=sys.stdout):
    for year in msg_links:
        for month in msg_links[year]:
            for date, msg_num in msg_links[year][month]:
                print(f"[*] Fetching message for {year}/{month}/{date}", file=sys.stderr)
                for i in range(1, msg_num+1):
                    url = f"{bugtraq_url}/{year}/{month}/{date}/{i}"
                    msg = fetch_msg(url)
                    if msg:
                        ensure_dir(f"{dest_dir}/{year}/{month}/{date}")
                        save_msg(msg, f"{dest_dir}/{year}/{month}/{date}/{i}")
                    time.sleep(interval)


if __name__ == '__main__':
    try:
        # [TODO] currently, we fetch all the messages
        # in the futrue, we calculate the delta between the online messages and the local messages
        # and only fetch the new messages
        delta = list()
        # check whether the link index file exists
        # if it does, load the links from the file
        # otherwise, fetch the links from the website
        if os.path.exists(link_index):
            print(f"[*] {link_index} found, loading links from the file", file=sys.stderr)
            with open(link_index, 'r') as f:
                msg_links = json.load(f)
                delta = msg_links
        else:
            print(f"[!] {link_index} found, fetching links from the website", file=sys.stderr)
            with open(link_index, 'w') as f:
                msg_links = fetch_msg_links(bugtraq_url, interval=1, print_result=sys.stdout)
                f.write(json.dumps(msg_links))
            delta = msg_links
        # downloading the messages
        download_messages(delta, interval=1, print_result=sys.stdout)
    except KeyboardInterrupt:
        print("[!] User interrupted", file=sys.stderr)
        sys.exit(1)
