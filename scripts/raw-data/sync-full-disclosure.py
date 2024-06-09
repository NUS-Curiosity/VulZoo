#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import sys
import os
import time
import json

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
}

dest_dir = "../../raw-data/full-disclosure-database"
link_index = f"{dest_dir}/full-disclosure-msg-links.json"
full_disclosure_url = 'https://lists.openwall.net/full-disclosure'


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def parse_mail_table_year(url):
    r = requests.get(url)
    if r.status_code != 200:
        print("[-] Failed to fetch full-disclosure page", file=sys.stderr)
        return None

    soup = BeautifulSoup(r.text, 'html.parser')
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
    url = f"{full_disclosure_url}/{mail_year}/{mail_month}"
    r = requests.get(url)
    if r.status_code != 200:
        print(f"[-] Failed to fetch message list for year {mail_year}, month {mail_month}", file=sys.stderr)
        return None

    data_msg_list = parse_mail_table_month(r.text)
    return data_msg_list


def fetch_msg_links(url, interval=5, print_result=sys.stdout):
    mail_table = parse_mail_table_year(url)
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
    try:
        r = requests.get(url, headers=headers)
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError) as e:
        time.sleep(10)
        print(f"Retrying {url}", file=sys.stderr)
        r = requests.get(url, headers=headers)
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
                    url = f"{full_disclosure_url}/{year}/{month}/{date}/{i}"
                    msg = fetch_msg(url)
                    if msg:
                        ensure_dir(f"{dest_dir}/{year}/{month}/{date}")
                        save_msg(msg, f"{dest_dir}/{year}/{month}/{date}/{i}")
                    time.sleep(interval)


def get_delta(msg_links, url, interval=5, print_result=sys.stdout):
    delta = {}
    # get the latest year/month/date from local msg_links
    # sort the key in msg_links and get the last one
    local_latest_year = sorted(msg_links.keys())[-1]
    local_latest_month = sorted(msg_links[local_latest_year].keys())[-1]
    # each item in msg_links[year][month] is a tuple (date, msg_num). sort the date and get the last one
    local_latest_date, local_latest_date_num = sorted(msg_links[local_latest_year][local_latest_month])[-1]

    # get the latest year/month/date from online website
    mail_table = parse_mail_table_year(url)
    online_latest_year = sorted(mail_table.keys())[-1]
    online_latest_month = sorted(mail_table[online_latest_year].keys())[-1]
    latest_month_list = fetch_msg_list_per_month(online_latest_year, online_latest_month)
    online_latest_date, online_latest_date_num = sorted(latest_month_list)[-1]

    # construct the date (yyyy-mm-dd) to compare the local and online latest date
    local_date = f"{local_latest_year}-{local_latest_month}-{local_latest_date}"
    online_date = f"{online_latest_year}-{online_latest_month}-{online_latest_date}"
    if local_date == online_date and local_latest_date_num == online_latest_date_num:
        return delta, local_latest_year, local_latest_month, local_latest_date
    if local_date > online_date or (local_date == online_date and local_latest_date_num > online_latest_date_num):
        print("[!] Weird that local database is newer than the online website", file=sys.stderr)
        return delta, local_latest_year, local_latest_month, local_latest_date
    
    # get the delta
    for year in mail_table:
        if year < local_latest_year:
            continue
        if year == local_latest_year:
            for month in mail_table[year]:
                if month < local_latest_month:
                    continue
                specs = fetch_msg_list_per_month(year, month)
                if not specs:
                    print(f"[!] No message list for year {year}, month {month}", file=sys.stderr)
                    continue
                # if print_result:
                #     print(f"{specs}", file=print_result, flush=True)
                delta[year] = delta.get(year, {})
                delta[year][month] = specs
                time.sleep(interval)
            # remove date that is less than local_latest_date
            delta[year][local_latest_month] = [x for x in delta[year][local_latest_month] if x[0] >= local_latest_date]
        else: # year > local_latest_year
            for month in mail_table[year]:
                specs = fetch_msg_list_per_month(year, month)
                if not specs:
                    print(f"[!] No message list for year {year}, month {month}", file=sys.stderr)
                    continue
                delta[year] = delta.get(year, {})
                delta[year][month] = specs
                time.sleep(interval)

    return delta, local_latest_year, local_latest_month, local_latest_date


def update_index_with_delta(local_index, delta, lly, llm, lld):
    for year in delta:
        for month in delta[year]:
            local_index[year] = local_index.get(year, {})
            local_index[year][month] = local_index[year].get(month, [])
            if year == lly and month == llm:
                local_month_dates = [x[0] for x in local_index[year][month]]
                delta_month_dates = [x[0] for x in delta[year][month]]
                if lld in delta_month_dates:
                    local_index[year][month].pop(local_month_dates.index(lld))

            local_index[year][month].extend(delta[year][month])
    with open(link_index, 'w') as f:
        f.write(json.dumps(local_index))


if __name__ == '__main__':
    print("[*] Syncing full-disclosure database", file=sys.stderr)
    try:
        # only fetch the new messages
        # check whether the link index file exists
        # if it does, load the links from the file and calculate the delta
        # otherwise, fetch the links from the website
        if os.path.exists(link_index):
            print(f"[*] {link_index} found, loading links from the file", file=sys.stderr)
            with open(link_index, 'r') as f:
                msg_links = json.load(f)
            print(f"[*] Calculating the delta between local and online full-disclosure database", file=sys.stderr)
            delta, lly, llm, lld = get_delta(msg_links, full_disclosure_url, interval=1)
            # update the msg_links and save it to the file
            if delta:
                print(f"[!] {link_index} is outdated, updating the link index", file=sys.stderr)
                update_index_with_delta(msg_links, delta, lly, llm, lld)
        else:
            print(f"[!] {link_index} not found, fetching links from the website", file=sys.stderr)
            with open(link_index, 'w') as f:
                msg_links = fetch_msg_links(full_disclosure_url, interval=5, print_result=sys.stdout)
                f.write(json.dumps(msg_links))
            delta = msg_links
        # downloading the messages
        if delta:
            download_messages(delta, interval=5, print_result=sys.stdout)
        else:
            print("[+] full-disclosure database is up-to-date", file=sys.stderr)
    except KeyboardInterrupt:
        print("[!] User interrupted", file=sys.stderr)
        sys.exit(1)
