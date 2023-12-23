import sys
import hashlib
import time
import json
import requests
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import datetime
import logging

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

LOGIN_SID_ROUTE = "/login_sid.lua?version=2"

class LoginState:
    def __init__(self, challenge: str, blocktime: int):
        self.challenge = challenge
        self.blocktime = blocktime
        self.is_pbkdf2 = challenge.startswith("2$")

def get_sid(box_url: str, username: str, password: str) -> str:
    """ Get a sid by solving the PBKDF2 (or SHA-256) challenge-response process. """
    try:
        state = get_login_state(box_url)
    except Exception as ex:
        raise Exception("failed to get challenge") from ex

    if state.is_pbkdf2:
        print("PBKDF2 supported")
        challenge_response = calculate_pbkdf2_response(state.challenge,password)

    else:
        print("Falling back to SHA-256")
        challenge_response = calculate_sha256_response(state.challenge, password)

    if state.blocktime > 0:
        print(f"Waiting for {state.blocktime} seconds...")
        time.sleep(state.blocktime)
    try:
        sid = send_response(box_url, username, challenge_response)
    except Exception as ex:
        raise Exception("failed to login") from ex

    if (sid == "0000000000000000"):
        raise Exception("wrong username or password")
    return sid

def get_login_state(box_url: str) -> LoginState:
    """ Get login state from FRITZ!Box using login_sid.lua?version=2 """
    url = box_url + LOGIN_SID_ROUTE
    http_response = urllib.request.urlopen(url)
    xml = ET.fromstring(http_response.read())
    # print(f"xml: {xml}")
    challenge = xml.find("Challenge").text
    blocktime = int(xml.find("BlockTime").text)
    return LoginState(challenge, blocktime)

def calculate_pbkdf2_response(challenge: str, password: str) -> str:
    """ Calculate the response for a given challenge via PBKDF2 """
    challenge_parts = challenge.split("$")
    # Extract all necessary values encoded into the challenge
    iter1 = int(challenge_parts[1])
    salt1 = bytes.fromhex(challenge_parts[2])
    iter2 = int(challenge_parts[3])
    salt2 = bytes.fromhex(challenge_parts[4])
    # Hash twice, once with static salt...
    hash1 = hashlib.pbkdf2_hmac("sha256", password.encode(), salt1, iter1)
    # Once with dynamic salt.
    hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, iter2)
    return f"{challenge_parts[4]}${hash2.hex()}"

def calculate_sha256_response(challenge: str, password: str) -> str:
    """ Calculate the response for a challenge using SHA-256 """
    response = challenge + "-" + password
    response = response.encode("utf-16-le")
    sha256_sum = hashlib.sha256()
    sha256_sum.update(response)
    response = challenge + "-" + sha256_sum.hexdigest()
    return response

def send_response(box_url: str, username: str, challenge_response: str) -> str:
    """ Send the response and return the parsed sid. raises an Exception on error """
    # Build response params
    post_data_dict = {"username": username, "response": challenge_response}
    post_data = urllib.parse.urlencode(post_data_dict).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    url = box_url + LOGIN_SID_ROUTE
    # Send response
    http_request = urllib.request.Request(url, post_data, headers)
    http_response = urllib.request.urlopen(http_request)
    # Parse SID from resulting XML.
    xml = ET.fromstring(http_response.read())
    return xml.find("SID").text

def convert_date(date_string):
  """Converts a date in format dd.mm.yy to yyyy-mm-dd.

  Args:
    date_string: The date string in format dd.mm.yy.

  Returns:
    The date in format yyyy-mm-dd.
  """

  # Parse the date string into a datetime object.
  date = datetime.datetime.strptime(date_string, "%d.%m.%y")

  # Convert the datetime object to a string in format yyyy-mm-dd.
  return date.strftime("%Y-%m-%d")

def parse_string_to_dict(string):
  """Parses a string into a dictionary.

  The function takes a string and parses it into a dictionary. The first
  string followed by a space character is added to the dictionary with the key
  "date" in format dd.mm.yyyy. The next string followed by a space character is
  the time in format hh:mm:ss and is added to the dictionary with the key
  "time". The rest of the string is added to the dictionary with the key "msg".

  Args:
    string: The string to parse.

  Returns:
    A dictionary containing the parsed string.
  """

  # Split the string into a list of words.
  words = string.split()

  # Create a dictionary to store the parsed data.
  data = {}

  # Add the date and time to the dictionary.
  data["timestamp"] = convert_date(words[0]) + "T" + words[1]

  # Add the rest of the string to the dictionary.
  data["msg"] = " ".join(words[2:])

  # Return the dictionary.
  return data

def getLogs(sid: str, url: str):
    r = requests.get(url + "/query.lua?mq_log=logger:status/log&sid=+"+sid)

    cleaned_logs = []
    for element in r.json()["mq_log"]:
        log_entry = parse_string_to_dict(element[0])
        # print(log_entry)
        # logging.info(log_entry)
        cleaned_logs.append(log_entry)

    return cleaned_logs

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} http://fritz.box user pass interval")
        exit(1)

    url = sys.argv[1]
    logging.info(f"URL is set to: {url}")
    username = sys.argv[2]
    logging.info(f"Username is set to: {username}")
    password = sys.argv[3]
    logging.info(f"Password is set to: {password}")
    interval = int(sys.argv[4])
    logging.info(f"Interval is set to: {interval}")

    sid = get_sid(url, username, password)
    logging.info(f"Successful login for user: {username}")
    logging.info(f"sid: {sid}")

    all_logs = []

    # while True:
    for i in range(2):
        new_logs = getLogs(sid, url)

        for new_log in new_logs:
            if new_log not in all_logs:
                all_logs.append(new_log)
                logging.info(new_log)

        time.sleep(interval)

    logging.info("-------- complete string json --------")
    json_formatted_response = json.dumps(all_logs, indent=2)
    logging.info(json_formatted_response)

if __name__ == "__main__":
    main()
