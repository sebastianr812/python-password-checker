import requests
# hashed password123 = cbfdac6008f9cab4083784cbd1874f76618d2a97
import hashlib
import sys


def request_api_data(query_param):
    url = 'https://api.pwnedpasswords.com/range/' + query_param
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching the data: {res.status_code}, check api and try again')
    return res


def get_pass_leak_counts(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())

    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def check_full_pass(password):
    # check if our password exists in api response
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five, tail = sha1_password[:5], sha1_password[5:]

    res_api = request_api_data(first_five)

    return get_pass_leak_counts(res_api, tail)


def main(args):
    for password in args:
        count = check_full_pass(password)
        if count:
            print(
                f'Your password: {password} was found {count} times, its recommended that you change it!')
        else:
            print(
                f'Your password: {password} was NOT found in the system ... good job and good password!')
    return 'done'

# adding if __name__ if check so this only runs if it is the main file being run, not if its being imported


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
