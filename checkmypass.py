import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
# respond
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API and try again')
    return res


# check the hash_to_check and loop through all the responses(hashes)
def get_passwords_leaks_count(hashes, hash_to_check):
    # tuple that has the hash and the count
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # loop through the generator object created
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# converts password to SHA1
def pwned_api_check(password):
    shaw1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = shaw1password[:5], shaw1password[5:]
    # send to API
    response = request_api_data(first5_char)
    return get_passwords_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... You should probably change your password!')
        else:
            print(f'{password} was not found. Carry on!')
    return 'done!'


# read passwords from a text file
def get_password_from_txt(password_file):
    with open(sys.argv[1], 'r') as my_file:
        psswd_list = my_file.read()
        return psswd_list.split()


if __name__ == '__main__':
    password_file = sys.argv[1]
    passwords = get_password_from_txt(password_file)
    sys.exit(main(passwords))
