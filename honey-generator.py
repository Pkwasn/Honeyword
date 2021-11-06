import typing
import secrets
import math
import string
import password_strength

def cprint(statement, output):
    """Cyan Output Color"""
    print(statement + '\033[96m' + output + '\033[0m')

"""
Last Updated: 10/21/2021

Honeyword Use Description:

    Honeywords fundamentally improve the security of hashed passwords commonly
    found in databases. Honeywords are essentially fake password hashes which are
    included alongside the original password hash in a database for each specific user.
    If an adversary cracks a honeyword and attempts to login or generally use that password
    for any service, an alarm will be set off. Alarm in this case is a very general term, as
    it could represent an actual alert to a systems admin (so they can take action against the
    adversary), or percise location tracking software, or it can allow the adversary to access a
    'burner'/'data-less account' so they can't access any sensitive information (Similar concept to
    honeypot on a server). Fundamentally, honeywords significantly increase time spent on password
    cracking ( as an adversary now has to crack 'N' hashes instead of a single hash) and increase
    security through an alert system.

    Note: While not necessarily a best practice, it makes more sense to make honeywords (not the hashes
    themselves) similar to the actual password so the attacker won't be able to easily differenciate
    between the honeywords and the actual password (if cracked). Personally I believe this is signicantly
    better implementation than just hashing randomly generated passwords.

Purpose:

    Given an input password, generate N amount of similar honeywords (not hashed). This can then be
    passed to a hashing algorithm and used in a honeyword detection system.

Generation Methods:

    Tail-Tweaking ('tt') :
    Tweaking-Digits ('td') :

Other Options:

    Tough-Nut (tn_count) : Include N tough-nuts in the output list, basically a password which will never
                            be cracked. Length of 40 characters


Reference: Honeywords: Making Password-Cracking Detectable
           - Ari Juels (ari.juels@rsa.com), Ronald L. Rivest (rivest@mit.edu)
           - https://people.csail.mit.edu/rivest/pubs/JR13.pdf


"""

default_chars = string.ascii_letters + string.digits + string.punctuation

policy = password_strength.PasswordPolicy.from_names(
    length = 10, # min length: 8
    uppercase = 2, # need min. 2 uppercase letters
    numbers = 2, # need min. 2 digits
    special = 2, # need min. 2 special characters
    nonletters = 2, # need miin. 2 non-letter characters

)

def generate_honeywords(password : str, count : int, generation_method : str='td', tn_count : int=2) -> list:
    """Generate count number of honeywords based on the inputed password and generation method, overview
    of the generation method is detailed in the file summary above, tough nuts are counted seperately from
    regular generation
    """

    p_list = [password]                 # List which will be returned by generate_honeywords at random

    for i in range(tn_count):
        nut = generate_tough_nut()
        p_list.append(nut)

    if 'td' in generation_method:
        for i in range(count):
            honeyword = tweak_digits(password)
            p_list.append(honeyword)

    return scramble_list(p_list)

def honeyword(password : str, instances : int = 10):

    print_analysis(password)



def tweak_password_length(password : str) -> str:
    """Tweak the length of the password, adding or subtracting characters at random based on the
    password length. Passwords under length 10 will only be increased in size, as they are computationally easier
    to crack than longer passwords
    """
    length_variance = get_length_variance(password)
    sign = secrets.randbelow(2) - 1

    if len(password) > 10 and sign:
        password = password[:-length_variance]
    else:
        password += ''.join(secrets.choice(default_chars) for i in range(length_variance))

    return password


def determine_incices(password : str, char_type : str=string.punctuation, target_type : str) -> list:
    """
    char_type : what we want to change
    target_type : from what indecies
    """

    L = find_all_positions(password, char_type)

    for count, i in emumerate(L):
        if count % 2 == 1:
            index = L[i][1]



def tweak_odd_indices(password : str, char_type : str) -> str:
    pass

def tweak_digits(password : str, first : bool=True) -> str:
    """Tweak only the digits of the password, automatically determine if it is better (more digits) to tweak after
    or before the first/last punctuation
    """

    if first:
        index = find_first_char(password, string.punctuation)
    else:
        index = find_last_char(password, string.punctuation)

    # Counting how many digits are before and after index
    b_count = count_chars(password[:index], string.digits)
    a_count = count_chars(password[index:], string.digits)

    # if the amoung of symbols after > before, change the string after index
    if b_count < a_count:
        start = index
        end = len(password)-1
    else:
        start = 0
        end = index

    temp = list(password)

    for index in range(start,end):
        if temp[index] in string.digits:
            temp[index] = tweak_char(temp[index])
        else:
            continue

    return ''.join(u for u in temp)


def tail_tweak_all(password : str, divisor : int=3 ) ->str:
    """Change characters to a different character of the same character type
    starting from the end of the string to the ~(divisor) index of the password
    """
    end = len(password)//divisor
    start = len(password)

    temp = list(password)

    for index in range(start-1,start-end-1, -1):
        temp[index] = tweak_char(temp[index])

    return ''.join(u for u in temp)

def generate_tough_nut() -> str:
    """Generate a password which will not be able to get cracked, 40 character length
    Implementing a password policy for generating tough nuts is unncessary as each char_type
    will be used atleast once
    """

    return ''.join(secrets.choice(default_chars) for i in range(40))

def scramble_list(passlist : list) -> list:
    """Return a scrambled version of inputed list, only called in generate_honeywords so
    generated honeywords aren't in the same position each time
    """
    temp = []
    while len(passlist) > 0:
        index = secrets.randbelow(len(passlist))
        temp.append(passlist[index])
        passlist.pop(index)

    return temp

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~[Helper Methods]~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

def tweak_char(char : str) -> str:
    """Return a char of the same type as the inputed type"""
    if char in string.digits:
        return secrets.choice(string.digits)
    elif char in string.punctuation:
        return secrets.choice(string.punctuation)
    elif char in string.ascii_letters:
        return secrets.choice(string.ascii_letters)

def count_chars(string : str, char_type : str) -> int:
    """Count how many chars of a specific type (string.ascii_letters, string.punctuation, string.digits)
    """
    count = 0
    for i in range(len(string)):
        if string[i] in char_type:
            count += 1
        else:
            continue

    return count

def find_first_char(password : str, char_type : str) -> int:
    """Returns the position of the first char which matches the char type
    Character Types: string.digits, string.ascii_letters, string.punctuation (symbols)
    """
    for index in range(len(password)):
        if password[index:index+1] in char_type:
            return index
        else:
            continue

    return -1

def find_last_char(password : str, char_type : str) -> int:
    """Returns the position of the last char which matches the char type
    Character Types: string.digits, string.ascii_letters, string.punctuation
    """
    index = 0
    for i in range(len(password)):
        if password[i:i+1] in char_type:
            index = i
        else:
            continue

    return index -1

def find_all_positions(password : str, char_type : str) -> list:
    """Return all chars of the type char_type in a list in a tuple ( char, index )
    Character Types: string.digits, string.ascii_letters, string.punctuation (symbols)
    """
    l = []

    for i in range(len(password)):
        if password[i:i+1] in char_type:
            l.append( (password[i:i+1], i) )
        else:
            continue

    return l


def get_length_variance(password : str) -> int:
    """Mathmatically generate a integer based on the length of inputed string
    used to determine how many characters should be added to honeyword
    """

    return secrets.randbelow(int((math.log(len(string)))**2) - 2) + 1

def print_analysis(password : str) -> None:
    types = {'Digits': string.digits, 'Letters': string.ascii_letters, 'Symbols': string.punctuation}

    cprint('Analyzing: ', password)
    cprint('Password Length: ', str(len(password)))

    max_count = ('temp', -1)

    for key in types.keys():
        count = count_chars(password, types[key])
        positions = find_all_positions(password, types[key])
        print(f'{key} count: {count}')
        print(f'{key} positions: {positions}\n')

        if max_count[1] < count:
            max_count = (key, count)

    print(f'Most commonly found type: {max_count}')
    print('Password does not meed the following criteria (if empty password is sufficient)')
    print(f'{policy.test(password)=}]')


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~[ MAIN ]~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

if __name__ == "__main__":

    honeyword('abc1234!@#!$')
