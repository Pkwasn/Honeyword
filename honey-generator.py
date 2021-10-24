import typing
import secrets
import math
import string

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

    Tough-Nut-Inclusion ('tni') :

Reference: Honeywords: Making Password-Cracking Detectable
           - Ari Juels (ari.juels@rsa.com), Ronald L. Rivest (rivest@mit.edu)
           - https://people.csail.mit.edu/rivest/pubs/JR13.pdf


"""

default_chars = string.ascii_letters + string.digits + string.punctuation


def generate_honeywords(password : str, count : int, generation_method : str='tt') -> list:
    """Generate count number of honeywords based on the inputed password and generation method, overview
    of the generation method is detailed in the file summary above
    """




def tweak_password_length(password : str) -> str:
    """Tweak the length of the password, adding or subtracting characters at random based on the
    password length. Passwords under length 10 will only be increased in size, as they are computationally easier
    to crack than longer passwords
    """
    length_variance = get_length_variance(password)
    sign = determine_sign()

    if len(password) > 10 and sign:
        password = password[:-length_variance]
    else:
        password += ''.join(secrets.choice(default_chars) for i in range(length_variance))

    return password

def tail_tweak_all(password : str, divisor : int=3 ) ->str:
    """Change characters to a different character of the same character type
    starting from the end of the string to the 2/3 index of the password
    """
    end = len(password)//divisor
    start = len(password)

    for index in range(start-1,start-end-1, -1):
        password[index] = tweak_char(password[index])

    print(password)
    return(password)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~[Helper Methods]~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

def tweak_char(char : str) -> str:
    """Return a char of the same type as the inputed type"""
    if char in string.digits:
        return secrets.choice(string.digits)
    elif char in string.punctuation:
        return secrets.choice(string.punctuation)
    elif char in string.ascii_letters:
        return secrets.choice(string.ascii_letters)

def find_first_char(password : str, char_type : str) -> int:
    """Returns the position of the first char which matches the char type
    Character Types: string.digit, string.ascii_letters, string.punctuation (symbols)
    """
    for index in range(len(password)-1):
        if password[index:index+1] in char_type:
            return index
        else:
            continue

    return -1

def find_last_char(password : str, char_type : str) -> int:
    """Returns the position of the last char which matches the char type
    Character Types: string.digit, string.ascii_letters, string.punctuation
    """
    index = 0
    for i in range(len(password)-1):
        if password[i:i+1] in char_type:
            index = i
        else:
            continue

    return index

def get_length_variance(string : str) -> int:
    """Mathmatically generate a integer based on the length of inputed string
    used to determine how many characters should be added to honeyword
    """

    return secrets.randbelow(int((math.log(len(string)))**2) - 2) + 1

def determine_sign() -> bool:
    """Function used to randomly determine if length_variance should subtract or add
    characters to the honeyword
    """

    sign = secrets.randbelow(2)
    return False if sign == 1 else True

if __name__ == "__main__":

    pass1 = tail_tweak_all('password')
