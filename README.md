Honeyword use description:

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
    
HoneyGenerator.py use description:

    Generate various honeywords with a variety of generation methods.
	
	Generation Methods:
	
	
