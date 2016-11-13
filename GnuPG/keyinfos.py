#-*- coding: utf-8 -*-
import os
import subprocess
import time


class KeyInfos(object):
    """
    Class parsing the output of gpg --list-keys --with-colons,
    returning information compatible with the man/DETAILS and RFC 4880.
    This is written to be compatible with both gpg and gpg2.
    """
    def __init__(self, keyhome=None, gpgbin=None):
        
        if keyhome is None:
            self.keyhome = os.path.join(os.path.expanduser("~"), ".gnupg")
        else:
            self.keyhome = keyhome
        
        if gpgbin is None:
            # TODO: this is not portable. Consider loop on os.environ["PATH"]
            if os.path.isfile("/usr/bin/gpg2"):
                self.gpgbin = "/usr/bin/gpg2"
            else:
                self.gpgbin = "/usr/bin/gpg"
        else:
            self.gpgbin = gpgbin
        
        # Field 1: Type of record
        self.recordType = {
            "pub" : "Public key",
            "crt" : "X.509 certificate",
            "crs" : "X.509 certificate and private key available",
            "sub" : "Subkey", # (secondary key)
            "sec" : "Secret key",
            "ssb" : "Secret subkey", # (secondary key)
            "uid" : "User id",
            "uat" : "User attribute", # (same as user id except for field 10).
            "sig" : "Signature",
            "rev" : "Revocation signature",
            "fpr" : "Fingerprint", #  (fingerprint is in field 10)
            "pkd" : "Public key data",
            "grp" : "Keygrip",
            "rvk" : "Revocation key",
            "tfs" : "TOFU statistics",
            "tru" : "Trust database information",
            "spk" : "Signature subpacket",
            "cfg" : "Configuration data",
        }
        # Field 2: Validity
        self.validity = {
            "o": "Unknown", # (this key is new to the system)
            "i": "Invalid", #(e.g. due to a missing self-signature)
            "d": "Disabled", #(deprecated - use the 'D' in field 12 instead)
            "r": "Revoked",
            "e": "Expired",
            "-": "Unknown validity", # (i.e. no value assigned)
            "q": "Undefined validity",  # '-' and 'q' may safely be treated asthe same value for most purposes
            "n": "Not valid",
            "m": "Marginal valid",
            "f": "Fully valid",
            "u": "Ultimately valid", # This often means that the secret key is available, but any key may be marked as ultimately valid.
            "w": "well known private part",
            "s": "special validity", #  This means that it might be self-signed and expected to be used in the STEED system.
        }
        # Field 4: Public key algorithm - see https://tools.ietf.org/html/rfc4880#section-9
        self.pubKeyAlgorithm = {
            1: "RSA (Encrypt or Sign)",
            2: "RSA Encrypt-Only",
            3: "RSA Sign-Only",
            16: "Elgamal (Encrypt-Only)",
            17: "DSA (Digital Signature Algorithm)",
            18: "Reserved for Elliptic Curve",
            19: "Reserved for ECDSA",
            20: "Reserved (formerly Elgamal Encrypt or Sign)",
            21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)"
        }
        for i in range(100, 110+1): 
            self.pubKeyAlgorithm[i] = "Private/Experimental algorithm"
        # Field 12: Key capabilities
        self.keyCapabilities = {
            "e": "Encrypt",
            "s": "Sign",
            "c": "Certify",
            "a": "Authentication",
            "?": "Unknown capability",
            # the primary key has uppercase versions of the letters to denote 
            # the _usable_ capabilities of the entire key, and 
            # a potential letter 'D' to indicate a disabled key.
            "E": "Encrypt (entire key)",
            "S": "Sign (entire key)",
            "C": "Certify (entire key)",
            "A": "Authentication (entire key)",
            "D": "Disabled",
        }
        # Field 16: Hash algorithm - NOT COMPLETE
        self.hashAlgorithm = {
            2: "SHA-1",
            8: "SHA-256",
        }
       
   
    @staticmethod
    def gpgTime(timestr):
        """
        The key dates can be given according to 3 formats:

            * seconds since epoch
            * ISO 8601 (contains a "T")
            * yyyy-mm-tt 
        """
        if "-" in timestr: # yyyy-mm-tt
            return timestr # This is the preferred format
        if "T" in timestr: # ISO 8601
            # TODO: Here we only keep day granularity.
            # Time zone has to be taken into account for finer precision.
            return "-".join([timestr[:4], timestr[4:6], timestr[6:8]])
        else: # should be seconds since epoch (default from GPG >= 2)
            if timestr == "":
                return ""
            t = int(timestr)
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
        
       
       
    
    def getGPGVersion(self):
        cmd = [self.gpgbin, "--version"]
        p = subprocess.Popen(cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        p.wait()
        for line in p.stdout.readlines():
            if line.startswith("gpg (GnuPG)"):
                res = line.rstrip("\n").split(") ")[1] # eg. '2.0.19'
                return res


    def getKeys(self, keyhome=None):
        """
        Provides informations on keys according to the doc/DETAILS manual of gpg.
        For now, it only provides informations on the first 12 fields.
        """
        
        cmd = [self.gpgbin, '--homedir', self.keyhome, '--list-keys', '--with-colons']
        p = subprocess.Popen(cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        p.wait()
        return self._parse_keys(p.stdout.readlines())
            
            
    def getSecretKeys(self, keyhome=None):
        """
        Provides informations on secret keys according to the doc/DETAILS manual of gpg.
        For now, it only provides informations on the first 12 fields.
        """
        
        cmd = [self.gpgbin, '--homedir', self.keyhome, '--list-secret-keys', '--with-colons']
        p = subprocess.Popen(cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        p.wait()
        return self._parse_keys(p.stdout.readlines())
    
    
    def _parse_keys(self, lines):
        keys = {}
        waiting_uid = None
        for line in lines:
            if (line.startswith("pub") or line.startswith("sub") or line.startswith("sec") or line.startswith("ssb")):
                res = line.split(":")
                D = {}
                # Field 1: type of record
                D[1] = self.recordType[res[0]]
                # Field 2: validity (may have several letters)
                validity = res[1]
                vals = []
                for char in validity:
                    vals.append(self.validity[char])
                D[2] = ", ".join(vals)
                # Field 3: Key length (bits)
                D[3] = int(res[2])
                # Field 4: Public key algorithm
                D[4] = self.pubKeyAlgorithm[int(res[3])]
                # Field 5: KeyID (will serve to identify the key in the resulting dict)
                keyid = res[4]
                D[5] = keyid
                # Field 6, 7: Creation and Expiration dates
                D[6] = self.gpgTime(res[5])
                D[7] = self.gpgTime(res[6])
                # Field 8: Certificate S/N, UID hash, trust signature info
                D[8] = res[7]
                # Field 9: Ownertrust
                D[9] = res[8]
                # Field 10: user ID. 
                # gpg2 does not show it directly, we have to wait for the 
                # corresponding "uid" entry.
                uid = res[9]
                if uid != "": # gpg
                    D[10] = res[9]
                else: # gpg2
                    waiting_uid = keyid
                # Field 11: signature class
                D[11] = res[10]
                # Field 12: key capabilities
                capa = res[11]
                vals = []
                for char in capa:
                    vals.append(self.keyCapabilities[char])
                D[12] = ", ".join(vals)
                
                # Register the key !
                keys[keyid] = D
            
            if line.startswith("uid") and (waiting_uid is not None): # gpg2
                # get date of this "uid" entry
                res = line.split(":")
                uid_date = self.gpgTime(res[5])
                # The "uid" key should come right after its key
                keys[waiting_uid][10] = res[9]
                waiting_uid = None
                
        return keys


