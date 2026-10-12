"""Listes de référence. À maintenir : elles résument des tendances, pas des certitudes."""

# Extensions très utilisées par les campagnes d'hameçonnage (bon marché ou trompeuses).
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "work", "gq", "tk", "ml", "cf", "ga",
    "rest", "cam", "icu", "buzz", "monster", "cyou", "sbs", "cfd", "lol",
}

# Raccourcisseurs : la vraie destination est masquée jusqu'à la redirection.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}

# Mots fréquents dans les liens qui réclament identifiants, codes ou paiements.
KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account", "update", "confirm",
    "password", "banking", "wallet", "bonus", "gift", "unlock", "suspended",
    "connexion", "compte", "verifier", "securite", "paiement", "remboursement",
    "cadeau", "gagnant", "debloquer", "momo",
}

# Marque -> domaines enregistrés officiels. Un nom de marque présent ailleurs que sur
# ces domaines est un signe classique d'usurpation (ex. mtn.bj.verification-compte.xyz).
BRANDS = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "office365": {"office.com", "microsoft.com"},
    "google": {"google.com", "google.bj"},
    "gmail": {"google.com", "gmail.com"},
    "facebook": {"facebook.com", "fb.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "amazon": {"amazon.com", "amazon.fr"},
    "mtn": {"mtn.bj", "mtn.com"},
    "moov": {"moov-africa.bj"},
    "celtiis": {"celtiis.bj"},
    "fedapay": {"fedapay.com"},
    "ecobank": {"ecobank.com"},
}

# Suffixe réservé aux sites de l'administration béninoise.
GOV_SUFFIX = "gouv.bj"
