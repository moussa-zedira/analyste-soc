"""UEBA — User & Entity Behavior Analytics.

Construit un profil comportemental par entite (user_id / src_ip / host) base
sur les heures de connexion, types d'evenements et geo-distribution. Calcule
un score de risque par deviation (rare event = haut risque) sur les N
dernieres minutes pour mettre en avant les comptes compromis ou anormaux.

Utilise le meme principe Welford-like que detection/anomaly.py mais profile
par entite et multi-dimensions (vs single-metric).
"""
