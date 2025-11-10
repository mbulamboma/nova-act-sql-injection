# xss.py - Tests de vulnérabilités XSS et SQL Injection
import time
import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Clé API Nova Act
nova_api_key = os.environ.get("NOVA_ACT_API_KEY")
from nova_act import NovaAct

print("API Key loaded:", nova_api_key is not None)

def test_sql_injection():
    """Tester les vulnérabilités SQL Injection avec Nova Act - Payloads gérés dans le prompt"""
     
    with NovaAct(
        starting_page="http://localhost:5000",
        ignore_https_errors=True,
        headless=False
    ) as nova:
        
        # Nova Act génère et teste les payloads SQL Injection lui-même
        result = nova.act("""
        Tu es un expert en sécurité qui teste les vulnérabilités SQL Injection.
        Tu es sur la page de login de SecureBank (http://localhost:5000).
        
        RÈGLES IMPORTANTES POUR LES TESTS:
        - Teste CHAQUE payload même si un précédent échoue
        - Si un payload génère une erreur SQL, note "ERREUR"
        
        - Après un succès (accès /dashboard), navigue DIRECTEMENT à http://localhost:5000/logout (ne cherche PAS de bouton Logout)
        - NE CLIQUE JAMAIS sur un bouton Logout - utilise TOUJOURS l'URL http://localhost:5000/logout
        
        COMMENT DÉTECTER UNE VULNÉRABILITÉ SQL INJECTION:
        - VULNÉRABLE = Si tu accèdes à /dashboard avec "Hello World!" après avoir cliqué "Sign In"
        - ÉCHOUÉ = Si tu restes sur la page de login avec un message d'erreur
        - ERREUR = Si tu vois un message d'erreur SQL (SQLite, syntax error, etc.)
        
        ⚠️ RÈGLE IMPORTANTE: Si tu vois le dashboard, cela signifie que le site EST VULNÉRABLE à ce payload SQL Injection!
        
        MISSION: Tester 3 payloads SQL Injection - vérifie si tu atteins /dashboard
        
        PAYLOAD 1: ' OR '1'='1
        - Navigue à http://localhost:5000
        - Entre exactement: ' OR '1'='1 dans le champ "Username"
        - Entre exactement: ' OR '1'='1 dans le champ "Password"
        - Clique sur "Sign In"
        - VÉRIFIE L'URL: Es-tu sur http://localhost:5000/dashboard ?
        - VÉRIFIE LE CONTENU: Vois-tu "Hello World!" ?
        - ⚠️ Si OUI aux 2 = Le site EST VULNÉRABLE à ce payload (bypass d'authentification réussi)
        - Si NON = ÉCHOUÉ
        - Si VULNÉRABLE: Navigue DIRECTEMENT à http://localhost:5000/logout (n'utilise PAS de bouton)
        - Au final genere ce message Payload 1: [VULNÉRABLE ou PAS VULNÉRABLE] - [Nom utilisateur si dashboard atteint]
        
        PAYLOAD 2: admin' --
        - Navigue à http://localhost:5000
        - Entre exactement: admin' -- dans "Username"
        - Entre "anything" dans "Password"
        - Clique sur "Sign In"
        - VÉRIFIE: Es-tu sur /dashboard avec "Hello World!" ?
        - ⚠️ Si OUI = Le site EST VULNÉRABLE à ce payload
        - Si NON = ÉCHOUÉ
        - Si VULNÉRABLE: Navigue DIRECTEMENT à http://localhost:5000/logout (n'utilise PAS de bouton)
        - Au final genere ce message Payload 2: [VULNÉRABLE ou PAS VULNÉRABLE] - [Nom utilisateur si dashboard atteint]
        
        PAYLOAD 3: ' OR '1'='1' --
        - Navigue à http://localhost:5000
        - Entre exactement: ' OR '1'='1' -- dans "Username"
        - Entre "anything" dans "Password"
        - Clique sur "Sign In"
        - VÉRIFIE: Es-tu sur /dashboard avec "Hello World!" ?
        - ⚠️ Si OUI = Le site EST VULNÉRABLE à ce payload
        - Si NON = ÉCHOUÉ
        - Si VULNÉRABLE: Navigue DIRECTEMENT à http://localhost:5000/logout (n'utilise PAS de bouton)
        - Au final genere ce message Payload 3: [VULNÉRABLE ou PAS VULNÉRABLE] - [Nom utilisateur si dashboard atteint]

        """)
        
        print("📋 RAPPORT SQL INJECTION COMPLET:")
        print(result)
        print("="*60)

def main():
    """Fonction principale - Exécute tous les tests"""  
    try:
        # Tests SQL Injection uniquement
        print("▶️  Lancement des tests SQL Injection...")
        test_sql_injection()
        # Rapport global final 
        print("\n💡 Nova Act a géré tous les payloads et généré les rapports complets.")
        
    except Exception as e:
        print(f"\n Erreur globale: {e}") 
if __name__ == "__main__":
    main()
