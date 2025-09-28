#!/usr/bin/env python3
"""
🔍 ANALYZE PROJECT VS USER RULES
Distinguish between project rules and user rules, analyze what should be applied
Generated: 2025-09-28
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Tuple

class ProjectUserRulesAnalyzer:
    """Analyze project rules vs user rules and identify gaps"""
    
    def __init__(self):
        self.project_root = "/Users/divinejohns/memU"
        self.rules_db = "finetuning_rules.db"
        self.components_db = "system_components.db"
    
    def identify_project_rules(self) -> List[Dict[str, Any]]:
        """Identify project-specific rules from files and configurations"""
        project_rules = []
        
        # Check for project-specific rule files
        rule_files = [
            ".cursorrules",
            "CURSOR_IZA_OS_PROMPTS.md",
            "200-cursor-prompts.md",
            "CURSOR_MASTER_RULES.md",
            "CURSOR_SESSION_AWARENESS_RULES.md",
            "CURSOR_WORLDWIDEBRO_CONTEXT_RULES.md",
            "CURSOR_SYSTEM_METRICS_RULES.md",
            "CURSOR_GUARDRAILS_RULES.md"
        ]
        
        for rule_file in rule_files:
            file_path = os.path.join(self.project_root, rule_file)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Extract rule information
                rule_info = {
                    "file": rule_file,
                    "type": "project",
                    "source": "file",
                    "content_length": len(content),
                    "has_worldwidebro": "worldwidebro" in content.lower(),
                    "has_revenue": "revenue" in content.lower(),
                    "has_consciousness": "consciousness" in content.lower(),
                    "has_quality": "quality" in content.lower(),
                    "has_security": "security" in content.lower()
                }
                project_rules.append(rule_info)
        
        return project_rules
    
    def identify_user_rules(self) -> List[Dict[str, Any]]:
        """Identify user-specific rules from database and configurations"""
        user_rules = []
        
        # Connect to rules database
        conn = sqlite3.connect(self.rules_db)
        cursor = conn.cursor()
        
        # Get all rules from database
        cursor.execute("""
            SELECT rule_id, rule_name, rule_type, priority, success_rate, 
                   revenue_impact, application_scope, last_applied
            FROM finetuning_rules
            ORDER BY priority DESC
        """)
        
        db_rules = cursor.fetchall()
        conn.close()
        
        for rule in db_rules:
            rule_id, rule_name, rule_type, priority, success_rate, revenue_impact, scope, last_applied = rule
            
            rule_info = {
                "id": rule_id,
                "name": rule_name,
                "type": rule_type,
                "priority": priority,
                "success_rate": success_rate,
                "revenue_impact": revenue_impact,
                "scope": scope,
                "last_applied": last_applied,
                "source": "database",
                "category": "user"
            }
            user_rules.append(rule_info)
        
        return user_rules
    
    def analyze_rule_application_gaps(self) -> Dict[str, Any]:
        """Analyze gaps between what should be applied and what is applied"""
        
        # Get project rules
        project_rules = self.identify_project_rules()
        
        # Get user rules
        user_rules = self.identify_user_rules()
        
        # Get component status
        conn = sqlite3.connect(self.components_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT component_name, rules_applied, performance_metrics
            FROM system_components
        """)
        
        components = cursor.fetchall()
        conn.close()
        
        # Analyze gaps
        gaps = {
            "project_rules_count": len(project_rules),
            "user_rules_count": len(user_rules),
            "components_count": len(components),
            "missing_applications": [],
            "low_success_rules": [],
            "unapplied_rules": [],
            "recommendations": []
        }
        
        # Check for rules with low success rates
        for rule in user_rules:
            if rule["success_rate"] < 60:
                gaps["low_success_rules"].append({
                    "name": rule["name"],
                    "success_rate": rule["success_rate"],
                    "priority": rule["priority"],
                    "revenue_impact": rule["revenue_impact"]
                })
        
        # Check for unapplied rules
        applied_rule_ids = set()
        for component in components:
            comp_name, rules_applied, perf_metrics = component
            applied_rules = json.loads(rules_applied)
            applied_rule_ids.update(applied_rules)
        
        for rule in user_rules:
            if rule["id"] not in applied_rule_ids:
                gaps["unapplied_rules"].append({
                    "name": rule["name"],
                    "id": rule["id"],
                    "priority": rule["priority"],
                    "revenue_impact": rule["revenue_impact"]
                })
        
        # Generate recommendations
        if gaps["low_success_rules"]:
            gaps["recommendations"].append("Improve success rates for low-performing rules")
        
        if gaps["unapplied_rules"]:
            gaps["recommendations"].append("Apply unapplied rules to relevant components")
        
        if len(project_rules) > len(user_rules):
            gaps["recommendations"].append("Convert more project rules to user rules")
        
        return gaps
    
    def create_rule_classification_report(self) -> Dict[str, Any]:
        """Create a comprehensive report classifying all rules"""
        
        project_rules = self.identify_project_rules()
        user_rules = self.identify_user_rules()
        gaps = self.analyze_rule_application_gaps()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "classification": {
                "project_rules": {
                    "count": len(project_rules),
                    "files": [rule["file"] for rule in project_rules],
                    "coverage": {
                        "worldwidebro": sum(1 for r in project_rules if r["has_worldwidebro"]),
                        "revenue": sum(1 for r in project_rules if r["has_revenue"]),
                        "consciousness": sum(1 for r in project_rules if r["has_consciousness"]),
                        "quality": sum(1 for r in project_rules if r["has_quality"]),
                        "security": sum(1 for r in project_rules if r["has_security"])
                    }
                },
                "user_rules": {
                    "count": len(user_rules),
                    "by_type": {},
                    "by_priority": {},
                    "success_rate_distribution": {
                        "excellent": sum(1 for r in user_rules if r["success_rate"] >= 80),
                        "good": sum(1 for r in user_rules if 60 <= r["success_rate"] < 80),
                        "needs_improvement": sum(1 for r in user_rules if 40 <= r["success_rate"] < 60),
                        "poor": sum(1 for r in user_rules if r["success_rate"] < 40)
                    }
                }
            },
            "gaps_analysis": gaps,
            "recommendations": {
                "immediate": [],
                "short_term": [],
                "long_term": []
            }
        }
        
        # Classify user rules by type
        for rule in user_rules:
            rule_type = rule["type"]
            if rule_type not in report["classification"]["user_rules"]["by_type"]:
                report["classification"]["user_rules"]["by_type"][rule_type] = 0
            report["classification"]["user_rules"]["by_type"][rule_type] += 1
        
        # Classify user rules by priority
        for rule in user_rules:
            priority = rule["priority"]
            if priority not in report["classification"]["user_rules"]["by_priority"]:
                report["classification"]["user_rules"]["by_priority"][priority] = 0
            report["classification"]["user_rules"]["by_priority"][priority] += 1
        
        # Generate recommendations
        if gaps["low_success_rules"]:
            report["recommendations"]["immediate"].append("Fix low success rate rules")
        
        if gaps["unapplied_rules"]:
            report["recommendations"]["immediate"].append("Apply unapplied rules")
        
        if len(project_rules) > len(user_rules):
            report["recommendations"]["short_term"].append("Convert project rules to user rules")
        
        report["recommendations"]["long_term"].append("Implement continuous rule monitoring")
        report["recommendations"]["long_term"].append("Create automated rule application system")
        
        return report
    
    def print_analysis_report(self):
        """Print a comprehensive analysis report"""
        
        report = self.create_rule_classification_report()
        
        print("🔍 PROJECT VS USER RULES ANALYSIS")
        print("=" * 50)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        print("📋 PROJECT RULES")
        print("-" * 30)
        project_rules = report["classification"]["project_rules"]
        print(f"Count: {project_rules['count']}")
        print("Files:")
        for file in project_rules["files"]:
            print(f"  - {file}")
        print()
        
        print("Coverage Analysis:")
        coverage = project_rules["coverage"]
        print(f"  - Worldwidebro: {coverage['worldwidebro']} files")
        print(f"  - Revenue: {coverage['revenue']} files")
        print(f"  - Consciousness: {coverage['consciousness']} files")
        print(f"  - Quality: {coverage['quality']} files")
        print(f"  - Security: {coverage['security']} files")
        print()
        
        print("👤 USER RULES")
        print("-" * 30)
        user_rules = report["classification"]["user_rules"]
        print(f"Count: {user_rules['count']}")
        print()
        
        print("By Type:")
        for rule_type, count in user_rules["by_type"].items():
            print(f"  - {rule_type}: {count} rules")
        print()
        
        print("By Priority:")
        for priority, count in user_rules["by_priority"].items():
            print(f"  - Priority {priority}: {count} rules")
        print()
        
        print("Success Rate Distribution:")
        success_dist = user_rules["success_rate_distribution"]
        print(f"  - Excellent (80%+): {success_dist['excellent']} rules")
        print(f"  - Good (60-79%): {success_dist['good']} rules")
        print(f"  - Needs Improvement (40-59%): {success_dist['needs_improvement']} rules")
        print(f"  - Poor (<40%): {success_dist['poor']} rules")
        print()
        
        print("🚨 GAPS ANALYSIS")
        print("-" * 30)
        gaps = report["gaps_analysis"]
        
        if gaps["low_success_rules"]:
            print("Low Success Rules:")
            for rule in gaps["low_success_rules"]:
                print(f"  - {rule['name']}: {rule['success_rate']}% (Priority: {rule['priority']})")
            print()
        
        if gaps["unapplied_rules"]:
            print("Unapplied Rules:")
            for rule in gaps["unapplied_rules"]:
                print(f"  - {rule['name']} (ID: {rule['id']}, Priority: {rule['priority']})")
            print()
        
        print("💡 RECOMMENDATIONS")
        print("-" * 30)
        
        if report["recommendations"]["immediate"]:
            print("Immediate Actions:")
            for rec in report["recommendations"]["immediate"]:
                print(f"  - {rec}")
            print()
        
        if report["recommendations"]["short_term"]:
            print("Short-term Actions:")
            for rec in report["recommendations"]["short_term"]:
                print(f"  - {rec}")
            print()
        
        if report["recommendations"]["long_term"]:
            print("Long-term Actions:")
            for rec in report["recommendations"]["long_term"]:
                print(f"  - {rec}")
            print()
        
        print("🔧 HOW TO FIX ISSUES")
        print("-" * 30)
        print("1. Run: python3 IMPROVE_FINETUNING_SUCCESS_RATES.py")
        print("2. Check: rule_monitoring_dashboard.json")
        print("3. Apply: Unapplied rules to relevant components")
        print("4. Monitor: Rule success rates continuously")
        print("5. Validate: Rule application in Cursor IDE")
        print()
        
        return report

def main():
    """Main function to analyze project vs user rules"""
    analyzer = ProjectUserRulesAnalyzer()
    report = analyzer.print_analysis_report()
    
    # Save report to file
    with open('project_user_rules_analysis.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("📊 Analysis report saved to: project_user_rules_analysis.json")

if __name__ == "__main__":
    main()
