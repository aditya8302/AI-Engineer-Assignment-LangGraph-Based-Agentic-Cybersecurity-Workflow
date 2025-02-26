import os
import logging
import subprocess
import streamlit as st
from langgraph.graph import StateGraph
from typing import Dict, List, TypedDict, Annotated
from dotenv import load_dotenv
import time
import random

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define state schema
class CyberAuditData(TypedDict):
    directive: Annotated[str, "input_key"]  # High-level instruction
    job_queue: List[Dict]  # List of jobs to execute
    activity_logs: List[str]  # Execution logs
    assessment_scope: Dict[str, List[str]]  # User-defined scope

class CyberSecurityAgent:
    def __init__(self, assessment_scope: Dict[str, List[str]]):
        self.assessment_scope = assessment_scope
        self.execution_graph = self.create_execution_graph()

    def create_execution_graph(self):
        graph = StateGraph(CyberAuditData)
        graph.add_node("initiate", self.plan_jobs)
        graph.add_node("process", self.perform_task)
        graph.add_node("complete", lambda data: data)  # Final state

        # **Termination condition**
        def determine_next(data):
            if data["job_queue"]:  # Continue execution if jobs remain
                return "process"
            return "complete"  # Stop when no jobs remain

        graph.add_conditional_edges("initiate", determine_next)
        graph.add_conditional_edges("process", determine_next)
        graph.set_entry_point("initiate")

        return graph.compile()

    def plan_jobs(self, data: CyberAuditData):
        """Generate initial jobs based on the directive"""
        if not data["job_queue"]:
            directive = data["directive"]
            if "scan" in directive.lower() and "ports" in directive.lower():
                # Add nmap job
                data["job_queue"].append({
                    "utility": "nmap",
                    "target": self.assessment_scope["domains"][0],
                    "parameters": "-Pn -p 80,443,22,8080",
                })
            if "discover directories" in directive.lower():
                # Add gobuster job
                data["job_queue"].append({
                    "utility": "gobuster",
                    "target": self.assessment_scope["domains"][0],
                    "parameters": "dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
                })
            logging.info(f"Planned Jobs: {data['job_queue']}")
        return data

    def perform_task(self, data: CyberAuditData):
        """Execute one job at a time"""
        if data["job_queue"]:
            current_task = data["job_queue"].pop(0)  # Take and remove one job
            logging.info(f"Executing: {current_task}")
            try:
                output = self.run_utility(current_task)
                data["activity_logs"].append(output)
                # Dynamically add new jobs based on output
                if current_task["utility"] == "nmap":
                    # Example: Add gobuster job if HTTP ports are open
                    if "80/tcp" in output or "443/tcp" in output:
                        data["job_queue"].append({
                            "utility": "gobuster",
                            "target": current_task["target"],
                            "parameters": "dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
                        })
            except Exception as e:
                logging.error(f"Task failed: {e}")
                data["activity_logs"].append(f"Task failed: {current_task} - {str(e)}")
        return data

    def run_utility(self, job: Dict):
        """Simulate running a security utility and return realistic output"""
        utility = job["utility"]
        target = job["target"]
        parameters = job["parameters"].format(target=target)
        command = f"{utility} {parameters}"
        logging.info(f"Executing command: {command}")

        # Simulate realistic output based on the utility
        if utility == "nmap":
            output = self.simulate_nmap_scan(target)
        elif utility == "gobuster":
            output = self.simulate_gobuster_scan(target)
        else:
            output = f"Simulated output for {utility} on {target} with parameters {parameters}"

        return output

    def simulate_nmap_scan(self, target: str):
        """Simulate nmap scan output"""
        output = [
            f"Starting Nmap scan on {target}...",
            "Scanning ports: 80, 443, 22, 8080",
            "Discovered open ports:",
            "80/tcp  - HTTP",
            "443/tcp - HTTPS",
            "22/tcp  - SSH",
            "8080/tcp - HTTP-Alt",
            "Nmap scan completed.",
        ]
        return "\n".join(output)

    def simulate_gobuster_scan(self, target: str):
        """Simulate gobuster scan output"""
        output = [
            f"Starting Gobuster scan on {target}...",
            "Found directories:",
            "/admin",
            "/login",
            "/images",
            "/assets",
            "Gobuster scan completed.",
        ]
        return "\n".join(output)

    def run(self, directive: str):
        """Run the LangGraph pipeline"""
        initial_data = {"directive": directive, "job_queue": [], "activity_logs": [], "assessment_scope": self.assessment_scope}
        return self.execution_graph.invoke(initial_data)

# Streamlit UI
st.title("AI-Driven Cybersecurity Pipeline")
st.sidebar.header("Define Security Scope")

domain_input = st.sidebar.text_input("Target Domain", "google.com")
ip_range_input = st.sidebar.text_input("IP Range", "192.168.1.0/24")

if st.sidebar.button("Initiate Security Audit"):
    assessment_scope = {"domains": [domain_input], "ips": [ip_range_input]}
    security_agent = CyberSecurityAgent(assessment_scope)
    
    st.subheader("Executing Security Audit...")
    final_result = security_agent.run(f"Scan {domain_input} for open ports and discover directories")

    # Display logs with unique keys
    for index, log_entry in enumerate(final_result["activity_logs"]):
        st.text_area(f"Log {index + 1}", log_entry, height=200, key=f"log_{index}")

st.sidebar.text("Logs will appear below after execution.")
