#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import shutil
import json
from datetime import datetime
from typing import List, Optional

# Try to import rich for pretty printing
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
except ImportError:
    print("Error: 'rich' library not found.")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

# --- Configuration ---
REQUIRED_TOOLS = ["subfinder", "dnsx", "naabu", "httpx", "katana"]
DEFAULT_PORTS = "80,443,8080,8443,8000,8008,8888"

class ReconPipeline:
    def __init__(self, args):
        self.domain = args.domain
        self.domain_list = args.list
        self.output_dir = args.output
        self.proxy = args.proxy
        self.dry_run = args.dry_run
        self.llm_analysis = args.llm
        
        if not self.dry_run:
            os.makedirs(self.output_dir, exist_ok=True)

    def log(self, message, style="bold blue"):
        console.print(f"[{style}]>> {message}[/{style}]")

    def get_binary_path(self, tool_name):
        """Locates the tool binary, prioritizing Go paths."""
        possible_paths = [
            os.path.expanduser(f"~/go/bin/{tool_name}"),
            f"/usr/local/bin/{tool_name}",
            f"/usr/bin/{tool_name}"
        ]
        # Check GOBIN
        try:
            gobin = subprocess.check_output(["go", "env", "GOBIN"], text=True, stderr=subprocess.DEVNULL).strip()
            if gobin:
                possible_paths.insert(0, os.path.join(gobin, tool_name))
        except:
            pass

        for p in possible_paths:
            if os.path.exists(p):
                # Special check for httpx to avoid python library conflict
                if tool_name == "httpx":
                    try:
                        subprocess.run([p, "-version"], capture_output=True, check=True)
                        return p
                    except:
                        continue
                return p
        
        return shutil.which(tool_name) or tool_name

    def check_tools(self):
        """Verifies tools are installed."""
        self.log("Checking for required tools...", style="cyan")
        missing = []
        for tool in REQUIRED_TOOLS:
            path = self.get_binary_path(tool)
            if path == tool and not shutil.which(tool):
                missing.append(tool)
            elif path != tool and not os.path.exists(path):
                missing.append(tool)
        
        if missing:
            console.print(Panel(f"[red]Missing tools:[/red] {', '.join(missing)}\nPlease install them via 'go install ...'", title="Missing Dependencies"))
            sys.exit(1)
        self.log("All tools found.", style="green")

    def run_command(self, command: List[str], step_name: str, output_file: Optional[str] = None, append_output: bool = False):
        """Executes a shell command."""
        cmd_str = " ".join(command)
        if self.dry_run:
            console.print(Panel(f"[yellow]DRY RUN:[/yellow] {cmd_str}", title=step_name))
            return True

        self.log(f"Running {step_name}...", style="bold magenta")
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description=f"Executing {step_name}...", total=None)
                
                # Use subprocess.run
                result = subprocess.run(command, capture_output=True, text=True, check=False)

                if result.returncode != 0:
                    if "httpx" in command[0] and "No such option" in result.stderr:
                         console.print(Panel(f"[bold red]CRITICAL ERROR: Wrong HTTPX Version[/bold red]\nUse the Go version.", title="Version Conflict"))
                    else:
                        console.print(f"[red]Error running {step_name}:[/red]\n{result.stderr}")
                    return False
                
                # Write output
                if output_file:
                    mode = 'a' if append_output else 'w'
                    content = result.stdout.strip()
                    with open(output_file, mode) as f:
                        if content: f.write(content + '\n')
                    # Touch file if empty
                    if not os.path.exists(output_file):
                         with open(output_file, 'w') as f: pass

                # Count lines
                line_count = 0
                if output_file and os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        line_count = len([line for line in f if line.strip()])
                
                self.log(f"{step_name} completed. Found {line_count} unique results.", style="green")
                return True
        except Exception as e:
            console.print(f"[red]Exception during {step_name}: {e}[/red]")
            return False

    def create_burp_file(self):
        """
        Generates a specific file for Burp Suite import.
        Combines HTTPx (cleaned) and Katana results into a pure URL list.
        """
        if self.dry_run: return

        self.log("Generating Burp Suite import file...", style="cyan")
        
        httpx_file = os.path.join(self.output_dir, "httpx.txt")
        katana_file = os.path.join(self.output_dir, "katana.txt")
        burp_file = os.path.join(self.output_dir, "urls_for_burp.txt")
        
        unique_urls = set()

        # 1. Process HTTPx (needs cleaning: "https://x.com [200]" -> "https://x.com")
        if os.path.exists(httpx_file):
            with open(httpx_file, 'r') as f:
                for line in f:
                    # Split by space, take first part
                    clean_url = line.split(' ')[0].strip()
                    if clean_url.startswith("http"):
                        unique_urls.add(clean_url)

        # 2. Process Katana (Already pure URLs)
        if os.path.exists(katana_file):
            with open(katana_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url.startswith("http"):
                        unique_urls.add(url)
        
        # 3. Write to file
        with open(burp_file, 'w') as f:
            for url in sorted(unique_urls):
                f.write(url + "\n")
        
        return burp_file, len(unique_urls)

    def generate_summary(self):
        if self.dry_run: return
        summary = {
            "target": self.domain or self.domain_list,
            "timestamp": datetime.now().isoformat(),
            "stats": {}
        }
        files = {"subdomains": "subfinder.txt", "resolved": "dnsx.txt", "ports": "naabu.txt", "http_services": "httpx.txt", "endpoints": "katana.txt", "burp_import": "urls_for_burp.txt"}
        
        for key, filename in files.items():
            filepath = os.path.join(self.output_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r') as f: summary["stats"][key] = len(f.readlines())
            else: summary["stats"][key] = 0

        with open(os.path.join(self.output_dir, "summary.json"), 'w') as f:
            json.dump(summary, f, indent=4)
        self.log(f"Summary saved to {os.path.join(self.output_dir, 'summary.json')}", style="bold green")

    def run_llm_advisory(self):
        if self.dry_run: return
        katana_file = os.path.join(self.output_dir, "katana.txt")
        if not os.path.exists(katana_file): return

        self.log("Generating LLM Advisory Prompt...", style="cyan")
        with open(katana_file, 'r') as f: urls = [line.strip() for line in f.readlines() if line.strip()]
        if not urls: return

        prompt_content = f"Analyze these URLs and find high-risk endpoints:\n{json.dumps(urls[:200], indent=2)}"
        prompt_path = os.path.join(self.output_dir, "llm_prompt.txt")
        with open(prompt_path, 'w') as f: f.write(prompt_content)
        console.print(Panel(f"LLM Prompt generated at: [bold]{prompt_path}[/bold]", title="LLM Integration (Bonus)"))

    def execute(self):
        self.check_tools()
        console.print(Panel.fit(f"Target: {self.domain or self.domain_list}\nOutput: {self.output_dir}\nProxy: {self.proxy or 'None'}", title="Starting Recon Chain"))

        bin_subfinder = self.get_binary_path("subfinder")
        bin_dnsx = self.get_binary_path("dnsx")
        bin_naabu = self.get_binary_path("naabu")
        bin_httpx = self.get_binary_path("httpx")
        bin_katana = self.get_binary_path("katana")

        # 1. Subfinder
        subfinder_out = os.path.join(self.output_dir, "subfinder.txt")
        cmd_sub = [bin_subfinder, "-all", "-o", subfinder_out]
        if self.domain: cmd_sub.extend(["-d", self.domain])
        elif self.domain_list: cmd_sub.extend(["-dL", self.domain_list])
        if not self.run_command(cmd_sub, "Subfinder", subfinder_out): return

        # Robustness: Ensure root domain is included
        if self.domain and not self.dry_run and os.path.exists(subfinder_out):
            with open(subfinder_out, 'a+') as f:
                f.seek(0); content = f.read()
                if self.domain not in content: f.write(f"\n{self.domain}\n")

        # 2. DNSx
        dnsx_out = os.path.join(self.output_dir, "dnsx.txt")
        if not self.run_command([bin_dnsx, "-l", subfinder_out, "-o", dnsx_out], "DNSx", dnsx_out): return

        # 3. Naabu
        naabu_out = os.path.join(self.output_dir, "naabu.txt")
        if not self.run_command([bin_naabu, "-l", dnsx_out, "-p", DEFAULT_PORTS, "-o", naabu_out], "Naabu", naabu_out): return

        # 4. HTTPx (With Proxy Support)
        httpx_out = os.path.join(self.output_dir, "httpx.txt")
        cmd_httpx = [bin_httpx, "-l", naabu_out, "-title", "-tech-detect", "-status-code", "-o", httpx_out]
        if self.proxy:
            cmd_httpx.extend(["-http-proxy", self.proxy]) # <--- BURP PROXY INTEGRATION
        if not self.run_command(cmd_httpx, "HTTPx", httpx_out): return

        # --- KATANA PREP: CLEAN HTTPX OUTPUT ---
        katana_input = os.path.join(self.output_dir, "katana_input_clean.txt")
        if not self.dry_run and os.path.exists(httpx_out):
            with open(httpx_out, 'r') as infile, open(katana_input, 'w') as outfile:
                for line in infile:
                    clean_url = line.split(' ')[0] # Strip titles/status codes
                    if clean_url.strip():
                        outfile.write(clean_url.strip() + "\n")
        else:
            katana_input = httpx_out 

        # 5. Katana (With Proxy Support)
        katana_out = os.path.join(self.output_dir, "katana.txt")
        cmd_katana = [bin_katana, "-list", katana_input, "-o", katana_out, "-jc", "-kf", "all", "-c", "10", "-d", "2"]
        if self.proxy:
            cmd_katana.extend(["-proxy", self.proxy]) # <--- BURP PROXY INTEGRATION
        if not self.run_command(cmd_katana, "Katana", katana_out): return

        # 6. Create Burp Import File
        burp_file_path, burp_count = self.create_burp_file() if not self.dry_run else (None, 0)

        # 7. Finalize
        self.generate_summary()
        if self.llm_analysis: self.run_llm_advisory()
        
        # Final Output Panel
        success_msg = f"[bold green]Recon Chain Complete![/bold green]\n"
        if self.proxy:
             success_msg += f"\n[bold yellow]Proxy Active:[/bold yellow] Traffic was routed to {self.proxy}. Check Burp HTTP History."
        if burp_file_path:
             success_msg += f"\n[bold cyan]Burp Import:[/bold cyan] File generated at {burp_file_path} ({burp_count} URLs)."

        console.print(Panel(success_msg, title="Done"))

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target domain")
    group.add_argument("-l", "--list", help="Domain list file")
    parser.add_argument("-o", "--output", default="recon_results", help="Output dir")
    parser.add_argument("-p", "--proxy", help="Burp Proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--llm", action="store_true")
    args = parser.parse_args()
    ReconPipeline(args).execute()

if __name__ == "__main__":
    main()
