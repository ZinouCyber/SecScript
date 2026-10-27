import os
from datetime import datetime

def save_security_report(target_name, report_content, scan_type="General"):
    """
    Saves the AI security report into the reports directory in a formatted Markdown file
    with a timestamp, target name, and scan type. 
    """

    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    safe_target = target_name.replace("://", "_").replace("/", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"{reports_dir}/report_{scan_type}_{safe_target}_{timestamp}.md"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# AI-Driven Offensive Security Report\n\n")
        f.write(f"- **Target:** `{target_name}`\n")
        f.write(f"- **Scan Type:** `{scan_type}`\n")
        f.write(f"- **Date & Time:** `{datetime.now().strftime('%Y%m%d_%H%M%S')}`\n")
        f.write(f"- **AI Model:** `qwen2:1.5b`\n\n")
        f.write("---\n\n")
        f.write(report_content)
        f.write("\n\n---\n*Generated automatically by AI-Driven Offensive Python Toolkit*\n")

    print(f"[+] Report successfully saved to: {filename}")
    return filename
        