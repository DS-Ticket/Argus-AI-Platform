import re
import datetime
from nlp_ollama import OllamaNLP


class ChatbotInterface:
    def __init__(self, connector, model="llama3.2:latest", base_url="http://localhost:11434"):
        self.connector = connector
        self.nlp = OllamaNLP(model=model, base_url=base_url)

    # Fallback intent classification
    def classify_intent(self, text: str) -> str:
        text = text.lower()

        if "summarize" in text or "overview" in text:
            return "summarize"

        if re.search(r"alert\s+\d+", text):
            return "alert_lookup"

        if "last" in text and ("minutes" in text or "hours" in text):
            return "time_range"

        if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text):
            return "ioc_hunt"

        if "brute" in text or "failed login" in text:
            return "brute_force"

        if "powershell" in text:
            return "powershell"

        if "file change" in text or "fim" in text:
            return "fim"

        if "malware" in text or "eicar" in text:
            return "malware"

        if "scan" in text or "nmap" in text:
            return "network_scan"

        return "unknown"

    def respond(self, text: str) -> str:

        alerts = self.connector.get_alerts()
        if not text or not text.strip():
            return "Please type something."

        text = text.strip()

        parsed = None
        err = None

        
        # TRY OLLAMA PARSE
        
        try:
            parsed = self.nlp.parse(text)
        except Exception as e:
            err = str(e)
            parsed = None

            self.last_user_text = text
            self.last_parsed = parsed
            self.last_ollama_error = err
            self.used_fallback = (parsed is None)

        tool_text = None

        
        # OLLAMA INTENT ROUTING
        
        if parsed:
            intent = parsed.get("intent", "unknown")
            if intent == "unknown":
                try:
                    return self.nlp.chat(text)
                except Exception:
                    pass

            alert_id = parsed.get("alert_id")
            ip_address = parsed.get("ip_address")
            amount = parsed.get("amount")
            unit = parsed.get("unit")

            if intent == "summarize":
                    if not alerts:
                        return "No alerts found."

                    alert_text = self.format_alerts_for_llm(alerts)

                    prompt = f"""
                You are a SOC analyst.

                Analyze the following alerts and generate a structured incident response playbook.

                Return in this format:

                ### Alert Summary
                - Total alerts
                - Severity breakdown

                ### Key Observations
                - Any suspicious behavior or patterns

                ### What Happened
                Explain clearly what is occurring.

                ### Why It Matters
                Explain the risk level.

                ### Investigation Steps
                - Step 1
                - Step 2

                ### Recommended Actions
                - Action 1
                - Action 2

                Alerts:
                {alert_text}
                """

                    tool_text = self.nlp.generate(prompt)

            elif intent == "alert_lookup":
                if not alert_id:
                    return "Tell me the alert ID, like alert 2356."
                tool_text = self.connector.lookup_alert(alert_id)

            elif intent == "time_range":
                if amount and unit in ["minutes", "hours"]:
                    tool_text = self.connector.alerts_in_last(int(amount), unit)
                else:
                    tool_text = self.handle_time_range(text)

            elif intent == "ioc_hunt":
                if ip_address:
                    tool_text = self.connector.hunt_for_ip(ip_address)
                else:
                    tool_text = self.handle_ioc_hunt(text)

            elif intent == "brute_force":
                tool_text = self.connector.summarize_bruteforce()

            elif intent == "powershell":
                tool_text = self.connector.summarize_powershell()

            elif intent == "fim":
                tool_text = self.connector.summarize_fim()

            elif intent == "malware":
                tool_text = self.connector.summarize_malware()

            elif intent == "network_scan":
                tool_text = self.connector.summarize_network_scans()

        # FALLBACK ROUTING
        
        if tool_text is None:
            intent = self.classify_intent(text)

            if intent == "summarize":
                tool_text = self.connector.get_alert_summary()

            elif intent == "alert_lookup":
                match = re.search(r"alert\s+(\d+)", text.lower())
                if not match:
                    return "Tell me the alert ID, like alert 2356."
                tool_text = self.connector.lookup_alert(match.group(1))

            elif intent == "time_range":
                tool_text = self.handle_time_range(text)

            elif intent == "ioc_hunt":
                tool_text = self.handle_ioc_hunt(text)

            elif intent == "brute_force":
                tool_text = self.connector.summarize_bruteforce()

            elif intent == "powershell":
                tool_text = self.connector.summarize_powershell()

            elif intent == "fim":
                tool_text = self.connector.summarize_fim()

            elif intent == "malware":
                tool_text = self.connector.summarize_malware()

            elif intent == "network_scan":
                tool_text = self.connector.summarize_network_scans()

            else:
                try:
                    return self.nlp.chat(text)
                except Exception:
                    return "Hey! Ask me to summarize alerts, look up an alert ID, or hunt an IP."

        
        # FINAL AI REWRITE 
        
        try:
    #  strip HTML before rewrite 
            plain_tool_text = re.sub(r"<[^>]+>", "", tool_text)

            rewritten = self.nlp.rewrite(text, plain_tool_text)

    #  force consistent rendering
            rewritten = rewritten.strip()

            if not rewritten.startswith("###"):
             rewritten = "### SOC Assistant Response\n\n" + rewritten

            return rewritten

        except Exception:
            return tool_text
        
    def format_alerts_for_llm(self, alerts):
        formatted = []
        for a in alerts[:5]:
            formatted.append(
                f"ID: {a['id']}\n"
                f"Severity: {a['severity']}\n"
                f"Summary: {a['summary']}\n"
                f"Timestamp: {a['timestamp']}\n"
            )
        return "\n---\n".join(formatted)


    def handle_time_range(self, text: str) -> str:
        try:
            numbers = re.findall(r"\d+", text)
            if not numbers:
                return "Tell me a time range like last 10 minutes or last 2 hours."

            amount = int(numbers[0])
            unit = "minutes" if "minute" in text.lower() else "hours"
            return self.connector.alerts_in_last(amount, unit)
        except Exception:
            return "Could not understand the time range. Try last 10 minutes."

    def handle_ioc_hunt(self, text: str) -> str:
        match = re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text)
        if not match:
            return "Paste an IP address to hunt, like 192.168.56.110."
        return self.connector.hunt_for_ip(match.group(0))