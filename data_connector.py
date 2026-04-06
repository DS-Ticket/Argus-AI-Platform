import requests

class DataConnector:
    def __init__(self):
        self.base_url = "http://localhost:3000"

    def get_alerts(self):
        try:
            response = requests.get(f"{self.base_url}/api/alerts", timeout=2)
            data = response.json()
            alerts = data.get("alerts", [])

            return [self.normalize_alert(a) for a in alerts]

        except Exception as e:
            print("Error fetching alerts:", e)
            return []

    def normalize_alert(self, a):
        return {
            "id": str(a.get("id") or a.get("_id") or "N/A"),
            "summary": str(
                a.get("summary") or 
                a.get("description") or 
                a.get("title") or 
                "No summary"
            ),
            "severity": str(a.get("severity", "low")).lower(),
            "timestamp": a.get("timestamp"),
        }