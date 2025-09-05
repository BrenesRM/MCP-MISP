import os
from typing import Optional, Dict

from mcp.server.fastmcp import FastMCP
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

# Initialize MCP server
mcp = FastMCP("misp-server")

# --- CONFIG from .env ---
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
MISP_VERIFY_CERT = os.getenv("MISP_VERIFY_CERT", "false").lower() == "true"

# Initialize MISP connection
misp = None
try:
    misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT)
except Exception as e:
    print(f"⚠ Could not connect to MISP: {e}")


# --- TOOLS ---

@mcp.tool()
@mcp.tool()
def misp_ping() -> dict:
    """Check connectivity to the MISP server and return version info."""
    if not misp:
        return {"result": None, "text": "❌ MISP client not initialized"}
    try:
        # Try modern API call
        try:
            version = misp.get_api_version()
        except AttributeError:
            # Fallback for older PyMISP
            version = misp.get("servers/getVersion.json").get("version", "unknown")

        return {
            "result": version,
            "text": f"✅ Connected to MISP (version: {version})"
        }
    except Exception as e:
        return {"result": None, "text": f"❌ Failed to connect: {e}"}


@mcp.tool()
def misp_search_events(value: str, limit: int = 5) -> dict:
    """Search events in MISP by value (e.g., domain, hash, IP)."""
    if not misp:
        return {"result": None, "text": "❌ MISP client not initialized"}
    try:
        events = misp.search("events", value=value, limit=limit)
        return {
            "result": events,
            "text": f"🔎 Found {len(events)} events for '{value}'"
        }
    except Exception as e:
        return {"result": None, "text": f"❌ Search failed: {e}"}


@mcp.tool()
def misp_add_event(info: str, distribution: int = 0, threat_level_id: int = 4,
                   analysis: int = 0) -> dict:
    """Create a new MISP event."""
    if not misp:
        return {"result": None, "text": "❌ MISP client not initialized"}
    try:
        event = MISPEvent()
        event.info = info
        event.distribution = distribution
        event.threat_level_id = threat_level_id
        event.analysis = analysis

        new_event = misp.add_event(event)
        return {
            "result": new_event.to_json(),
            "text": f"✅ Created new event: {new_event['Event']['id']}"
        }
    except Exception as e:
        return {"result": None, "text": f"❌ Event creation failed: {e}"}


@mcp.tool()
def misp_add_attribute(event_id: str, type: str, value: str,
                       category: str = "External analysis") -> dict:
    """Add an attribute (IOC) to an existing event."""
    if not misp:
        return {"result": None, "text": "❌ MISP client not initialized"}
    try:
        attribute = MISPAttribute()
        attribute.type = type
        attribute.value = value
        attribute.category = category

        result = misp.add_attribute(event_id, attribute)
        return {
            "result": result.to_json(),
            "text": f"✅ Added attribute {type}: {value} to event {event_id}"
        }
    except Exception as e:
        return {"result": None, "text": f"❌ Attribute creation failed: {e}"}


if __name__ == "__main__":
    mcp.run()
