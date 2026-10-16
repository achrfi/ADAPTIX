from src.adaptix.agents.planner import action_rejection


def test_idor_tool_accepts_name_present_in_idor_scenarios():
    state = {
        "idor_scenarios": [
            {
                "name": "vampi-private-book",
                "base_url": "http://127.0.0.1:18080",
                "path_template": "/books/v1/{object_id}",
                "object_id": "adaptix_private_1",
                "method": "GET",
            }
        ],
        "api_operations": [],
        "api_observations": [],
    }
    action = {"tool": "idor", "target": "vampi-private-book"}
    available = {"idor", "scenario", "api_discover", "httpx", "nmap", "nuclei", "playwright"}

    rejection = action_rejection(state, action, available)
    print("IDOR REJECTION REASON:", rejection)

    assert rejection is None


def test_scenario_tool_rejects_name_only_in_idor_scenarios():
    state = {
        "idor_scenarios": [
            {
                "name": "vampi-private-book",
                "base_url": "http://127.0.0.1:18080",
                "path_template": "/books/v1/{object_id}",
                "object_id": "adaptix_private_1",
                "method": "GET",
            }
        ],
        "api_operations": [],
        "api_observations": [],
    }
    action = {"tool": "scenario", "target": "vampi-private-book"}
    available = {"idor", "scenario", "api_discover", "httpx", "nmap", "nuclei", "playwright"}

    rejection = action_rejection(state, action, available)
    print("SCENARIO REJECTION REASON:", rejection)

    assert rejection is not None
    assert "Unknown scenario candidate" in rejection
