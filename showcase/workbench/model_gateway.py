"""Shared offline/live boundary; the workbench never enables paid mode itself.

Future live adapters require an explicitly authorized Campaign object and use
its existing durable reservation ledger. No second paid counter is created.
"""

from showcase.live_budget import require


class DeliveryModelGateway:
    def __init__(self, *, campaign=None):
        self.campaign = campaign

    def offline(self, operation):
        require(self.campaign is None, "offline_cannot_silently_use_live_campaign")
        return operation()

    def chat(self, **request):
        require(self.campaign is not None, "real_model_not_authorized")
        return self.campaign.chat(**request)


class OfflineProfessionalDecisionPort:
    def __init__(self, gateway=None):
        self.gateway = gateway or DeliveryModelGateway()

    def next_action(self, *, completed, operations, context=None, tool_results=None):
        def decide():
            remaining = [
                operation for operation in operations if operation not in completed
            ]
            if not remaining:
                return {"kind": "finish"}
            operation = remaining[0]
            return {
                "kind": "tool_call",
                "operation": operation,
                "arguments": {"query": "权限 引用 撤权 验收 用户"}
                if operation == "retrieve_evidence"
                else {},
            }

        return self.gateway.offline(decide)
