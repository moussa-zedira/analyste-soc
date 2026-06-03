"""AWS IAM connector via boto3."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC
from typing import Any

from apps.api.soar.connectors.base import Connector

DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    ],
}
DENY_ALL_POLICY_NAME = "SOAR-DenyAll-Containment"


class AWSConnector(Connector):
    """Connector IAM AWS via boto3. Utilise la chaine d'auth standard AWS."""

    name = "aws_iam"
    required_env = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]

    def _client(self, service: str):
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("boto3 non installe (pip install boto3)") from exc
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        return boto3.client(service, region_name=region)

    async def available(self) -> bool:
        if not self.configured:
            return False
        try:

            def _ping():
                client = self._client("sts")
                return client.get_caller_identity()

            ident = await asyncio.to_thread(_ping)
            return bool(ident.get("Account"))
        except Exception:
            return False

    async def disable_access_key(self, user: str, key_id: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "aws_not_configured"}

        def _do():
            iam = self._client("iam")
            iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
            return {"applied": True, "user": user, "access_key_id": key_id, "status": "Inactive"}

        try:
            return await asyncio.to_thread(_do)
        except Exception as exc:
            return {"applied": False, "error": str(exc), "user": user, "access_key_id": key_id}

    async def attach_deny_all_policy(self, user: str) -> dict[str, Any]:
        """Applique une policy inline 'Deny *' sur l'utilisateur (containment)."""
        if not self.configured:
            return {"applied": False, "reason": "aws_not_configured"}

        def _do():
            iam = self._client("iam")
            iam.put_user_policy(
                UserName=user,
                PolicyName=DENY_ALL_POLICY_NAME,
                PolicyDocument=json.dumps(DENY_ALL_POLICY),
            )
            return {"applied": True, "user": user, "policy_name": DENY_ALL_POLICY_NAME}

        try:
            return await asyncio.to_thread(_do)
        except Exception as exc:
            return {"applied": False, "error": str(exc), "user": user}

    async def revoke_sts_sessions(self, user: str) -> dict[str, Any]:
        """Invalide toutes les STS sessions existantes pour l'utilisateur.
        AWS n'expose pas de RevokeAllSessions direct ; l'astuce standard est
        d'attacher une policy inline avec aws:TokenIssueTime < now."""
        if not self.configured:
            return {"applied": False, "reason": "aws_not_configured"}

        from datetime import datetime

        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        revoke_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"DateLessThan": {"aws:TokenIssueTime": now_iso}},
                }
            ],
        }

        def _do():
            iam = self._client("iam")
            iam.put_user_policy(
                UserName=user,
                PolicyName="SOAR-RevokeSessions",
                PolicyDocument=json.dumps(revoke_policy),
            )
            return {
                "applied": True,
                "user": user,
                "revoke_before": now_iso,
                "policy_name": "SOAR-RevokeSessions",
            }

        try:
            return await asyncio.to_thread(_do)
        except Exception as exc:
            return {"applied": False, "error": str(exc), "user": user}
