"""
title: PII Redaction Filter
author: justinh-rahb
author_url: https://github.com/justinh-rahb
funding_url: https://github.com/open-webui
version: 0.2.0
license: MIT
description: A filter for redacting PII using either Presidio or regex patterns
requirements: presidio-analyzer, presidio-anonymizer
"""

import re
from typing import Optional
from pydantic import BaseModel, Field
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


class Filter:
    class Valves(BaseModel):
        priority: int = Field(
            default=0, description="Priority level for the filter operations."
        )
        enabled_for_admins: bool = Field(
            default=True,
            description="Whether PII Redaction is enabled for admin users.",
        )
        # Engine selection
        use_presidio: bool = Field(
            default=True, description="Use Presidio engine for PII detection"
        )
        use_regex: bool = Field(
            default=False, description="Use regex patterns for PII detection"
        )
        # Presidio settings
        presidio_entities: str = Field(
            default="PERSON,EMAIL_ADDRESS,PHONE_NUMBER,IN_AADHAAR,IN_PAN,IN_VEHICLE_REGISTRATION,IN_VOTER,CREDIT_CARD,IP_ADDRESS,IN_PASSPORT,LOCATION,NRP,CRYPTO",
            description="Comma-separated list of Presidio entity types to redact",
        )
        presidio_language: str = Field(
            default="en", description="Language code for Presidio analyzer"
        )
        # Regex settings
        redact_email: bool = Field(default=True, description="Redact email addresses")
        redact_phone: bool = Field(default=True, description="Redact phone numbers")
        redact_ssn: bool = Field(
            default=True, description="Redact social security numbers"
        )
        redact_credit_card: bool = Field(
            default=True, description="Redact credit card numbers"
        )
        redact_ip_address: bool = Field(default=True, description="Redact IP addresses")

    def __init__(self):
        self.file_handler = False
        self.valves = self.Valves()
        self.patterns = {
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            "phone": re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
            "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        }
        self._analyzer = None
        self._anonymizer = None

    @property
    def analyzer(self):
        if self._analyzer is None:
            self._analyzer = AnalyzerEngine()
        return self._analyzer

    @property
    def anonymizer(self):
        if self._anonymizer is None:
            self._anonymizer = AnonymizerEngine()
        return self._anonymizer

    def redact_with_presidio(self, text: str) -> str:
        entities = [
            entity.strip() for entity in self.valves.presidio_entities.split(",")
        ]

        results = self.analyzer.analyze(
            text=text, language=self.valves.presidio_language, entities=entities
        )

        anonymized_text = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "PERSON": OperatorConfig("replace", {"new_value": "[PERSON REDACTED]"}),
                "EMAIL_ADDRESS": OperatorConfig(
                    "replace", {"new_value": "[EMAIL ADDRESS REDACTED]"}
                ),
                "PHONE_NUMBER": OperatorConfig(
                    "replace", {"new_value": "[PHONE NUMBER REDACTED]"}
                ),
                "IN_AADHAAR": OperatorConfig(
                    "replace", {"new_value": "[AADHAAR NUMBER REDACTED]"}
                ),
                "IN_PAN": OperatorConfig(
                    "replace", {"new_value": "[PAN NUMBER REDACTED]"}
                ),
                "IN_VEHICLE_REGISTRATION": OperatorConfig(
                    "replace", {"new_value": "[VEHICLE REGISTRATION NUMBER REDACTED]"}
                ),
                "IN_VOTER": OperatorConfig(
                    "replace", {"new_value": "[VOTER ID REDACTED]"}
                ),
                "CREDIT_CARD": OperatorConfig(
                    "replace", {"new_value": "[CARD NUMBER REDACTED]"}
                ),
                "IP_ADDRESS": OperatorConfig(
                    "replace", {"new_value": "[IP ADDRESS REDACTED]"}
                ),
                "IN_PASSPORT": OperatorConfig(
                    "replace", {"new_value": "[PASSPORT REDACTED]"}
                ),
                "LOCATION": OperatorConfig(
                    "replace", {"new_value": "[LOCATION REDACTED]"}
                ),
                "NRP": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                "CRYPTO": OperatorConfig(
                    "replace", {"new_value": "[CRYPTO WALLET NUMBER REDACTED]"}
                ),
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
            },
        )

        return anonymized_text.text

    def redact_with_regex(self, text: str) -> str:
        if self.valves.redact_email:
            text = self.patterns["email"].sub("[EMAIL REDACTED]", text)
        if self.valves.redact_phone:
            text = self.patterns["phone"].sub("[PHONE REDACTED]", text)
        if self.valves.redact_ssn:
            text = self.patterns["ssn"].sub("[SSN REDACTED]", text)
        if self.valves.redact_credit_card:
            text = self.patterns["credit_card"].sub("[CREDIT CARD REDACTED]", text)
        if self.valves.redact_ip_address:
            text = self.patterns["ip_address"].sub("[IP ADDRESS REDACTED]", text)
        return text

    def inlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        print(f"inlet:{__name__}")
        print(f"inlet:body:{body}")
        print(f"inlet:user:{__user__}")

        if (
            __user__ is None
            or not __user__.get("role") == "admin"
            or self.valves.enabled_for_admins
        ):
            messages = body.get("messages", [])
            for message in messages:
                if message.get("role") == "user":
                    content = message["content"]
                    if self.valves.use_regex:
                        content = self.redact_with_regex(content)
                    if self.valves.use_presidio:
                        content = self.redact_with_presidio(content)
                    message["content"] = content

        return body

    def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        print(f"outlet:{__name__}")
        print(f"outlet:body:{body}")
        print(f"outlet:user:{__user__}")

        return body
