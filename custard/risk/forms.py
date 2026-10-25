from __future__ import annotations

import datetime

from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone

from custard.catalog.models import Mitigation, Vulnerability
from custard.core.choices import Level

from .models import AssetRisk, RiskTreatment


def _users():
    return get_user_model().objects.filter(is_active=True).order_by("username")


class DateInput(forms.DateInput):
    input_type = "date"


class RiskUpdateForm(forms.ModelForm):
    class Meta:
        model = AssetRisk
        fields = ["likelihood", "impact_override", "residual_likelihood", "owner", "status", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 3})}
        labels = {"impact_override": "Impact"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = _users()
        self.fields["owner"].empty_label = "Unassigned"
        asset_impact = self.instance.asset.get_impact_display()
        self.fields["impact_override"].choices = [("", f"Use asset impact ({asset_impact})")] + list(Level.choices)
        self.fields["residual_likelihood"].choices = [("", "Not assessed")] + list(Level.choices)
        # Acceptance has its own, permission-checked workflow.
        allowed = [AssetRisk.Status.OPEN, AssetRisk.Status.IN_TREATMENT, AssetRisk.Status.MITIGATED,
                   AssetRisk.Status.NOT_APPLICABLE]
        if self.instance.status == AssetRisk.Status.ACCEPTED:
            allowed.append(AssetRisk.Status.ACCEPTED)
        self.fields["status"].choices = [(s.value, s.label) for s in AssetRisk.Status if s in allowed]

    def clean(self):
        cleaned = super().clean()
        status = cleaned.get("status")
        if status == AssetRisk.Status.MITIGATED and not cleaned.get("residual_likelihood"):
            self.add_error("residual_likelihood", "Set the residual likelihood when marking a risk as mitigated.")
        if status == AssetRisk.Status.NOT_APPLICABLE and not (cleaned.get("notes") or "").strip():
            self.add_error("notes", "Explain why this risk does not apply.")
        return cleaned


class RiskAcceptForm(forms.Form):
    justification = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}), min_length=20,
                                    help_text="Business reason, compensating controls and residual exposure.")
    review_date = forms.DateField(widget=DateInput, help_text="Acceptances expire and must be reviewed (max. 1 year).")

    def clean_review_date(self):
        value = self.cleaned_data["review_date"]
        today = timezone.localdate()
        if value <= today:
            raise forms.ValidationError("The review date must be in the future.")
        if value > today + datetime.timedelta(days=366):
            raise forms.ValidationError("Risk acceptances must be reviewed at least once a year.")
        return value


class TreatmentForm(forms.ModelForm):
    class Meta:
        model = RiskTreatment
        fields = ["status", "owner", "due_date", "notes"]
        widgets = {"due_date": DateInput, "notes": forms.TextInput()}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = _users()
        self.fields["owner"].empty_label = "Unassigned"
        if self.instance.pk:
            # Rendered as one table row; the inputs join their row's <form> via the HTML form attribute.
            for field in self.fields.values():
                field.widget.attrs["form"] = f"tf{self.instance.pk}"
                field.widget.attrs["aria-label"] = f"{field.label} for {self.instance.mitigation}"


class AddTreatmentForm(forms.Form):
    mitigation = forms.ModelChoiceField(queryset=Mitigation.objects.all(), required=False,
                                        empty_label="Choose from the catalog")
    new_mitigation = forms.CharField(max_length=255, required=False, label="…or describe a new mitigation")
    owner = forms.ModelChoiceField(queryset=None, required=False)
    due_date = forms.DateField(required=False, widget=DateInput)

    def __init__(self, *args, risk: AssetRisk, **kwargs):
        super().__init__(*args, **kwargs)
        self.risk = risk
        self.fields["owner"].queryset = _users()
        self.fields["owner"].empty_label = "Unassigned"
        self.fields["mitigation"].queryset = Mitigation.objects.exclude(treatments__risk=risk)

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("mitigation") and not (cleaned.get("new_mitigation") or "").strip():
            raise forms.ValidationError("Choose a mitigation or describe a new one.")
        return cleaned


class AddRiskForm(forms.Form):
    vulnerability = forms.ModelChoiceField(queryset=Vulnerability.objects.all(), required=False,
                                           empty_label="Choose from the vulnerability library")
    new_vulnerability = forms.CharField(max_length=150, required=False, label="…or name a new weakness")
    likelihood = forms.ChoiceField(choices=Level.choices, initial=Level.MEDIUM,
                                   help_text="NIST SP 800-30: how likely a threat-source exercises the weakness.")
    mitigations = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}),
                                  help_text="Optional: one mitigation per line.")

    def __init__(self, *args, asset, **kwargs):
        super().__init__(*args, **kwargs)
        self.asset = asset
        self.fields["vulnerability"].queryset = Vulnerability.objects.exclude(asset_risks__asset=asset)

    def clean(self):
        cleaned = super().clean()
        vuln, new = cleaned.get("vulnerability"), (cleaned.get("new_vulnerability") or "").strip()
        if not vuln and not new:
            raise forms.ValidationError("Choose a weakness or name a new one.")
        if not vuln and AssetRisk.objects.filter(asset=self.asset, vulnerability__name__iexact=new).exists():
            raise forms.ValidationError("This asset already has that risk.")
        return cleaned

    def mitigation_names(self) -> list[str]:
        lines = (self.cleaned_data.get("mitigations") or "").splitlines()
        return [line.strip()[:255] for line in lines if line.strip()]
